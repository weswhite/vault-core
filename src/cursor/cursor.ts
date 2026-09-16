/**
 * Keyset pagination cursors.
 *
 * Opaque so that clients cannot parse one. The sort key behind a feed changes
 * (a tiebreaker gets added, a timestamp moves from created to occurred), and
 * every client that learned to read a cursor breaks on that day. Handing back
 * one blob nobody can interpret is what keeps that change to one deploy.
 *
 * Opaque is NOT secret. This is base64url over plain text with no MAC, no key
 * and nothing secret in it. Anyone can decode a cursor, and anyone can forge
 * one. That is acceptable because a cursor only picks the starting row inside a
 * query the endpoint has already scoped to the caller's own user id. Two rules
 * follow, and they are the reason this comment exists: never put anything in a
 * cursor the caller is not already allowed to see, and never treat a decoded
 * cursor as proof of anything. If a cursor ever needs to be trusted, it needs a
 * MAC and a new CURSOR_VERSION, not an argument about how unlikely it is that
 * someone would bother.
 *
 * Round-tripping exactly matters more than it looks. A cursor that decodes to a
 * timestamp one millisecond off skips or repeats a row at every page boundary,
 * and what the user sees is a catch missing from their history.
 *
 * Runs on Node, in a browser worker, and on Hermes: no Buffer, no atob, no
 * TextDecoder, no Array.at.
 */

import { CURSOR_VERSION } from '../version.js';
import { VaultFormatError, base64UrlEncode, base64UrlDecode } from '../envelope/format.js';

/**
 * ASCII Unit Separator, the same separator the AAD uses. It cannot appear in an
 * id (ids are restricted to printable ASCII below), so the payload splits
 * unambiguously with no length prefixes.
 */
const SEP = '\u001f';

/** Tags the blob as ours, so a base64url string from somewhere else fails loudly. */
const CURSOR_MAGIC = 'wlc';

/**
 * Ids here are database primary keys: cuid, uuid or a stringified integer, all
 * of them short. The cap stops a client handing back a megabyte of "id" that
 * then gets interpolated into a query plan.
 */
export const MAX_CURSOR_ID_LENGTH = 128;

/** Widest instant a JS Date can represent, +/-100,000,000 days from the epoch. */
const MAX_TIMESTAMP_MS = 8640000000000000;

/**
 * Date-only, or a full instant with an explicit Z or +/-HH:MM offset. An offset
 * is required when a time is present: "2026-09-16T12:00:00" is defined to be
 * LOCAL time, so a phone in UTC+9 and a server in UTC would build different
 * cursors from the same string. Date-only is unambiguous (UTC midnight) and is
 * allowed.
 */
const ISO_INSTANT =
  /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?(Z|[+-]\d{2}:\d{2}))?$/;

/** Canonical decimal, no leading zeros, no plus, no "-0". */
const CANONICAL_INT = /^(0|-?[1-9]\d*)$/;

const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

export interface CursorInput {
  ts: string | number | Date;
  id: string;
}

export interface DecodedCursor {
  /** Epoch milliseconds. */
  ts: number;
  id: string;
}

function bad(message: string): VaultFormatError {
  return new VaultFormatError(message, 'VAULT_BAD_CURSOR');
}

function isDate(value: unknown): value is Date {
  // instanceof is wrong across realms: a Date that came out of a worker message
  // or a second copy of a bundle fails it, and the cursor would throw somewhere
  // nobody would think to look.
  return Object.prototype.toString.call(value) === '[object Date]';
}

function isLeapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

/**
 * Every field is range-checked here rather than left to Date.parse. Engines
 * disagree: V8 happily reads "2026-02-31" as March 3rd while rejecting
 * "2026-13-01", and a cursor silently moved by two days pages through the wrong
 * rows. Checking the calendar ourselves is the only way three runtimes agree.
 */
function isoToEpochMs(value: string): number {
  const match = ISO_INSTANT.exec(value);
  if (match === null) {
    throw bad(
      'ts string must be ISO-8601 with an explicit Z or +/-HH:MM offset ' +
        `(or a bare date), got ${JSON.stringify(value)}`,
    );
  }

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  // Optional groups are undefined at runtime when they did not match. They are
  // matched as \d{2}, so a group that did match is never the empty string and a
  // truthiness check is exact.
  const hour = match[4] ? Number(match[4]) : 0;
  const minute = match[5] ? Number(match[5]) : 0;
  const second = match[6] ? Number(match[6]) : 0;

  if (month < 1 || month > 12) throw bad(`ts month ${match[2]} is out of range`);
  const maxDay = month === 2 && isLeapYear(year) ? 29 : DAYS_IN_MONTH[month - 1];
  if (day < 1 || day > maxDay) {
    throw bad(`ts day ${match[3]} is out of range for month ${match[2]}`);
  }
  // 24:00 is legal ISO for midnight ending the day, and it names the same
  // instant as 00:00 the next day. Two spellings of one instant would produce
  // two different cursors for the same row, so one of them is rejected.
  if (hour > 23) throw bad(`ts hour ${match[4]} is out of range (24:00 is not accepted)`);
  if (minute > 59) throw bad(`ts minute ${match[5]} is out of range`);
  // Leap seconds do not exist in epoch milliseconds, so :60 has nowhere to go.
  if (second > 59) throw bad(`ts second ${match[6]} is out of range`);

  // Sub-millisecond digits are truncated toward the start of the second, never
  // rounded. Rounding a timestamp up moves the cursor past a row that shares
  // that millisecond, and that row is then never returned on any page.
  const fraction = match[7];
  const millis = fraction ? Number((fraction + '000').slice(0, 3)) : 0;

  const offset = match[8];
  let offsetMs = 0;
  if (offset && offset !== 'Z') {
    const offsetHours = Number(offset.slice(1, 3));
    const offsetMinutes = Number(offset.slice(4, 6));
    if (offsetHours > 23 || offsetMinutes > 59) throw bad(`ts offset ${offset} is out of range`);
    const sign = offset.charAt(0) === '-' ? -1 : 1;
    offsetMs = sign * (offsetHours * 3600000 + offsetMinutes * 60000);
  }

  let epoch: number;
  if (year >= 100) {
    epoch = Date.UTC(year, month - 1, day, hour, minute, second, millis);
  } else {
    // Date.UTC maps a year of 0..99 onto 1900..1999, which would read "0042"
    // as 1942.
    const date = new Date(0);
    date.setUTCFullYear(year, month - 1, day);
    date.setUTCHours(hour, minute, second, millis);
    epoch = date.getTime();
  }

  return epoch - offsetMs;
}

function toEpochMs(ts: string | number | Date): number {
  let epoch: number;

  if (isDate(ts)) {
    epoch = ts.getTime();
    if (!Number.isFinite(epoch)) throw bad('ts is an Invalid Date');
  } else if (typeof ts === 'number') {
    if (!Number.isFinite(ts)) throw bad(`ts must be a finite number, got ${String(ts)}`);
    if (!Number.isInteger(ts)) {
      throw bad(`ts must be whole epoch milliseconds, got ${ts}`);
    }
    epoch = ts;
  } else if (typeof ts === 'string') {
    epoch = isoToEpochMs(ts);
  } else {
    throw bad(`ts must be a string, number or Date, got ${typeof ts}`);
  }

  if (!Number.isSafeInteger(epoch) || Math.abs(epoch) > MAX_TIMESTAMP_MS) {
    throw bad(`ts ${epoch} is outside the representable range`);
  }
  return epoch;
}

function assertId(id: string): void {
  if (typeof id !== 'string' || id.length === 0) {
    throw bad('id must be a non-empty string');
  }
  if (id.length > MAX_CURSOR_ID_LENGTH) {
    throw bad(`id is ${id.length} characters, maximum is ${MAX_CURSOR_ID_LENGTH}`);
  }
  for (let i = 0; i < id.length; i++) {
    const code = id.charCodeAt(i);
    if (code === 0x1f) {
      throw bad('id must not contain the field separator (U+001F)');
    }
    // Printable ASCII only. Every primary key that reaches this is a cuid, a
    // uuid or a number, so the restriction costs nothing, and it is what lets
    // the payload be encoded byte-for-byte without a TextEncoder/TextDecoder
    // pair -- Hermes cannot be relied on for the decoder half.
    if (code < 0x21 || code > 0x7e) {
      throw bad(
        `id must be printable ASCII with no spaces, bad character at index ${i}: ` +
          JSON.stringify(id.charAt(i)),
      );
    }
  }
}

function asciiToBytes(value: string): Uint8Array {
  const out = new Uint8Array(value.length);
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code > 0x7f) throw bad(`cursor payload must be ASCII, bad character at index ${i}`);
    out[i] = code;
  }
  return out;
}

function bytesToAscii(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] > 0x7f) throw bad(`cursor payload must be ASCII, bad byte at index ${i}`);
    out += String.fromCharCode(bytes[i]);
  }
  return out;
}

/**
 * Payload is `wlc` SEP version SEP epochMillis SEP id, base64url encoded.
 *
 * The timestamp is written as canonical decimal epoch milliseconds, which is
 * both shorter than ISO text and free of the timezone question entirely.
 */
export function encodeCursor(input: CursorInput): string {
  // Typed, but two of the three callers reach this from untyped JSON.
  const source: CursorInput | null | undefined = input;
  if (source === null || source === undefined || typeof source !== 'object') {
    throw bad('cursor input must be an object with ts and id');
  }

  assertId(source.id);
  const ts = toEpochMs(source.ts);
  const payload = CURSOR_MAGIC + SEP + String(CURSOR_VERSION) + SEP + String(ts) + SEP + source.id;
  return base64UrlEncode(asciiToBytes(payload));
}

/**
 * Every failure throws. A cursor that decodes "as far as it got" would page
 * from a plausible-looking wrong row, and nothing downstream can tell that
 * apart from a correct page.
 *
 * An unknown version is rejected outright, with no attempt to read it as v1.
 * Note that this is the opposite of the record rule in FORMAT.md, and
 * deliberately so: a cursor is transient. The worst an unreadable one costs is
 * a client re-requesting the first page, whereas an unreadable record is user
 * data nobody can ever recover. That is also why there is no
 * SUPPORTED_CURSOR_VERSIONS list to append to.
 */
export function decodeCursor(cursor: string): DecodedCursor {
  if (typeof cursor !== 'string' || cursor.length === 0) {
    throw bad('cursor must be a non-empty string');
  }

  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(cursor);
  } catch (err) {
    const reason = err instanceof Error ? err.message : 'decode failed';
    throw bad(`cursor is not valid base64url: ${reason}`);
  }

  const parts = bytesToAscii(bytes).split(SEP);
  if (parts.length !== 4) {
    throw bad(`cursor has ${parts.length} fields, expected 4`);
  }
  if (parts[0] !== CURSOR_MAGIC) {
    throw bad('cursor is not a Waterlands cursor');
  }

  if (!CANONICAL_INT.test(parts[1])) {
    throw bad(`cursor version ${JSON.stringify(parts[1])} is not a number`);
  }
  const version = Number(parts[1]);
  if (version !== CURSOR_VERSION) {
    throw new VaultFormatError(
      `unsupported cursor version ${version}, this build writes ${CURSOR_VERSION}`,
      'VAULT_UNSUPPORTED_CURSOR_VERSION',
    );
  }

  if (!CANONICAL_INT.test(parts[2])) {
    throw bad(`cursor timestamp ${JSON.stringify(parts[2])} is not a canonical integer`);
  }
  const ts = Number(parts[2]);
  if (!Number.isSafeInteger(ts) || Math.abs(ts) > MAX_TIMESTAMP_MS) {
    throw bad(`cursor timestamp ${parts[2]} is outside the representable range`);
  }

  assertId(parts[3]);

  return { ts, id: parts[3] };
}
