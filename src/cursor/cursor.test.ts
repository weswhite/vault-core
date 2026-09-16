import { describe, it, expect } from 'vitest';

import { CURSOR_VERSION } from '../version.js';
import { base64UrlEncode } from '../envelope/format.js';
import { MAX_CURSOR_ID_LENGTH, decodeCursor, encodeCursor } from './cursor.js';

/** Builds a raw cursor payload, so the tests can forge malformed ones. */
function forge(payload: string): string {
  const bytes = new Uint8Array(payload.length);
  for (let i = 0; i < payload.length; i++) bytes[i] = payload.charCodeAt(i);
  return base64UrlEncode(bytes);
}

const SEP = '\u001f';
const ID = 'clx1234567890abcdefghijk';
const TS = 1789562096123; // 2026-09-16T12:34:56.123Z

describe('encodeCursor', () => {
  it('produces url-safe text with no padding', () => {
    const cursor = encodeCursor({ ts: TS, id: ID });
    expect(cursor).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(cursor.indexOf('=')).toBe(-1);
  });

  // Pins the wire format. A change here is a CURSOR_VERSION bump, not an edit.
  it('matches the frozen encoding', () => {
    expect(encodeCursor({ ts: 0, id: 'a' })).toBe('d2xjHzEfMB9h');
    expect(encodeCursor({ ts: TS, id: 'clx1' })).toBe('d2xjHzEfMTc4OTU2MjA5NjEyMx9jbHgx');
  });

  it('accepts a number, an ISO string and a Date for the same instant', () => {
    const fromNumber = encodeCursor({ ts: TS, id: ID });
    const fromString = encodeCursor({ ts: '2026-09-16T12:34:56.123Z', id: ID });
    const fromDate = encodeCursor({ ts: new Date(TS), id: ID });
    expect(fromString).toBe(fromNumber);
    expect(fromDate).toBe(fromNumber);
  });

  it('reads an offset rather than assuming the local zone', () => {
    expect(decodeCursor(encodeCursor({ ts: '2026-09-16T12:34:56+02:00', id: 'x' })).ts).toBe(
      Date.UTC(2026, 8, 16, 10, 34, 56, 0),
    );
    expect(decodeCursor(encodeCursor({ ts: '2026-09-16T12:34:56-07:00', id: 'x' })).ts).toBe(
      Date.UTC(2026, 8, 16, 19, 34, 56, 0),
    );
    expect(decodeCursor(encodeCursor({ ts: '2026-09-16', id: 'x' })).ts).toBe(
      Date.UTC(2026, 8, 16, 0, 0, 0, 0),
    );
  });

  it('truncates sub-millisecond digits toward the start of the second', () => {
    // Rounding up would step past a row sharing that millisecond, and that row
    // would never appear on any page.
    expect(decodeCursor(encodeCursor({ ts: '2026-09-16T12:34:56.999999Z', id: 'x' })).ts).toBe(
      Date.UTC(2026, 8, 16, 12, 34, 56, 999),
    );
    expect(decodeCursor(encodeCursor({ ts: '2026-09-16T12:34:56.9Z', id: 'x' })).ts).toBe(
      Date.UTC(2026, 8, 16, 12, 34, 56, 900),
    );
  });

  it('handles instants before the epoch', () => {
    expect(decodeCursor(encodeCursor({ ts: -1, id: 'x' })).ts).toBe(-1);
    expect(decodeCursor(encodeCursor({ ts: '1969-12-31T23:59:59.999Z', id: 'x' })).ts).toBe(-1);
    // Date.UTC maps a two-digit year onto the 1900s; a four-digit year must not.
    expect(decodeCursor(encodeCursor({ ts: '0042-01-01T00:00:00Z', id: 'x' })).ts).toBe(
      -60841756800000,
    );
  });

  it('rejects an id that would make the payload ambiguous', () => {
    expect(() => encodeCursor({ ts: 0, id: 'a' + SEP + 'b' })).toThrow(/separator/);
    expect(() => encodeCursor({ ts: 0, id: 'a b' })).toThrow(/printable ASCII/);
    expect(() => encodeCursor({ ts: 0, id: 'caf\u00e9' })).toThrow(/printable ASCII/);
    expect(() => encodeCursor({ ts: 0, id: 'a\nb' })).toThrow(/printable ASCII/);
    expect(() => encodeCursor({ ts: 0, id: '' })).toThrow(/non-empty/);
    expect(() => encodeCursor({ ts: 0, id: null as unknown as string })).toThrow(/non-empty/);
  });

  it('bounds the id length', () => {
    const atLimit = 'x'.repeat(MAX_CURSOR_ID_LENGTH);
    expect(decodeCursor(encodeCursor({ ts: 0, id: atLimit })).id).toBe(atLimit);
    expect(() => encodeCursor({ ts: 0, id: 'x'.repeat(MAX_CURSOR_ID_LENGTH + 1) })).toThrow(
      /maximum/,
    );
  });

  it('rejects a timestamp it cannot round-trip', () => {
    expect(() => encodeCursor({ ts: 1.5, id: 'a' })).toThrow(/whole epoch milliseconds/);
    expect(() => encodeCursor({ ts: Number.NaN, id: 'a' })).toThrow(/finite/);
    expect(() => encodeCursor({ ts: Number.POSITIVE_INFINITY, id: 'a' })).toThrow(/finite/);
    expect(() => encodeCursor({ ts: new Date(Number.NaN), id: 'a' })).toThrow(/Invalid Date/);
    expect(() => encodeCursor({ ts: 8640000000000001, id: 'a' })).toThrow(/representable/);
    expect(() => encodeCursor({ ts: {} as unknown as number, id: 'a' })).toThrow(/string, number/);
  });

  it('accepts the extremes of the Date range', () => {
    expect(decodeCursor(encodeCursor({ ts: 8640000000000000, id: 'a' })).ts).toBe(8640000000000000);
    expect(decodeCursor(encodeCursor({ ts: -8640000000000000, id: 'a' })).ts).toBe(
      -8640000000000000,
    );
  });

  it('rejects a timestamp string that is ambiguous or impossible', () => {
    // No offset means local time, which would differ per device.
    expect(() => encodeCursor({ ts: '2026-09-16T12:34:56', id: 'a' })).toThrow(/ISO-8601/);
    // Engines disagree about this one: some read it as March 3rd.
    expect(() => encodeCursor({ ts: '2026-02-31T00:00:00Z', id: 'a' })).toThrow(/day/);
    expect(() => encodeCursor({ ts: '2023-02-29T00:00:00Z', id: 'a' })).toThrow(/day/);
    expect(() => encodeCursor({ ts: '2026-13-01T00:00:00Z', id: 'a' })).toThrow(/month/);
    expect(() => encodeCursor({ ts: '2026-09-16T24:00:00Z', id: 'a' })).toThrow(/hour/);
    expect(() => encodeCursor({ ts: '2026-09-16T12:60:00Z', id: 'a' })).toThrow(/minute/);
    expect(() => encodeCursor({ ts: '2026-09-16T12:34:60Z', id: 'a' })).toThrow(/second/);
    expect(() => encodeCursor({ ts: 'not a date', id: 'a' })).toThrow(/ISO-8601/);
    // Epoch milliseconds as a string would be read as a year by Date.parse.
    expect(() => encodeCursor({ ts: '1789562096123', id: 'a' })).toThrow(/ISO-8601/);
  });

  it('accepts a leap day that exists', () => {
    expect(decodeCursor(encodeCursor({ ts: '2024-02-29T00:00:00Z', id: 'a' })).ts).toBe(
      Date.UTC(2024, 1, 29),
    );
  });
});

describe('decodeCursor', () => {
  it('round-trips exactly', () => {
    const cases: Array<{ ts: number; id: string }> = [
      { ts: 0, id: 'a' },
      { ts: TS, id: ID },
      { ts: -1, id: '42' },
      { ts: 1, id: 'a-b_c.d~e' },
    ];
    for (const input of cases) {
      expect(decodeCursor(encodeCursor(input))).toEqual(input);
    }
  });

  it('is stable: re-encoding a decoded cursor gives the same string', () => {
    const cursor = encodeCursor({ ts: TS, id: ID });
    const decoded = decodeCursor(cursor);
    expect(encodeCursor(decoded)).toBe(cursor);
  });

  it('rejects an unknown version instead of guessing', () => {
    const v2 = forge('wlc' + SEP + '2' + SEP + '0' + SEP + 'a');
    expect(() => decodeCursor(v2)).toThrow(/unsupported cursor version 2/);
    expect(CURSOR_VERSION).toBe(1);
  });

  it('rejects anything that is not one of our cursors', () => {
    expect(() => decodeCursor('')).toThrow(/non-empty/);
    expect(() => decodeCursor(null as unknown as string)).toThrow(/non-empty/);
    expect(() => decodeCursor('not base64!!')).toThrow(/base64url/);
    expect(() => decodeCursor('====')).toThrow(/base64url/);
    expect(() => decodeCursor(forge('wlc'))).toThrow(/fields/);
    expect(() => decodeCursor(forge('wlc' + SEP + '1' + SEP + '0'))).toThrow(/fields/);
    expect(() => decodeCursor(forge('xxx' + SEP + '1' + SEP + '0' + SEP + 'a'))).toThrow(
      /not a Waterlands cursor/,
    );
    expect(() => decodeCursor(base64UrlEncode(new Uint8Array([0xff, 0xfe])))).toThrow(/ASCII/);
  });

  it('rejects a timestamp field that is not canonical', () => {
    // "01" and "-0" decode to numbers that would re-encode differently, which
    // means two cursors for one row.
    expect(() => decodeCursor(forge('wlc' + SEP + '1' + SEP + '01' + SEP + 'a'))).toThrow(
      /canonical/,
    );
    expect(() => decodeCursor(forge('wlc' + SEP + '1' + SEP + '-0' + SEP + 'a'))).toThrow(
      /canonical/,
    );
    expect(() => decodeCursor(forge('wlc' + SEP + '1' + SEP + '1.5' + SEP + 'a'))).toThrow(
      /canonical/,
    );
    expect(() => decodeCursor(forge('wlc' + SEP + '1' + SEP + '1e3' + SEP + 'a'))).toThrow(
      /canonical/,
    );
    expect(() => decodeCursor(forge('wlc' + SEP + '1' + SEP + '' + SEP + 'a'))).toThrow(
      /canonical/,
    );
    expect(() =>
      decodeCursor(forge('wlc' + SEP + '1' + SEP + '8640000000000001' + SEP + 'a')),
    ).toThrow(/representable/);
  });

  it('rejects an empty id field', () => {
    expect(() => decodeCursor(forge('wlc' + SEP + '1' + SEP + '0' + SEP + ''))).toThrow(
      /non-empty/,
    );
  });

  it('is obfuscation, not authentication', () => {
    // Stated as a test so nobody later mistakes the opacity for a guarantee: a
    // forged cursor decodes fine, and the endpoint is what scopes the query.
    const forged = forge('wlc' + SEP + '1' + SEP + '123' + SEP + 'someone-elses-id');
    expect(decodeCursor(forged)).toEqual({ ts: 123, id: 'someone-elses-id' });
  });
});
