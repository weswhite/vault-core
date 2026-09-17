/**
 * WLV1 record header, and the base64url codec everything crosses the wire in.
 *
 * Runs on Node, in a browser worker, and on Hermes. That last one sets the
 * language floor: no Buffer, no atob/btoa, no String.replaceAll, no Array.at,
 * no Object.hasOwn, no regex lookbehind or Unicode property escapes.
 *
 * See FORMAT.md for the byte layout and why it is shaped this way.
 */

import {
  ENVELOPE_VERSION,
  SUPPORTED_ENVELOPE_VERSIONS,
  SUITE_X25519_HKDF_XCHACHA20,
} from '../version.js';

/** "WLV1" */
export const RECORD_MAGIC = new Uint8Array([0x57, 0x4c, 0x56, 0x31]);

export const RECORD_HEADER_SIZE = 40;
export const EPK_SIZE = 32;
export const TAG_SIZE = 16;

/** 40 header + at least 1 byte of plaintext + 16 tag. */
export const MIN_RECORD_SIZE = RECORD_HEADER_SIZE + 1 + TAG_SIZE;

/**
 * Refuse anything larger than this. A sealed row is a few hundred bytes; 8 KiB
 * is generous for a long note and small enough that a malicious client cannot
 * make the server allocate meaningfully.
 */
export const MAX_RECORD_BYTES = 8192;

export const FLAG_PADDED = 0x01;
/** padBucket when the record is not padded. */
export const PAD_BUCKET_NONE = 0xff;

export interface RecordHeader {
  version: number;
  suite: number;
  flags: number;
  padBucket: number;
  padded: boolean;
  epk: Uint8Array;
  /** Byte offset where ciphertext||tag begins. Always RECORD_HEADER_SIZE for v1. */
  bodyOffset: number;
}

export interface BuildHeaderInput {
  version?: number;
  suite?: number;
  padded: boolean;
  padBucket: number;
  epk: Uint8Array;
}

export function buildRecordHeader(input: BuildHeaderInput): Uint8Array {
  const { epk } = input;
  if (epk.length !== EPK_SIZE) {
    throw new VaultFormatError(`epk must be ${EPK_SIZE} bytes, got ${epk.length}`);
  }
  const header = new Uint8Array(RECORD_HEADER_SIZE);
  header.set(RECORD_MAGIC, 0);
  header[4] = input.version ?? ENVELOPE_VERSION;
  header[5] = input.suite ?? SUITE_X25519_HKDF_XCHACHA20;
  header[6] = input.padded ? FLAG_PADDED : 0;
  header[7] = input.padded ? input.padBucket : PAD_BUCKET_NONE;
  header.set(epk, 8);
  return header;
}

export class VaultFormatError extends Error {
  readonly code: string;
  constructor(message: string, code = 'VAULT_FORMAT') {
    super(message);
    this.name = 'VaultFormatError';
    this.code = code;
  }
}

/**
 * Cheap check that bytes look like a vault record. Does not authenticate
 * anything — a blob can pass this and still fail to open.
 */
export function isVaultBlob(bytes: Uint8Array): boolean {
  if (bytes.length < MIN_RECORD_SIZE) return false;
  for (let i = 0; i < RECORD_MAGIC.length; i++) {
    if (bytes[i] !== RECORD_MAGIC[i]) return false;
  }
  return true;
}

export function parseRecordHeader(bytes: Uint8Array): RecordHeader {
  if (bytes.length < MIN_RECORD_SIZE) {
    throw new VaultFormatError(
      `record too short: ${bytes.length} < ${MIN_RECORD_SIZE}`,
      'VAULT_TOO_SHORT',
    );
  }
  if (!isVaultBlob(bytes)) {
    throw new VaultFormatError('bad magic, not a WLV record', 'VAULT_BAD_MAGIC');
  }

  const version = bytes[4];
  if (SUPPORTED_ENVELOPE_VERSIONS.indexOf(version) === -1) {
    // Do not "handle" this by falling back to another version. An unknown
    // version means this build is older than the record; opening it with the
    // wrong schedule would fail the tag anyway, and a clear error is what tells
    // the user to update rather than that their data is corrupt.
    throw new VaultFormatError(
      `unsupported envelope version ${version}`,
      'VAULT_UNSUPPORTED_VERSION',
    );
  }

  const suite = bytes[5];
  if (suite !== SUITE_X25519_HKDF_XCHACHA20) {
    throw new VaultFormatError(`unsupported suite ${suite}`, 'VAULT_UNSUPPORTED_SUITE');
  }

  const flags = bytes[6];
  if ((flags & ~FLAG_PADDED) !== 0) {
    throw new VaultFormatError(`reserved flag bits set: ${flags}`, 'VAULT_BAD_FLAGS');
  }

  const padded = (flags & FLAG_PADDED) !== 0;
  const padBucket = bytes[7];
  if (!padded && padBucket !== PAD_BUCKET_NONE) {
    throw new VaultFormatError('padBucket set on an unpadded record', 'VAULT_BAD_FLAGS');
  }

  return {
    version,
    suite,
    flags,
    padBucket,
    padded,
    epk: bytes.subarray(8, 8 + EPK_SIZE),
    bodyOffset: RECORD_HEADER_SIZE,
  };
}

export interface ValidateOptions {
  maxBytes?: number;
}

export interface ValidationResult {
  ok: boolean;
  code?: string;
  message?: string;
  header?: RecordHeader;
}

/**
 * Shape check for the server, which can never decrypt and so can only verify
 * that a client sent something structurally sane. Never throws; the caller maps
 * the code to an HTTP status.
 */
export function validateRecordShape(
  blob: string | Uint8Array,
  options: ValidateOptions = {},
): ValidationResult {
  const maxBytes = options.maxBytes ?? MAX_RECORD_BYTES;
  let bytes: Uint8Array;

  if (typeof blob === 'string') {
    if (!isBase64Url(blob)) {
      return { ok: false, code: 'VAULT_BAD_ENCODING', message: 'not base64url' };
    }
    try {
      bytes = base64UrlDecode(blob);
    } catch (err) {
      return {
        ok: false,
        code: 'VAULT_BAD_ENCODING',
        message: err instanceof Error ? err.message : 'decode failed',
      };
    }
  } else {
    bytes = blob;
  }

  if (bytes.length > maxBytes) {
    return {
      ok: false,
      code: 'VAULT_TOO_LARGE',
      message: `${bytes.length} > ${maxBytes}`,
    };
  }

  try {
    return { ok: true, header: parseRecordHeader(bytes) };
  } catch (err) {
    if (err instanceof VaultFormatError) {
      return { ok: false, code: err.code, message: err.message };
    }
    throw err;
  }
}

// ── base64url ───────────────────────────────────────────────────────────────
// Hand-rolled because the three runtimes disagree on what is available:
// Node has Buffer, browsers have atob, Hermes reliably has neither.

const B64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const B64URL_LOOKUP = /* @__PURE__ */ (() => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64URL_ALPHABET.length; i++) {
    table[B64URL_ALPHABET.charCodeAt(i)] = i;
  }
  return table;
})();

/** Unpadded base64url. No '=', no '+', no '/'. */
export function base64UrlEncode(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out +=
      B64URL_ALPHABET[(n >> 18) & 63] +
      B64URL_ALPHABET[(n >> 12) & 63] +
      B64URL_ALPHABET[(n >> 6) & 63] +
      B64URL_ALPHABET[n & 63];
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i] << 16;
    out += B64URL_ALPHABET[(n >> 18) & 63] + B64URL_ALPHABET[(n >> 12) & 63];
  } else if (rem === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out +=
      B64URL_ALPHABET[(n >> 18) & 63] +
      B64URL_ALPHABET[(n >> 12) & 63] +
      B64URL_ALPHABET[(n >> 6) & 63];
  }
  return out;
}

export function isBase64Url(value: string): boolean {
  // The empty string is valid base64url for zero bytes, so the codec round-trips
  // cleanly. Callers that need a non-empty value check length themselves;
  // validateRecordShape already rejects short input via MIN_RECORD_SIZE.
  if (value.length === 0) return true;
  // A 4k-group remainder of 1 char cannot encode any whole byte.
  if (value.length % 4 === 1) return false;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code > 127 || B64URL_LOOKUP[code] === -1) return false;
  }
  return true;
}

export function base64UrlDecode(value: string): Uint8Array {
  if (!isBase64Url(value)) {
    throw new VaultFormatError('invalid base64url', 'VAULT_BAD_ENCODING');
  }
  const groups = value.length >> 2;
  const rem = value.length & 3;
  const outLen = groups * 3 + (rem === 2 ? 1 : rem === 3 ? 2 : 0);
  const out = new Uint8Array(outLen);

  let oi = 0;
  let vi = 0;
  for (let g = 0; g < groups; g++) {
    const n =
      (B64URL_LOOKUP[value.charCodeAt(vi)] << 18) |
      (B64URL_LOOKUP[value.charCodeAt(vi + 1)] << 12) |
      (B64URL_LOOKUP[value.charCodeAt(vi + 2)] << 6) |
      B64URL_LOOKUP[value.charCodeAt(vi + 3)];
    out[oi++] = (n >> 16) & 0xff;
    out[oi++] = (n >> 8) & 0xff;
    out[oi++] = n & 0xff;
    vi += 4;
  }
  if (rem === 2) {
    const n =
      (B64URL_LOOKUP[value.charCodeAt(vi)] << 18) |
      (B64URL_LOOKUP[value.charCodeAt(vi + 1)] << 12);
    out[oi++] = (n >> 16) & 0xff;
  } else if (rem === 3) {
    const n =
      (B64URL_LOOKUP[value.charCodeAt(vi)] << 18) |
      (B64URL_LOOKUP[value.charCodeAt(vi + 1)] << 12) |
      (B64URL_LOOKUP[value.charCodeAt(vi + 2)] << 6);
    out[oi++] = (n >> 16) & 0xff;
    out[oi++] = (n >> 8) & 0xff;
  }
  return out;
}
