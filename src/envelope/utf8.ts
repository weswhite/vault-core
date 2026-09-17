/**
 * UTF-8 encode and decode.
 *
 * Hand-rolled because `TextEncoder` and `TextDecoder` cannot be relied on across
 * the three runtimes. Node and browsers have them; React Native on Hermes does
 * not guarantee them, and whether they exist has varied by RN version and by
 * which polyfills an app happens to load. A package whose whole job is producing
 * identical bytes everywhere cannot depend on a global that might be absent, or
 * worse, present but supplied by a polyfill that rounds differently on
 * malformed input.
 *
 * Roughly 60 lines to remove an entire class of "works on my platform".
 */

import { VaultFormatError } from './format.js';

export function encodeUtf8(value: string): Uint8Array {
  // Worst case is 3 bytes per UTF-16 code unit; a surrogate pair is 2 units and
  // 4 bytes, so this bound always holds.
  const buf = new Uint8Array(value.length * 3);
  let out = 0;

  for (let i = 0; i < value.length; i++) {
    let code = value.charCodeAt(i);

    if (code < 0x80) {
      buf[out++] = code;
      continue;
    }
    if (code < 0x800) {
      buf[out++] = 0xc0 | (code >> 6);
      buf[out++] = 0x80 | (code & 0x3f);
      continue;
    }

    // Surrogate pair.
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < value.length) {
      const next = value.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        code = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
        i++;
        buf[out++] = 0xf0 | (code >> 18);
        buf[out++] = 0x80 | ((code >> 12) & 0x3f);
        buf[out++] = 0x80 | ((code >> 6) & 0x3f);
        buf[out++] = 0x80 | (code & 0x3f);
        continue;
      }
    }

    // A lone surrogate is not a valid code point. Substitute U+FFFD rather than
    // throwing: this encodes user free text, and one malformed character should
    // not fail a whole sync. WHATWG does the same.
    if (code >= 0xd800 && code <= 0xdfff) {
      code = 0xfffd;
    }

    buf[out++] = 0xe0 | (code >> 12);
    buf[out++] = 0x80 | ((code >> 6) & 0x3f);
    buf[out++] = 0x80 | (code & 0x3f);
  }

  return buf.subarray(0, out);
}

/**
 * Strict decode. Unlike the encoder, malformed input throws rather than
 * substituting, because by the time we decode, the AEAD tag has already verified
 * the bytes. Invalid UTF-8 at that point means an encoder on some platform is
 * producing garbage, which is exactly the cross-platform bug this package exists
 * to catch. Silently replacing it with U+FFFD would hide it.
 */
export function decodeUtf8(bytes: Uint8Array): string {
  let out = '';
  let i = 0;

  while (i < bytes.length) {
    const b0 = bytes[i];

    if (b0 < 0x80) {
      out += String.fromCharCode(b0);
      i += 1;
      continue;
    }

    let need: number;
    let code: number;
    let min: number;

    if (b0 >= 0xc2 && b0 <= 0xdf) {
      need = 1;
      code = b0 & 0x1f;
      min = 0x80;
    } else if (b0 >= 0xe0 && b0 <= 0xef) {
      need = 2;
      code = b0 & 0x0f;
      min = 0x800;
    } else if (b0 >= 0xf0 && b0 <= 0xf4) {
      need = 3;
      code = b0 & 0x07;
      min = 0x10000;
    } else {
      // Includes 0xc0/0xc1, which can only ever start an overlong encoding.
      throw new VaultFormatError(
        `invalid UTF-8 lead byte 0x${b0.toString(16)} at ${i}`,
        'VAULT_BAD_UTF8',
      );
    }

    if (i + need >= bytes.length) {
      throw new VaultFormatError(`truncated UTF-8 sequence at ${i}`, 'VAULT_BAD_UTF8');
    }

    for (let k = 1; k <= need; k++) {
      const b = bytes[i + k];
      if ((b & 0xc0) !== 0x80) {
        throw new VaultFormatError(
          `invalid UTF-8 continuation byte at ${i + k}`,
          'VAULT_BAD_UTF8',
        );
      }
      code = (code << 6) | (b & 0x3f);
    }

    // Overlong encodings and surrogates are both rejected. An overlong form is a
    // classic way to smuggle a byte past a naive validator.
    if (code < min) {
      throw new VaultFormatError(`overlong UTF-8 encoding at ${i}`, 'VAULT_BAD_UTF8');
    }
    if (code >= 0xd800 && code <= 0xdfff) {
      throw new VaultFormatError(`surrogate code point at ${i}`, 'VAULT_BAD_UTF8');
    }
    if (code > 0x10ffff) {
      throw new VaultFormatError(`code point out of range at ${i}`, 'VAULT_BAD_UTF8');
    }

    if (code < 0x10000) {
      out += String.fromCharCode(code);
    } else {
      const adjusted = code - 0x10000;
      out += String.fromCharCode(0xd800 + (adjusted >> 10), 0xdc00 + (adjusted & 0x3ff));
    }

    i += need + 1;
  }

  return out;
}
