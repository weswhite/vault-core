/**
 * The payload codec's rules, as opposed to its bytes.
 *
 * The bytes are the test vectors' job, and they run on Node, in the browser and
 * on Hermes. What is here is what the vectors cannot express: which values the
 * codec refuses, and what it does with a key it has never seen.
 *
 * `tsp` is the reason this file exists. It is the first key whose value is a
 * list rather than a scalar, so it is the first one where "must be a string"
 * was the wrong check.
 */

import { describe, it, expect } from 'vitest';
import { encodePayload, decodePayload } from './payload.js';
import { VaultFormatError } from './format.js';

const utf8 = new TextEncoder();

describe('a list-valued key', () => {
  it('round-trips, order intact', () => {
    const payload = { nm: 'Cedar Hole', tsp: ['Walleye', 'Arctic Grayling'] };

    expect(decodePayload(encodePayload(payload))).toEqual(payload);
  });

  it('refuses a bare string where a list belongs', () => {
    // Joining on commas is the obvious shortcut and it loses any species whose
    // name contains one. The codec says no rather than letting it through.
    expect(() => encodePayload({ tsp: 'Walleye' } as never)).toThrow(VaultFormatError);
  });

  it('refuses a list with a non-string in it', () => {
    expect(() => encodePayload({ tsp: ['Walleye', 7] } as never)).toThrow(
      /must be an array of strings/,
    );
  });

  it('writes an empty list when given one, having been given one', () => {
    // Callers omit empty rather than passing []; the codec is not where that
    // decision belongs, so it does as it is told.
    expect(decodePayload(encodePayload({ tsp: [] }))).toEqual({ tsp: [] });
  });

  it('refuses a list on the wire where a string belongs', () => {
    const bytes = utf8.encode(JSON.stringify({ nm: ['Cedar Hole'] }));

    expect(() => decodePayload(bytes)).toThrow(/must be a string/);
  });

  it('refuses a string on the wire where a list belongs', () => {
    const bytes = utf8.encode(JSON.stringify({ tsp: 'Walleye' }));

    expect(() => decodePayload(bytes)).toThrow(/must be an array of strings/);
  });
});

describe('the serialisation order', () => {
  it('puts a new key last, whatever order the object was built in', () => {
    // Appended, never inserted. Object key order is an engine detail, and the
    // vectors are bytes, so the order here is the format rather than a habit.
    const bytes = encodePayload({ tsp: ['Walleye'], lat: 1, nm: 'n' } as never);

    expect(new TextDecoder().decode(bytes)).toBe('{"lat":1,"nm":"n","tsp":["Walleye"]}');
  });
});

describe('a key from a newer version', () => {
  it('is ignored rather than refused', () => {
    // An older client must still read the fields it knows. Refusing the record
    // would hide a note that is sitting right there in the plaintext.
    const bytes = utf8.encode(JSON.stringify({ nt: 'a note', zzz: 'from the future' }));

    expect(decodePayload(bytes)).toEqual({ nt: 'a note' });
  });

  it('reads a record written before the key existed', () => {
    // Which is every record sealed before this release: no tsp at all, and an
    // absent field reads as empty, not as locked.
    const bytes = utf8.encode(JSON.stringify({ nm: 'Cedar Hole' }));

    expect(decodePayload(bytes)).toEqual({ nm: 'Cedar Hole' });
  });
});

describe('absent and null', () => {
  it('omits both rather than writing them', () => {
    expect(new TextDecoder().decode(encodePayload({ nm: 'n', tsp: undefined }))).toBe('{"nm":"n"}');
    expect(new TextDecoder().decode(encodePayload({ nm: 'n', tsp: null } as never))).toBe(
      '{"nm":"n"}',
    );
  });
});
