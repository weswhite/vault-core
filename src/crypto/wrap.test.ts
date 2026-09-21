/**
 * What a wrap will and will not open.
 *
 * The cost floor is the interesting part. It depends on what the wrap protects,
 * because that is what Argon2 cost is for: a PIN is guessable and cost is the
 * only thing in the way, while a 24-word code is not guessable at any cost.
 * A single floor could not say that, and the one that used to be here made the
 * recovery path take five minutes on a mid-range Android.
 */

import { describe, it, expect } from 'vitest';
import {
  ARGON2_RECOVERY,
  ARGON2_TEST_ONLY,
  generateDataKey,
  unwrapDataKey,
  wrapDataKey,
} from '../crypto.js';
import { WRAP_TYPE_PIN, WRAP_TYPE_RECOVERY } from '../version.js';
import { base64UrlDecode, base64UrlEncode } from '../index.js';

const secret = new Uint8Array(32).fill(7);
const binding = (wrapType: number) => ({
  userId: 'usr_1',
  wrapType,
  keyVersion: 1,
  vaultPubKeyFp: 'fp',
});

function roundTrip(wrapType: number, params: { memKiB: number; timeCost: number; lanes: number }) {
  const dataKey = generateDataKey();
  const blob = wrapDataKey({ dataKey, secret, binding: binding(wrapType), params });
  return { dataKey, opened: unwrapDataKey({ blob, secret, binding: binding(wrapType) }) };
}

describe('a recovery wrap', () => {
  it('opens at the shipped parameters', () => {
    // 64 KiB / t=1: 0.8s on a Galaxy A17, where 16 MiB took 320s.
    const { dataKey, opened } = roundTrip(WRAP_TYPE_RECOVERY, ARGON2_RECOVERY);
    expect(Array.from(opened)).toEqual(Array.from(dataKey));
  });

  it('opens at a cost far above the floor too', () => {
    // Wraps made before the floor moved carry their own parameters.
    const { dataKey, opened } = roundTrip(WRAP_TYPE_RECOVERY, ARGON2_TEST_ONLY);
    expect(Array.from(opened)).toEqual(Array.from(dataKey));
  });

  it('refuses a cost below any sane floor', () => {
    const dataKey = generateDataKey();
    const blob = wrapDataKey({
      dataKey,
      secret,
      binding: binding(WRAP_TYPE_RECOVERY),
      params: { memKiB: 8, timeCost: 1, lanes: 1 },
    });
    expect(() => unwrapDataKey({ blob, secret, binding: binding(WRAP_TYPE_RECOVERY) })).toThrow(
      /implausible/,
    );
  });
});

describe('a PIN wrap', () => {
  it('opens at a cost worth having', () => {
    const { dataKey, opened } = roundTrip(WRAP_TYPE_PIN, ARGON2_TEST_ONLY);
    expect(Array.from(opened)).toEqual(Array.from(dataKey));
  });

  it('refuses the cheap parameters a recovery wrap is allowed', () => {
    // Twenty bits of entropy behind 64 KiB of work is a PIN anyone can guess,
    // so this is refused even though the same blob shape is fine for recovery.
    const dataKey = generateDataKey();
    const blob = wrapDataKey({
      dataKey,
      secret,
      binding: binding(WRAP_TYPE_PIN),
      params: ARGON2_RECOVERY,
    });
    expect(() => unwrapDataKey({ blob, secret, binding: binding(WRAP_TYPE_PIN) })).toThrow(
      /implausible/,
    );
  });
});

describe('any wrap', () => {
  it('refuses memory large enough to hang the device', () => {
    // The header is patched rather than produced: deriving at 2 GiB to prove
    // the check rejects 2 GiB would cost the suite the very thing the check
    // exists to prevent. The parse runs before any derivation, so this is the
    // path a hostile blob would take.
    const blob = wrapDataKey({
      dataKey: generateDataKey(),
      secret,
      binding: binding(WRAP_TYPE_RECOVERY),
      params: ARGON2_RECOVERY,
    });
    const bytes = base64UrlDecode(blob);
    const huge = 2097152;
    bytes[8] = (huge >>> 24) & 0xff;
    bytes[9] = (huge >>> 16) & 0xff;
    bytes[10] = (huge >>> 8) & 0xff;
    bytes[11] = huge & 0xff;

    expect(() =>
      unwrapDataKey({ blob: base64UrlEncode(bytes), secret, binding: binding(WRAP_TYPE_RECOVERY) }),
    ).toThrow(/implausible/);
  });
});
