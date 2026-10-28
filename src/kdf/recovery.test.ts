/**
 * The recovery code shrank to 12 words in 0.7.0, and 24-word codes must keep
 * opening forever.
 *
 * That second half is the part worth a test. The recovery wrap is the only wrap
 * on our servers, it was derived from a 24-word code for everyone who enrolled
 * before 0.7.0, and nothing re-wraps it. A length check that accepts only 12
 * would read as a tidy cleanup and would lock those people out of their own
 * data with no path back.
 */

import { describe, it, expect } from 'vitest';
import {
  ACCEPTED_RECOVERY_WORD_COUNTS,
  ARGON2_TEST_ONLY,
  RECOVERY_WORD_COUNT,
  RecoveryCodeError,
  generateDataKey,
  generateRecoveryCode,
  isValidRecoveryCode,
  pickVerificationIndices,
  recoveryCodeToKey,
  unwrapDataKey,
  wrapDataKey,
} from '../crypto.js';
import { WRAP_TYPE_RECOVERY } from '../version.js';

/** The BIP-39 all-zeros codes at both lengths. */
const LEGACY_24 = `${'abandon '.repeat(23)}art`;
const CURRENT_12 = `${'abandon '.repeat(11)}about`;

describe('generating a code', () => {
  it('makes 12 words', () => {
    expect(generateRecoveryCode().split(' ')).toHaveLength(12);
    expect(RECOVERY_WORD_COUNT).toBe(12);
  });

  it('makes a code that validates and derives 16 bytes', () => {
    const code = generateRecoveryCode();
    expect(isValidRecoveryCode(code)).toBe(true);
    expect(recoveryCodeToKey(code)).toHaveLength(16);
  });

  it('never repeats', () => {
    expect(generateRecoveryCode()).not.toBe(generateRecoveryCode());
  });
});

describe('a 24-word code from before 0.7.0', () => {
  it('still validates', () => {
    expect(isValidRecoveryCode(LEGACY_24)).toBe(true);
  });

  it('still derives the same 32 bytes', () => {
    // A byte contract. These are the bytes an existing recovery wrap on our
    // servers was built against; change them and that wrap stops opening.
    const key = recoveryCodeToKey(LEGACY_24);

    expect(key).toHaveLength(32);
    expect(Array.from(key).every((byte) => byte === 0)).toBe(true);
  });

  it('is still listed as accepted', () => {
    expect(ACCEPTED_RECOVERY_WORD_COUNTS).toContain(24);
    expect(ACCEPTED_RECOVERY_WORD_COUNTS).toContain(12);
  });
});

describe('a wrong length', () => {
  it.each([
    ['one word short', `${'abandon '.repeat(10)}about`],
    ['one word long', `${'abandon '.repeat(12)}about`],
    ['23 words', `${'abandon '.repeat(22)}art`],
    ['empty', ''],
  ])('%s does not validate', (_label, code) => {
    expect(isValidRecoveryCode(code)).toBe(false);
  });

  it('throws naming both accepted lengths', () => {
    let thrown: unknown;
    try {
      recoveryCodeToKey('abandon abandon abandon');
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(RecoveryCodeError);
    expect((thrown as RecoveryCodeError).code).toBe('VAULT_RECOVERY_WRONG_LENGTH');
    expect((thrown as RecoveryCodeError).message).toContain('12 or 24');
  });
});

describe('a bad checksum', () => {
  it('is caught at 12 words, where it is 4 bits', () => {
    // Swapping the last word breaks the checksum without leaving the wordlist,
    // which is the mistake the pre-check exists to catch.
    expect(isValidRecoveryCode(`${'abandon '.repeat(11)}abandon`)).toBe(false);
  });
});

describe('a 16-byte secret', () => {
  it('wraps and unwraps a data key', () => {
    // wrapDataKey only asks that a secret be non-empty, so the shorter password
    // needs no change there. This proves it end to end rather than by reading.
    const secret = recoveryCodeToKey(CURRENT_12);
    expect(secret).toHaveLength(16);

    const binding = {
      userId: 'usr_1',
      wrapType: WRAP_TYPE_RECOVERY,
      keyVersion: 1,
      vaultPubKeyFp: 'fp',
    };
    const dataKey = generateDataKey();
    const blob = wrapDataKey({ dataKey, secret, binding, params: ARGON2_TEST_ONLY });

    expect(Array.from(unwrapDataKey({ blob, secret, binding }))).toEqual(Array.from(dataKey));
  });
});

describe('verification positions', () => {
  it('stay inside a 12-word code by default', () => {
    // A walk rather than a constant: the picker collects distinct values, so a
    // source that always answers the same number never fills the set.
    let next = -1;
    const picked = pickVerificationIndices(3, (max) => {
      next = (next + 1) % max;
      return next;
    });

    expect(picked).toHaveLength(3);
    expect(picked.every((i) => i >= 0 && i < 12)).toBe(true);
  });

  it('span the length the caller passes', () => {
    // A deterministic walk, so the set fills without a random source.
    let next = -1;
    const picked = pickVerificationIndices(
      24,
      (max) => {
        next = (next + 1) % max;
        return next;
      },
      24,
    );
    expect(picked).toHaveLength(24);
    expect(Math.max(...picked)).toBe(23);
  });

  it('refuses to quiz more words than the code has', () => {
    expect(() => pickVerificationIndices(13, (max) => max - 1)).toThrow(RecoveryCodeError);
  });
});
