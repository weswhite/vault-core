/**
 * The recovery code is 12 words, and that is the only length anything accepts.
 *
 * 24 is refused, and that refusal has a test because of what it would cost if
 * it were ever wrong in the other direction. A recovery wrap is derived from the
 * code, it is the only wrap on our servers, and nothing on our side can
 * re-derive it. So a 24-word code reaching this code path at all would mean a
 * vault exists that 0.7.0 cannot open. None did when 24 was retired, which is
 * the only reason retiring it was safe.
 */

import { describe, it, expect } from 'vitest';
import {
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

/** The BIP-39 all-zeros codes at 24 words (retired) and 12 (current). */
const RETIRED_24 = `${'abandon '.repeat(23)}art`;
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

describe('a 24-word code', () => {
  it('does not validate, though it is a valid BIP-39 mnemonic', () => {
    // The checksum is fine. The length is what rejects it, which is the whole
    // point: this is a well-formed code for a vault that cannot exist.
    expect(isValidRecoveryCode(RETIRED_24)).toBe(false);
  });

  it('derives nothing, and says the length is why', () => {
    let thrown: unknown;
    try {
      recoveryCodeToKey(RETIRED_24);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(RecoveryCodeError);
    expect((thrown as RecoveryCodeError).code).toBe('VAULT_RECOVERY_WRONG_LENGTH');
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

  it('throws naming the one accepted length', () => {
    let thrown: unknown;
    try {
      recoveryCodeToKey('abandon abandon abandon');
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(RecoveryCodeError);
    expect((thrown as RecoveryCodeError).code).toBe('VAULT_RECOVERY_WRONG_LENGTH');
    expect((thrown as RecoveryCodeError).message).toContain('must be 12 words');
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

  it('span the length the caller passes, not the default', () => {
    // Enrollment passes the real length of the code in hand rather than
    // trusting the constant. A deterministic walk, so the set fills without a
    // random source.
    let next = -1;
    const picked = pickVerificationIndices(
      6,
      (max) => {
        next = (next + 1) % max;
        return next;
      },
      6,
    );
    expect(picked).toHaveLength(6);
    expect(Math.max(...picked)).toBe(5);
  });

  it('refuses to quiz more words than the code has', () => {
    expect(() => pickVerificationIndices(13, (max) => max - 1)).toThrow(RecoveryCodeError);
  });
});
