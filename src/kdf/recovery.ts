/**
 * The 24-word recovery code.
 *
 * This is the only way back into a vault after a lost phone, and the only wrap
 * stored on our servers. If a user loses both their PIN and this code, their
 * data is gone and nobody, including us, can recover it. That sentence has to
 * appear verbatim at enrollment.
 *
 * BIP-39 English via @scure/bip39 rather than a bespoke wordlist. The wordlist
 * is unambiguous in its first four characters (so autocomplete works and typos
 * are catchable), it is the format every hardware wallet user already
 * recognises, and hand-rolling one is the kind of thing that looks fine until a
 * homograph pair makes a code undecodable.
 *
 * 24 words is 264 bits: 256 bits of entropy plus an 8-bit checksum. The checksum
 * is what lets the UI reject a mistyped word before the user believes they have
 * a working code.
 */

import { generateMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import type { Argon2Params } from '../crypto/provider.js';

export const RECOVERY_WORD_COUNT = 24;
const ENTROPY_BITS = 256;

/**
 * Recovery wraps can use cheap Argon2 parameters, and should.
 *
 * Argon2 cost exists to make guessing expensive. A 6-digit PIN has roughly 20
 * bits of entropy and needs every bit of slowdown available. A 24-word code has
 * 256 bits, so brute force is off the table regardless of cost, and paying a
 * second of key derivation on a device someone is already struggling with is
 * pure friction.
 *
 * Because parameters travel inside the wrap blob, the two wraps for the same
 * user can legitimately differ.
 */
export const ARGON2_RECOVERY: Argon2Params = {
  memKiB: 16384,
  timeCost: 2,
  lanes: 1,
};

export class RecoveryCodeError extends Error {
  readonly code: string;
  constructor(message: string, code = 'VAULT_BAD_RECOVERY_CODE') {
    super(message);
    this.name = 'RecoveryCodeError';
    this.code = code;
  }
}

/**
 * Lowercase, NFKD, collapse all whitespace to single spaces, trim.
 *
 * Users paste these out of password managers and notes apps, which introduce
 * non-breaking spaces, smart punctuation and line breaks. Normalising
 * aggressively is the difference between "your code is wrong" and the code
 * simply working.
 */
export function normalizeRecoveryCode(raw: string): string {
  let out = raw.normalize('NFKD').toLowerCase();

  // Replace every Unicode whitespace character with a plain space. Written as an
  // explicit class rather than \s because Hermes and V8 have differed on which
  // exotic separators \s matches.
  out = out.replace(
    /[
    -     　]+/g,
    ' ',
  );

  return out.trim();
}

export function generateRecoveryCode(): string {
  return generateMnemonic(wordlist, ENTROPY_BITS);
}

export function isValidRecoveryCode(raw: string): boolean {
  const normalized = normalizeRecoveryCode(raw);
  if (normalized.length === 0) return false;
  if (normalized.split(' ').length !== RECOVERY_WORD_COUNT) return false;
  try {
    return validateMnemonic(normalized, wordlist);
  } catch {
    return false;
  }
}

/**
 * The 32 bytes used as the Argon2 password for the recovery wrap.
 *
 * Deliberately the BIP-39 entropy rather than the UTF-8 words: it is fixed
 * length, and it means a code that differs only in whitespace or case produces
 * the same key without relying on normalisation having been perfect.
 */
export function recoveryCodeToKey(raw: string): Uint8Array {
  const normalized = normalizeRecoveryCode(raw);

  const words = normalized.length === 0 ? [] : normalized.split(' ');
  if (words.length !== RECOVERY_WORD_COUNT) {
    throw new RecoveryCodeError(
      `recovery code must be ${RECOVERY_WORD_COUNT} words, got ${words.length}`,
      'VAULT_RECOVERY_WRONG_LENGTH',
    );
  }

  try {
    return mnemonicToEntropy(normalized, wordlist);
  } catch (err) {
    // @scure distinguishes an unknown word from a bad checksum; surface that,
    // because "word 7 is not in the list" is actionable for the user and
    // "checksum failed" means they have a word in the wrong position.
    throw new RecoveryCodeError(
      err instanceof Error ? err.message : 'invalid recovery code',
      'VAULT_RECOVERY_INVALID',
    );
  }
}

/**
 * Split into groups for display. Grouping is what makes a 24-word code
 * transcribable without losing your place.
 */
export function formatRecoveryCode(code: string, groupSize = 4): string[][] {
  const words = normalizeRecoveryCode(code).split(' ');
  const groups: string[][] = [];
  for (let i = 0; i < words.length; i += groupSize) {
    groups.push(words.slice(i, i + groupSize));
  }
  return groups;
}

/**
 * Pick N distinct word positions to quiz the user on before enabling Continue.
 *
 * Verification is not optional ceremony. Without it people screenshot the
 * screen, never check it, and discover at recovery time that they saved the
 * wrong thing.
 */
export function pickVerificationIndices(
  count: number,
  random: (max: number) => number,
): number[] {
  if (count < 1 || count > RECOVERY_WORD_COUNT) {
    throw new RecoveryCodeError(`cannot verify ${count} of ${RECOVERY_WORD_COUNT} words`);
  }
  const chosen = new Set<number>();
  while (chosen.size < count) {
    chosen.add(random(RECOVERY_WORD_COUNT));
  }
  return Array.from(chosen).sort((a, b) => a - b);
}
