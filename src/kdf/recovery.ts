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
 * Recovery wraps use cheap Argon2 parameters, and must.
 *
 * Argon2 cost exists to make guessing expensive. A 6-digit PIN has roughly 20
 * bits of entropy and needs every bit of slowdown available. A 24-word code has
 * 256 bits: at a trillion guesses a second with no key derivation cost at all,
 * exhausting it takes about 10^57 years. Cost added on top of that defends
 * against nothing, and it is charged to someone who has just lost their phone
 * and is typing 24 words into a new one.
 *
 * These numbers are not a guess. Measured in pure JS on Hermes, on a Galaxy A17
 * (2026-09-20), deriving one key:
 *
 *   16 MiB, t=2  320 s     <- what this used to be
 *    1 MiB, t=1   10.3 s
 *  256 KiB, t=1    2.7 s
 *   64 KiB, t=1    0.8 s   <- what it is now
 *
 * Five minutes is not a slow unlock, it is a broken one, and it applied to
 * enrollment on a phone as well as recovery. The web pays the same cost in
 * about a second because V8 has a JIT and Hermes does not, which is exactly why
 * the weakest platform sets this number.
 *
 * A PIN wrap is the opposite case and keeps ARGON2_INTERACTIVE: twenty bits of
 * entropy is guessable, so every bit of slowdown counts. Because parameters
 * travel inside the wrap blob, the two wraps for the same user legitimately
 * differ, and wraps made before this change keep opening with their own.
 *
 * This holds only while the recovery code is machine-generated. A code the user
 * invents is not 256 bits, and cost would have to come back with it -- which on
 * a phone means a native Argon2 binding, not a bigger number here.
 */
export const ARGON2_RECOVERY: Argon2Params = {
  memKiB: 64,
  timeCost: 1,
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
 * Unicode whitespace, by code point. Covers the separators that turn up when a
 * code is pasted out of a password manager or a notes app: NBSP, the en-quad
 * family, line and paragraph separators, and the ideographic space.
 */
function isUnicodeSpace(code: number): boolean {
  return (
    code === 0x09 ||
    code === 0x0a ||
    code === 0x0b ||
    code === 0x0c ||
    code === 0x0d ||
    code === 0x20 ||
    code === 0x85 ||
    code === 0xa0 ||
    code === 0x1680 ||
    (code >= 0x2000 && code <= 0x200a) ||
    code === 0x2028 ||
    code === 0x2029 ||
    code === 0x202f ||
    code === 0x205f ||
    code === 0x3000
  );
}

function collapseWhitespace(value: string): string {
  let out = '';
  let pendingSpace = false;
  for (let i = 0; i < value.length; i++) {
    if (isUnicodeSpace(value.charCodeAt(i))) {
      pendingSpace = out.length > 0;
      continue;
    }
    if (pendingSpace) {
      out += ' ';
      pendingSpace = false;
    }
    out += value[i];
  }
  return out;
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

  // Collapse every Unicode whitespace character to a single space.
  //
  // Written as a code-point check rather than a regex for two reasons: \s has
  // differed between Hermes and V8 on exotic separators, and a regex literal
  // holding these escapes is one bad codemod away from containing a real
  // newline and silently becoming a different pattern.
  out = collapseWhitespace(out);

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
