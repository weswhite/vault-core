/**
 * The recovery code.
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
 * 12 words is 132 bits: 128 bits of entropy plus a 4-bit checksum. The checksum
 * is what lets the UI reject a mistyped word before the user believes they have
 * a working code, and it is the one thing that got weaker when the code got
 * shorter: it catches 15 of every 16 bad codes rather than 255 of 256. It was
 * never a security property. A wrong key fails the wrap's AEAD tag either way,
 * so the cost of a miss is an Argon2 the user waits out before being told no,
 * which on the slowest phone we have measured is 0.8 s.
 *
 * Codes issued before 0.7.0 are 24 words and still open. See
 * ACCEPTED_RECOVERY_WORD_COUNTS.
 */

import { generateMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import {
  ACCEPTED_RECOVERY_WORD_COUNTS,
  RECOVERY_WORD_COUNT,
} from '../recoveryWords.js';
import type { Argon2Params } from '../crypto/provider.js';

export { ACCEPTED_RECOVERY_WORD_COUNTS, RECOVERY_WORD_COUNT };

const ENTROPY_BITS = 128;

/**
 * Recovery wraps use cheap Argon2 parameters, and must.
 *
 * Argon2 cost exists to make guessing expensive. A 6-digit PIN has roughly 20
 * bits of entropy and needs every bit of slowdown available. A 12-word code has
 * 128 bits: at a trillion guesses a second with no key derivation cost at all,
 * exhausting it takes about 10^19 years, a billion times the age of the
 * universe. Cost added on top of that defends against nothing, and it is
 * charged to someone who has just lost their phone and is typing the code into
 * a new one.
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
 * invents is not 128 bits, and cost would have to come back with it -- which on
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
  if (!ACCEPTED_RECOVERY_WORD_COUNTS.includes(normalized.split(' ').length)) return false;
  try {
    return validateMnemonic(normalized, wordlist);
  } catch {
    return false;
  }
}

/**
 * The bytes used as the Argon2 password for the recovery wrap: 16 for a 12-word
 * code, 32 for a 24-word one issued before 0.7.0.
 *
 * Deliberately the BIP-39 entropy rather than the UTF-8 words: it is fixed
 * length for a given code length, and it means a code that differs only in
 * whitespace or case produces the same key without relying on normalisation
 * having been perfect.
 *
 * wrapDataKey asks only that a secret be non-empty, so the shorter password
 * needs nothing there, and a 24-word code still derives the same 32 bytes it
 * always did. That second part is a byte contract, and it is the whole reason an
 * existing recovery wrap keeps opening.
 */
export function recoveryCodeToKey(raw: string): Uint8Array {
  const normalized = normalizeRecoveryCode(raw);

  const words = normalized.length === 0 ? [] : normalized.split(' ');
  if (!ACCEPTED_RECOVERY_WORD_COUNTS.includes(words.length)) {
    throw new RecoveryCodeError(
      `recovery code must be ${ACCEPTED_RECOVERY_WORD_COUNTS.join(' or ')} words, got ${words.length}`,
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
 * Split into groups for display. Grouping is what makes a recovery code
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
 *
 * `wordCount` defaults to the length we generate, which is what enrollment
 * always has in hand. A caller holding the code should pass its real length
 * instead: this returns positions into a list of words on screen, and a number
 * past the end of that list quizzes the user on a blank.
 */
export function pickVerificationIndices(
  count: number,
  random: (max: number) => number,
  wordCount: number = RECOVERY_WORD_COUNT,
): number[] {
  if (count < 1 || count > wordCount) {
    throw new RecoveryCodeError(`cannot verify ${count} of ${wordCount} words`);
  }
  const chosen = new Set<number>();
  while (chosen.size < count) {
    chosen.add(random(wordCount));
  }
  return Array.from(chosen).sort((a, b) => a - b);
}
