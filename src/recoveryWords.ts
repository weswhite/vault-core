/**
 * How many words a recovery code has.
 *
 * Its own module, with no imports, because two kinds of consumer need these
 * numbers. `kdf/recovery.ts` needs them to generate and validate, and pulls in
 * the BIP-39 wordlist to do it. The enrollment and unlock screens need only the
 * numbers, and one of them (the web unlock dialog) renders on the server, where
 * importing anything from the crypto entry point drags a WASM module into the
 * SSR bundle. Both apps kept a private `const RECOVERY_WORDS = 24` for exactly
 * that reason, which is how a stale copy survives a change to the real number.
 */

/**
 * The length of a code we generate: 12 words, 128 bits of entropy plus a 4-bit
 * checksum.
 *
 * It was 24 words and 256 bits through 0.6.0. The entropy was never the weak
 * link. Exhausting 2^128 at a trillion guesses a second takes about 10^19
 * years, and each guess still has to pay an Argon2 first; the thing that loses
 * someone their vault is the paper, not the key length. What 24 words did cost
 * was real, and charged at the worst moment: transcribing them by hand, then
 * typing all 24 into a phone keyboard on the first unlock of every new device.
 */
export const RECOVERY_WORD_COUNT = 12;

/**
 * Every length an unlock accepts. Append only, and never remove 24.
 *
 * Anyone who enrolled before 0.7.0 has a recovery wrap on our servers derived
 * from a 24-word code, and nothing re-wraps it. Removing 24 from this list
 * locks those people out of their own data, permanently, with no path back that
 * we or they can take.
 */
export const ACCEPTED_RECOVERY_WORD_COUNTS: readonly number[] = [12, 24];
