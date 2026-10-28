/**
 * How many words a recovery code has.
 *
 * Its own module, with no imports, because two kinds of consumer need this
 * number. `kdf/recovery.ts` needs it to generate and validate, and pulls in the
 * BIP-39 wordlist to do it. The enrollment and unlock screens need only the
 * number, and one of them (the web unlock dialog) renders on the server, where
 * importing anything from the crypto entry point drags a WASM module into the
 * SSR bundle. Both apps kept a private `const RECOVERY_WORDS = 24` for exactly
 * that reason, which is how a stale copy survives a change to the real number.
 */

/**
 * The one length a recovery code has: 12 words, 128 bits of entropy plus a
 * 4-bit checksum. Generated at this length, and the only length an unlock
 * accepts.
 *
 * It was 24 words and 256 bits through 0.6.0. The entropy was never the weak
 * link. Exhausting 2^128 at a trillion guesses a second takes about 10^19
 * years, and each guess still has to pay an Argon2 first; the thing that loses
 * someone their vault is the paper, not the key length. What 24 words did cost
 * was real, and charged at the worst moment: transcribing them by hand, then
 * typing all 24 into a phone keyboard on the first unlock of every new device.
 *
 * 24 was accepted for one commit on the way here, then retired before 0.7.0
 * shipped, because no vault had been enrolled against one. If that ever stops
 * being true, a second accepted length is not the fix: a recovery wrap is
 * derived from the code and nothing on our side can re-derive it, so the only
 * path off a length is the owner rotating their own wrap from a device that is
 * already unlocked.
 */
export const RECOVERY_WORD_COUNT = 12;
