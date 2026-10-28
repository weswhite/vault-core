/**
 * @waterlands/vault-core/crypto
 *
 * Client-only. Importing this from a server render or a `.server.ts` file pulls
 * crypto into a bundle that has no business holding it — see the note in
 * `index.ts`.
 *
 * The one legitimate server use is `fingerprintPublicKey`, to verify at
 * enrollment that a client's claimed fingerprint really is the SHA-256 of the
 * key it sent. That is a hash, not a secret, and it is cheap enough that the
 * import is worth it there.
 */

export {
  DATA_KEY_SIZE,
  generateDataKey,
  vaultKeypairFromDataKey,
  fingerprintPublicKey,
  timingSafeEqual,
  wipe,
} from './crypto/keys.js';

export type { VaultKeypair } from './crypto/keys.js';

export { sealRecord, openRecord } from './crypto/seal.js';
export type { SealInput, OpenInput, RecordBinding } from './crypto/seal.js';

export { wrapDataKey, unwrapDataKey, parseWrapHeader } from './crypto/wrap.js';
export type { WrapInput, UnwrapInput, WrapBinding, WrapHeader } from './crypto/wrap.js';

export {
  ARGON2_INTERACTIVE,
  ARGON2_TEST_ONLY,
  setArgon2Provider,
  setRandomProvider,
  resetProviders,
  argon2idHash,
  randomBytes,
} from './crypto/provider.js';

export type { Argon2Params, Argon2Provider, RandomProvider } from './crypto/provider.js';

export {
  RECOVERY_WORD_COUNT,
  ARGON2_RECOVERY,
  RecoveryCodeError,
  normalizeRecoveryCode,
  generateRecoveryCode,
  isValidRecoveryCode,
  recoveryCodeToKey,
  formatRecoveryCode,
  pickVerificationIndices,
} from './kdf/recovery.js';
