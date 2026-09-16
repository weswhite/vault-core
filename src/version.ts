/**
 * Version constants.
 *
 * Read FORMAT.md before changing anything here. These are data-format versions,
 * not software versions: once a record exists in production at a version, every
 * future build must be able to open it. Dropping a version from
 * SUPPORTED_ENVELOPE_VERSIONS destroys user data that nobody, including us, can
 * recover.
 */

/** Version written by seal(). */
export const ENVELOPE_VERSION = 1;

/** Every version open() can read. Append only. Never remove an entry. */
export const SUPPORTED_ENVELOPE_VERSIONS: readonly number[] = [1];

/** Version written by wrapDataKey(). */
export const WRAP_VERSION = 1;

/** Every wrap version unwrapDataKey() can read. Append only. */
export const SUPPORTED_WRAP_VERSIONS: readonly number[] = [1];

/**
 * Cipher suite. 1 = X25519 + HKDF-SHA256 + XChaCha20-Poly1305.
 * A new suite is a new number, and the old one keeps working.
 */
export const SUITE_X25519_HKDF_XCHACHA20 = 1;

/** KDF identifier stored in a wrap header. 1 = Argon2id. */
export const KDF_ARGON2ID = 1;

/** Which secret a wrap is derived from. */
export const WRAP_TYPE_PIN = 1;
export const WRAP_TYPE_RECOVERY = 2;

/**
 * Package version, reported by the backend's /api/vault/status so clients can
 * warn on drift. A canary, not a gate: a mismatch is logged, never enforced,
 * because a hard check would brick clients mid-rollout.
 */
export const VAULT_CORE_VERSION = '0.1.0';

/**
 * Bumped when normalizeSpecies() changes its output for any input. Stored
 * alongside aggregated counts so a normalization change can be detected and the
 * counts rebuilt rather than silently double-counting "Brown" and "brown trout"
 * as separate rows.
 */
export const SPECIES_NORMALIZATION_VERSION = 1;

/** Bumped when the cursor encoding changes. Decode rejects unknown versions. */
export const CURSOR_VERSION = 1;

/** Geohash precision for the plaintext coarse cell. 4 chars is roughly 20km. */
export const GEOHASH_PRECISION = 4;
