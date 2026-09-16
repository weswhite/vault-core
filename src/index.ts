/**
 * @waterlands/vault-core
 *
 * The pure entry point: format, AAD, padding, geohash, species normalization,
 * cursors and placeholder constants. No crypto, no WASM, no native bindings.
 *
 * This split is load-bearing, not tidiness. The backend and the web server
 * render both legitimately need the geohash and cursor helpers. If they could
 * only reach them by importing the package root, a single `.server.ts` import
 * would drag a WASM crypto module into the SSR bundle, which is the most likely
 * way this feature breaks in production. Crypto lives behind
 * `@waterlands/vault-core/crypto` and nothing here imports it.
 */

export {
  ENVELOPE_VERSION,
  SUPPORTED_ENVELOPE_VERSIONS,
  WRAP_VERSION,
  SUPPORTED_WRAP_VERSIONS,
  SUITE_X25519_HKDF_XCHACHA20,
  KDF_ARGON2ID,
  WRAP_TYPE_PIN,
  WRAP_TYPE_RECOVERY,
  VAULT_CORE_VERSION,
  SPECIES_NORMALIZATION_VERSION,
  CURSOR_VERSION,
  GEOHASH_PRECISION,
} from './version.js';

export {
  RECORD_MAGIC,
  RECORD_HEADER_SIZE,
  EPK_SIZE,
  TAG_SIZE,
  MIN_RECORD_SIZE,
  MAX_RECORD_BYTES,
  FLAG_PADDED,
  PAD_BUCKET_NONE,
  VaultFormatError,
  isVaultBlob,
  parseRecordHeader,
  validateRecordShape,
  buildRecordHeader,
  base64UrlEncode,
  base64UrlDecode,
  isBase64Url,
} from './envelope/format.js';

export type {
  RecordHeader,
  BuildHeaderInput,
  ValidateOptions,
  ValidationResult,
} from './envelope/format.js';

export {
  FIELD_GROUPS,
  SEALABLE_TABLES,
  buildRecordAad,
  buildWrapAad,
} from './envelope/aad.js';

export type {
  FieldGroup,
  SealableTable,
  RecordAadInput,
  WrapAadInput,
} from './envelope/aad.js';

export { PAD_BUCKETS, padPlaintext, unpadPlaintext } from './envelope/pad.js';
export type { PaddedPlaintext } from './envelope/pad.js';

export { PAYLOAD_KEYS, encodePayload, decodePayload } from './envelope/payload.js';
export type { VaultPayload } from './envelope/payload.js';

export { encodeCell, cellCentroid, cellBounds } from './geo/geohash.js';

export { normalizeSpecies } from './species/normalize.js';

export { encodeCursor, decodeCursor } from './cursor/cursor.js';

export {
  PLACEHOLDER_SPOT_NAME,
  PLACEHOLDER_SPECIES,
  LOC_PRECISION,
  isCoarseLocation,
} from './constants.js';

export type { LocPrecision } from './constants.js';
