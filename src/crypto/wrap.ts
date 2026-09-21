/**
 * Wrapping the data key under a human secret.
 *
 * Two wraps exist per user. The PIN wrap never leaves the device. The recovery
 * wrap is the only one stored server-side, and it is the only path back in after
 * a lost phone.
 *
 * Argon2 parameters are written INTO the blob rather than read from a constant.
 * A low-end Android and a browser running WASM cannot afford the same cost, and
 * a user who enrolls on a weak device must still be able to open their vault on
 * a strong one. Reading the parameters from the blob is what makes that work,
 * and it also means costs can be raised for new enrollments without invalidating
 * existing vaults.
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha';

import {
  base64UrlEncode,
  base64UrlDecode,
  VaultFormatError,
} from '../envelope/format.js';
import { buildWrapAad } from '../envelope/aad.js';
import {
  argon2idHash,
  randomBytes,
  type Argon2Params,
  ARGON2_INTERACTIVE,
} from './provider.js';
import { DATA_KEY_SIZE } from './keys.js';
import {
  WRAP_VERSION,
  SUPPORTED_WRAP_VERSIONS,
  KDF_ARGON2ID,
  WRAP_TYPE_PIN,
} from '../version.js';

/** "WLW1" */
const WRAP_MAGIC = new Uint8Array([0x57, 0x4c, 0x57, 0x31]);

const WRAP_HEADER_SIZE = 56;
const SALT_SIZE = 16;
const NONCE_SIZE = 24;
const TAG_SIZE = 16;
const WRAP_TOTAL_SIZE = WRAP_HEADER_SIZE + DATA_KEY_SIZE + TAG_SIZE;

export interface WrapBinding {
  userId: string;
  wrapType: number;
  keyVersion: number;
  vaultPubKeyFp: string;
}

export interface WrapInput {
  dataKey: Uint8Array;
  /** UTF-8 bytes of the PIN, passphrase, or normalized recovery code. */
  secret: Uint8Array;
  binding: WrapBinding;
  params?: Argon2Params;
  /** Fixed salt and nonce, for deterministic test vectors ONLY. */
  salt?: Uint8Array;
  nonce?: Uint8Array;
}

export interface UnwrapInput {
  blob: string | Uint8Array;
  secret: Uint8Array;
  binding: WrapBinding;
}

export interface WrapHeader {
  version: number;
  kdf: number;
  wrapType: number;
  params: Argon2Params;
  salt: Uint8Array;
  nonce: Uint8Array;
}

function buildWrapHeader(
  wrapType: number,
  params: Argon2Params,
  salt: Uint8Array,
  nonce: Uint8Array,
): Uint8Array {
  const header = new Uint8Array(WRAP_HEADER_SIZE);
  header.set(WRAP_MAGIC, 0);
  header[4] = WRAP_VERSION;
  header[5] = KDF_ARGON2ID;
  header[6] = wrapType;
  header[7] = 0;
  header[8] = (params.memKiB >>> 24) & 0xff;
  header[9] = (params.memKiB >>> 16) & 0xff;
  header[10] = (params.memKiB >>> 8) & 0xff;
  header[11] = params.memKiB & 0xff;
  header[12] = params.timeCost;
  header[13] = params.lanes;
  header[14] = 0;
  header[15] = 0;
  header.set(salt, 16);
  header.set(nonce, 32);
  return header;
}

export function parseWrapHeader(bytes: Uint8Array): WrapHeader {
  if (bytes.length !== WRAP_TOTAL_SIZE) {
    throw new VaultFormatError(
      `wrap must be ${WRAP_TOTAL_SIZE} bytes, got ${bytes.length}`,
      'VAULT_BAD_WRAP',
    );
  }
  for (let i = 0; i < WRAP_MAGIC.length; i++) {
    if (bytes[i] !== WRAP_MAGIC[i]) {
      throw new VaultFormatError('bad magic, not a WLW wrap', 'VAULT_BAD_WRAP');
    }
  }

  const version = bytes[4];
  if (SUPPORTED_WRAP_VERSIONS.indexOf(version) === -1) {
    throw new VaultFormatError(
      `unsupported wrap version ${version}`,
      'VAULT_UNSUPPORTED_VERSION',
    );
  }

  const kdf = bytes[5];
  if (kdf !== KDF_ARGON2ID) {
    throw new VaultFormatError(`unsupported kdf ${kdf}`, 'VAULT_UNSUPPORTED_KDF');
  }

  const memKiB =
    ((bytes[8] << 24) | (bytes[9] << 16) | (bytes[10] << 8) | bytes[11]) >>> 0;
  const timeCost = bytes[12];
  const lanes = bytes[13];

  const wrapType = bytes[6];

  /*
   * A hostile or corrupt blob could otherwise ask a phone to allocate gigabytes
   * and hang, or name a cost so small that a guessable secret becomes cheap to
   * attack. The floor therefore depends on what the wrap protects, because that
   * is what the cost is for:
   *
   *   PIN       ~20 bits, guessable. Cost is the only thing standing in the
   *             way, so a cheap PIN wrap is refused outright.
   *   RECOVERY  24 words, 256 bits. Guessing is impossible at any cost, and the
   *             floor only has to catch nonsense.
   *
   * A single floor could not say that, and the one that was here (1 MiB for
   * everything) took five minutes on a mid-range Android for the wrap that
   * needed it least. See ARGON2_RECOVERY for those measurements.
   */
  const floorKiB = wrapType === WRAP_TYPE_PIN ? 8192 : 64;
  if (memKiB < floorKiB || memKiB > 1048576) {
    throw new VaultFormatError(`implausible Argon2 memory ${memKiB} KiB`, 'VAULT_BAD_WRAP');
  }
  if (timeCost < 1 || lanes < 1) {
    throw new VaultFormatError('Argon2 cost must be at least 1', 'VAULT_BAD_WRAP');
  }

  return {
    version,
    kdf,
    wrapType,
    params: { memKiB, timeCost, lanes },
    salt: bytes.subarray(16, 16 + SALT_SIZE),
    nonce: bytes.subarray(32, 32 + NONCE_SIZE),
  };
}

export function wrapDataKey(input: WrapInput): string {
  if (input.dataKey.length !== DATA_KEY_SIZE) {
    throw new VaultFormatError(
      `data key must be ${DATA_KEY_SIZE} bytes`,
      'VAULT_BAD_KEY',
    );
  }
  if (input.secret.length === 0) {
    throw new VaultFormatError('secret must not be empty', 'VAULT_BAD_SECRET');
  }

  const params = input.params ?? ARGON2_INTERACTIVE;
  const salt = input.salt ?? randomBytes(SALT_SIZE);
  const nonce = input.nonce ?? randomBytes(NONCE_SIZE);

  if (salt.length !== SALT_SIZE) {
    throw new VaultFormatError(`salt must be ${SALT_SIZE} bytes`, 'VAULT_BAD_WRAP');
  }
  if (nonce.length !== NONCE_SIZE) {
    throw new VaultFormatError(`nonce must be ${NONCE_SIZE} bytes`, 'VAULT_BAD_WRAP');
  }

  const header = buildWrapHeader(input.binding.wrapType, params, salt, nonce);
  const aad = buildWrapAad({
    header,
    userId: input.binding.userId,
    wrapType: input.binding.wrapType,
    keyVersion: input.binding.keyVersion,
    vaultPubKeyFp: input.binding.vaultPubKeyFp,
  });

  const kek = argon2idHash(input.secret, salt, params, 32);
  const body = xchacha20poly1305(kek, nonce, aad).encrypt(input.dataKey);
  kek.fill(0);

  const blob = new Uint8Array(WRAP_TOTAL_SIZE);
  blob.set(header, 0);
  blob.set(body, WRAP_HEADER_SIZE);
  return base64UrlEncode(blob);
}

export function unwrapDataKey(input: UnwrapInput): Uint8Array {
  const bytes =
    typeof input.blob === 'string' ? base64UrlDecode(input.blob) : input.blob;

  const header = parseWrapHeader(bytes);
  const body = bytes.subarray(WRAP_HEADER_SIZE);

  const aad = buildWrapAad({
    header: bytes,
    userId: input.binding.userId,
    wrapType: input.binding.wrapType,
    keyVersion: input.binding.keyVersion,
    vaultPubKeyFp: input.binding.vaultPubKeyFp,
  });

  const kek = argon2idHash(input.secret, header.salt, header.params, 32);

  let dataKey: Uint8Array;
  try {
    dataKey = xchacha20poly1305(kek, header.nonce, aad).decrypt(body);
  } catch {
    // Wrong PIN, wrong recovery code, or a substituted public key. Deliberately
    // one error: distinguishing them would tell an attacker which half they got
    // right.
    throw new VaultFormatError('wrap failed authentication', 'VAULT_AUTH_FAILED');
  } finally {
    kek.fill(0);
  }

  if (dataKey.length !== DATA_KEY_SIZE) {
    throw new VaultFormatError('wrap contained a malformed data key', 'VAULT_BAD_KEY');
  }
  return dataKey;
}
