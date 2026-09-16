/**
 * Sealing and opening records.
 *
 * The construction is HPKE-shaped, NOT libsodium's crypto_box_seal. They look
 * alike and are not compatible: crypto_box_seal derives its nonce as
 * blake2b(epk || rpk) and takes no AAD at all. We need AAD to bind a record to
 * its row, so the key schedule is HKDF-based instead. See FORMAT.md.
 *
 * Sealing needs only the recipient's PUBLIC key, which is the property that lets
 * a phone log a catch while the vault is locked and offline.
 */

import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';

import {
  buildRecordHeader,
  parseRecordHeader,
  base64UrlEncode,
  base64UrlDecode,
  VaultFormatError,
  RECORD_HEADER_SIZE,
  MAX_RECORD_BYTES,
  EPK_SIZE,
} from '../envelope/format.js';
import { padPlaintext, unpadPlaintext } from '../envelope/pad.js';
import { encodePayload, decodePayload, type VaultPayload } from '../envelope/payload.js';
import { buildRecordAad, type RecordAadInput } from '../envelope/aad.js';
import { randomBytes } from './provider.js';
import { ENVELOPE_VERSION } from '../version.js';

/** Frozen. Changing either string changes every record. */
const INFO_KEY = 'wlv1-key';
const INFO_NONCE = 'wlv1-nonce';

const KEY_SIZE = 32;
const NONCE_SIZE = 24;

export type RecordBinding = Omit<RecordAadInput, 'header' | 'encVersion'> & {
  encVersion?: number;
};

export interface SealInput {
  payload: VaultPayload;
  recipientPublicKey: Uint8Array;
  binding: RecordBinding;
  /**
   * Fixed ephemeral secret, for deterministic test vectors ONLY. Supplying this
   * in production destroys the per-record nonce uniqueness that makes the
   * construction safe.
   */
  ephemeralSecret?: Uint8Array;
}

export interface OpenInput {
  blob: string | Uint8Array;
  secretKey: Uint8Array;
  binding: RecordBinding;
}

function deriveKeySchedule(
  shared: Uint8Array,
  epk: Uint8Array,
  recipientPublicKey: Uint8Array,
): { key: Uint8Array; nonce: Uint8Array } {
  // Salt binds the record to the intended recipient key. Without it a record
  // could be replayed against a different recipient.
  const salt = new Uint8Array(epk.length + recipientPublicKey.length);
  salt.set(epk, 0);
  salt.set(recipientPublicKey, epk.length);

  return {
    key: hkdf(sha256, shared, salt, INFO_KEY, KEY_SIZE),
    nonce: hkdf(sha256, shared, salt, INFO_NONCE, NONCE_SIZE),
  };
}

export function sealRecord(input: SealInput): string {
  const { recipientPublicKey } = input;
  if (recipientPublicKey.length !== EPK_SIZE) {
    throw new VaultFormatError(
      `recipient public key must be ${EPK_SIZE} bytes`,
      'VAULT_BAD_KEY',
    );
  }

  const esk = input.ephemeralSecret ?? randomBytes(32);
  const epk = x25519.getPublicKey(esk);
  const shared = x25519.getSharedSecret(esk, recipientPublicKey);

  const plaintext = encodePayload(input.payload);
  const padded = padPlaintext(plaintext);

  const header = buildRecordHeader({
    padded: padded.padded,
    padBucket: padded.padBucket,
    epk,
  });

  const aad = buildRecordAad({
    header,
    userId: input.binding.userId,
    table: input.binding.table,
    recordKey: input.binding.recordKey,
    fieldGroup: input.binding.fieldGroup,
    encVersion: input.binding.encVersion ?? ENVELOPE_VERSION,
  });

  const { key, nonce } = deriveKeySchedule(shared, epk, recipientPublicKey);
  const body = xchacha20poly1305(key, nonce, aad).encrypt(padded.bytes);

  const record = new Uint8Array(RECORD_HEADER_SIZE + body.length);
  record.set(header, 0);
  record.set(body, RECORD_HEADER_SIZE);

  if (record.length > MAX_RECORD_BYTES) {
    throw new VaultFormatError(
      `sealed record is ${record.length} bytes, over the ${MAX_RECORD_BYTES} limit`,
      'VAULT_TOO_LARGE',
    );
  }

  return base64UrlEncode(record);
}

export function openRecord(input: OpenInput): VaultPayload {
  const bytes =
    typeof input.blob === 'string' ? base64UrlDecode(input.blob) : input.blob;

  const header = parseRecordHeader(bytes);
  const body = bytes.subarray(header.bodyOffset);

  const shared = x25519.getSharedSecret(input.secretKey, header.epk);
  const recipientPublicKey = x25519.getPublicKey(input.secretKey);

  const aad = buildRecordAad({
    header: bytes,
    userId: input.binding.userId,
    table: input.binding.table,
    recordKey: input.binding.recordKey,
    fieldGroup: input.binding.fieldGroup,
    encVersion: input.binding.encVersion ?? header.version,
  });

  const { key, nonce } = deriveKeySchedule(shared, header.epk, recipientPublicKey);

  let padded: Uint8Array;
  try {
    padded = xchacha20poly1305(key, nonce, aad).decrypt(body);
  } catch {
    // A tag failure means one of: wrong key, tampered ciphertext, or a binding
    // that does not match the row. They are deliberately indistinguishable —
    // telling a caller which one would let them probe the binding.
    throw new VaultFormatError(
      'record failed authentication',
      'VAULT_AUTH_FAILED',
    );
  }

  return decodePayload(unpadPlaintext(padded, header.padBucket));
}
