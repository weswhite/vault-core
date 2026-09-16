/**
 * Data key, and the X25519 keypair derived from it.
 *
 * The keypair is DERIVED from the data key rather than generated separately and
 * stored under its own wrap. That choice is load-bearing: a user who has lost
 * their phone holds only the recovery code, which unwraps the data key. If the
 * private key were stored separately, they would recover the data key and still
 * be unable to open a single record — the recovery code would be worthless at
 * exactly the moment it is supposed to save them.
 */

import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { randomBytes } from './provider.js';
import { base64UrlEncode } from '../envelope/format.js';

export const DATA_KEY_SIZE = 32;

/** Frozen. Changing this string changes every derived keypair. */
const X25519_DERIVE_INFO = 'wlv1-x25519-v1';

export interface VaultKeypair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

export function generateDataKey(): Uint8Array {
  return randomBytes(DATA_KEY_SIZE);
}

/**
 * Standard X25519 clamping. Applied to the HKDF output so the derived scalar is
 * a valid secret key: clear the low three bits, clear the top bit, set the
 * second-highest.
 */
function clamp(scalar: Uint8Array): Uint8Array {
  const out = scalar.slice();
  out[0] &= 248;
  out[31] &= 127;
  out[31] |= 64;
  return out;
}

export function vaultKeypairFromDataKey(dataKey: Uint8Array): VaultKeypair {
  if (dataKey.length !== DATA_KEY_SIZE) {
    throw new Error(`data key must be ${DATA_KEY_SIZE} bytes, got ${dataKey.length}`);
  }
  const derived = hkdf(sha256, dataKey, undefined, X25519_DERIVE_INFO, 32);
  const secretKey = clamp(derived);
  const publicKey = x25519.getPublicKey(secretKey);
  return { secretKey, publicKey };
}

/**
 * base64url SHA-256 of the public key.
 *
 * The client pins this at enrollment and re-checks it on every status fetch. It
 * is also bound into the wrap AAD, which is what makes a server key substitution
 * detectable on a fresh device where there is no local pin to compare against.
 */
export function fingerprintPublicKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error(`public key must be 32 bytes, got ${publicKey.length}`);
  }
  return base64UrlEncode(sha256(publicKey));
}

/**
 * Constant-time comparison, for fingerprints and tags.
 *
 * The length check short-circuits and so is not constant time, which is fine:
 * the length of a fingerprint is not secret.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Best-effort erase.
 *
 * Overwrites the buffer in place. This genuinely helps for a Uint8Array, and it
 * is why key material is never held in a JS string: strings are immutable, so a
 * key that becomes a string stays in memory until the engine feels like
 * collecting it, and cannot be wiped.
 */
export function wipe(bytes: Uint8Array): void {
  bytes.fill(0);
}
