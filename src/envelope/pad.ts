/**
 * Length padding.
 *
 * Ciphertext length leaks plaintext length. Across a whole log that is enough to
 * identify the species without decrypting anything: "Brown trout" and
 * "Cutthroat" produce different sizes, and the distribution of sizes over a few
 * hundred catches gives the vocabulary away.
 *
 * So every payload is length-prefixed and zero-filled to a fixed bucket.
 */

import { VaultFormatError, PAD_BUCKET_NONE } from './format.js';

/** Frozen for v1. Changing these changes the output bytes. */
export const PAD_BUCKETS: readonly number[] = [64, 128, 256, 512, 1024, 2048, 4096];

const LENGTH_PREFIX_SIZE = 2;

export interface PaddedPlaintext {
  bytes: Uint8Array;
  /** Index into PAD_BUCKETS, or PAD_BUCKET_NONE when the payload was too large. */
  padBucket: number;
  padded: boolean;
}

/**
 * A payload larger than the biggest bucket is written unpadded rather than
 * truncated. A note that long is already unusual enough to stand out, and
 * silently losing user data is worse than leaking that one record is big.
 */
export function padPlaintext(plaintext: Uint8Array): PaddedPlaintext {
  const needed = LENGTH_PREFIX_SIZE + plaintext.length;

  let bucketIndex = -1;
  for (let i = 0; i < PAD_BUCKETS.length; i++) {
    if (PAD_BUCKETS[i] >= needed) {
      bucketIndex = i;
      break;
    }
  }

  if (bucketIndex === -1) {
    return { bytes: plaintext, padBucket: PAD_BUCKET_NONE, padded: false };
  }

  // uint16BE can address 65535, and the largest bucket is 4096, so the prefix
  // can always represent the length. If a bucket above 65537 is ever added,
  // this assumption needs revisiting along with a new envelope version.
  const size = PAD_BUCKETS[bucketIndex];
  const out = new Uint8Array(size);
  out[0] = (plaintext.length >> 8) & 0xff;
  out[1] = plaintext.length & 0xff;
  out.set(plaintext, LENGTH_PREFIX_SIZE);
  return { bytes: out, padBucket: bucketIndex, padded: true };
}

/**
 * Reverses padPlaintext.
 *
 * The zero-fill is verified rather than ignored. The AEAD tag already makes
 * tampering detectable, so this is belt and braces — but it also catches an
 * encoder on another platform writing garbage into the tail, which is exactly
 * the class of cross-platform bug this package exists to prevent.
 */
export function unpadPlaintext(padded: Uint8Array, padBucket: number): Uint8Array {
  if (padBucket === PAD_BUCKET_NONE) return padded;

  if (padBucket < 0 || padBucket >= PAD_BUCKETS.length) {
    throw new VaultFormatError(`unknown pad bucket ${padBucket}`, 'VAULT_BAD_PADDING');
  }

  const expectedSize = PAD_BUCKETS[padBucket];
  if (padded.length !== expectedSize) {
    throw new VaultFormatError(
      `padded length ${padded.length} does not match bucket ${padBucket} (${expectedSize})`,
      'VAULT_BAD_PADDING',
    );
  }

  const length = (padded[0] << 8) | padded[1];
  if (LENGTH_PREFIX_SIZE + length > expectedSize) {
    throw new VaultFormatError(
      `declared length ${length} overflows bucket ${expectedSize}`,
      'VAULT_BAD_PADDING',
    );
  }

  for (let i = LENGTH_PREFIX_SIZE + length; i < expectedSize; i++) {
    if (padded[i] !== 0) {
      throw new VaultFormatError('non-zero byte in padding', 'VAULT_BAD_PADDING');
    }
  }

  return padded.subarray(LENGTH_PREFIX_SIZE, LENGTH_PREFIX_SIZE + length);
}
