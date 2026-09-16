/**
 * Injectable providers.
 *
 * Two things differ per platform and neither can be hardcoded.
 *
 * Argon2id: React Native on Hermes has no WebCrypto and no native Argon2. A
 * pure-JS implementation at realistic memory cost takes multiple seconds on a
 * mid-range Android, and the vault unlocks on every view. Mobile therefore ships
 * a native binding and injects it here. The default is a pure-JS implementation
 * so Node and the browser work with no setup.
 *
 * Randomness: the sole CSPRNG. Never reach for Math.random, and never add a
 * second source — the mobile app already has a `joinCodeGenerator` that falls
 * back to Math.random because nothing installs `global.crypto`, and a vault must
 * not inherit that ambiguity.
 */

import { argon2id as nobleArgon2id } from '@noble/hashes/argon2';
import { randomBytes as nobleRandomBytes } from '@noble/hashes/utils';

export interface Argon2Params {
  /** Memory cost in KiB. */
  memKiB: number;
  /** Iterations. */
  timeCost: number;
  /** Parallelism. */
  lanes: number;
}

export interface Argon2Provider {
  /** Must return exactly `length` bytes of Argon2id output. */
  hash(
    password: Uint8Array,
    salt: Uint8Array,
    params: Argon2Params,
    length: number,
  ): Uint8Array;
}

export interface RandomProvider {
  bytes(length: number): Uint8Array;
}

/**
 * Interactive profile. Chosen for the WEAKEST platform that must open a vault,
 * not the strongest that creates one — a user enrolling on a fast laptop must
 * still be able to unlock on an old phone.
 *
 * These values are written into every wrap blob, so they are a default for new
 * enrollments rather than a global constant. Raising them later affects only
 * vaults created afterwards; existing wraps keep their own parameters and keep
 * opening.
 */
export const ARGON2_INTERACTIVE: Argon2Params = {
  memKiB: 65536,
  timeCost: 3,
  lanes: 1,
};

/**
 * Deliberately cheap. For test vectors and fixtures ONLY, so CI does not spend
 * a minute per run deriving keys. Never use for a real vault.
 */
export const ARGON2_TEST_ONLY: Argon2Params = {
  memKiB: 8192,
  timeCost: 1,
  lanes: 1,
};

const defaultArgon2: Argon2Provider = {
  hash(password, salt, params, length) {
    return nobleArgon2id(password, salt, {
      t: params.timeCost,
      m: params.memKiB,
      p: params.lanes,
      dkLen: length,
    });
  },
};

const defaultRandom: RandomProvider = {
  bytes(length) {
    return nobleRandomBytes(length);
  },
};

let argon2Provider: Argon2Provider = defaultArgon2;
let randomProvider: RandomProvider = defaultRandom;

/** Mobile calls this once at boot with its native binding. */
export function setArgon2Provider(provider: Argon2Provider): void {
  argon2Provider = provider;
}

export function setRandomProvider(provider: RandomProvider): void {
  randomProvider = provider;
}

/** Restores the pure-JS defaults. Used by tests. */
export function resetProviders(): void {
  argon2Provider = defaultArgon2;
  randomProvider = defaultRandom;
}

export function argon2idHash(
  password: Uint8Array,
  salt: Uint8Array,
  params: Argon2Params,
  length: number,
): Uint8Array {
  const out = argon2Provider.hash(password, salt, params, length);
  if (out.length !== length) {
    // A native binding returning the wrong length would otherwise produce a key
    // that silently differs from every other platform's.
    throw new Error(
      `Argon2 provider returned ${out.length} bytes, expected ${length}`,
    );
  }
  return out;
}

export function randomBytes(length: number): Uint8Array {
  const out = randomProvider.bytes(length);
  if (out.length !== length) {
    throw new Error(`Random provider returned ${out.length} bytes, expected ${length}`);
  }
  return out;
}
