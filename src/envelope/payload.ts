/**
 * The plaintext payload, before sealing.
 *
 * Short keys and a fixed key order, for two reasons. Small records keep the
 * padding buckets meaningful, and deterministic serialisation means the same
 * input produces the same bytes on all three platforms — which is what makes
 * the test vectors able to catch drift.
 *
 * JSON.stringify with an explicit key order is used rather than object literal
 * order, because object key order is an engine detail and Hermes, V8 and
 * JavaScriptCore have no obligation to agree on it.
 */

import { VaultFormatError } from './format.js';

/**
 * Wire keys. These are frozen: renaming one is a new envelope version, because
 * an old client opening a new record would silently read undefined and render a
 * catch with no species rather than failing.
 */
export const PAYLOAD_KEYS = {
  lat: 'lat',
  lng: 'lng',
  species: 'sp',
  name: 'nm',
  description: 'ds',
  notes: 'nt',
  customLocationName: 'cln',
} as const;

/** Serialisation order. Frozen. */
const KEY_ORDER: readonly string[] = ['lat', 'lng', 'sp', 'nm', 'ds', 'nt', 'cln'];

export interface VaultPayload {
  lat?: number;
  lng?: number;
  /** species */
  sp?: string;
  /** name (Spot) */
  nm?: string;
  /** description (Spot) */
  ds?: string;
  /** notes */
  nt?: string;
  /** customLocationName (FishingSession) */
  cln?: string;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

/**
 * Absent fields are omitted rather than written as null, because a record only
 * carries the field groups the user chose to encrypt. An explicit null would be
 * indistinguishable from "the user cleared this value".
 */
export function encodePayload(payload: VaultPayload): Uint8Array {
  const parts: string[] = [];

  for (let i = 0; i < KEY_ORDER.length; i++) {
    const key = KEY_ORDER[i];
    const value = (payload as Record<string, unknown>)[key];
    if (value === undefined || value === null) continue;

    if (key === 'lat' || key === 'lng') {
      if (typeof value !== 'number' || !Number.isFinite(value)) {
        throw new VaultFormatError(`${key} must be a finite number`, 'VAULT_BAD_PAYLOAD');
      }
    } else if (typeof value !== 'string') {
      throw new VaultFormatError(`${key} must be a string`, 'VAULT_BAD_PAYLOAD');
    }

    parts.push(JSON.stringify(key) + ':' + JSON.stringify(value));
  }

  return encoder.encode('{' + parts.join(',') + '}');
}

export function decodePayload(bytes: Uint8Array): VaultPayload {
  let text: string;
  try {
    text = decoder.decode(bytes);
  } catch {
    // Reached only if the tag verified and the bytes still are not UTF-8, which
    // means an encoder on some platform is producing garbage. Worth a distinct
    // error rather than a generic JSON failure.
    throw new VaultFormatError('payload is not valid UTF-8', 'VAULT_BAD_PAYLOAD');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new VaultFormatError('payload is not valid JSON', 'VAULT_BAD_PAYLOAD');
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new VaultFormatError('payload must be a JSON object', 'VAULT_BAD_PAYLOAD');
  }

  // Unknown keys are ignored rather than rejected. A future version may add a
  // field, and an older client should still be able to read the fields it knows
  // rather than refusing the whole record.
  const source = parsed as Record<string, unknown>;
  const out: VaultPayload = {};

  for (let i = 0; i < KEY_ORDER.length; i++) {
    const key = KEY_ORDER[i];
    const value = source[key];
    if (value === undefined || value === null) continue;

    if (key === 'lat' || key === 'lng') {
      if (typeof value !== 'number' || !Number.isFinite(value)) {
        throw new VaultFormatError(`${key} must be a finite number`, 'VAULT_BAD_PAYLOAD');
      }
      (out as Record<string, unknown>)[key] = value;
    } else {
      if (typeof value !== 'string') {
        throw new VaultFormatError(`${key} must be a string`, 'VAULT_BAD_PAYLOAD');
      }
      (out as Record<string, unknown>)[key] = value;
    }
  }

  return out;
}
