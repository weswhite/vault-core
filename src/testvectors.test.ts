/**
 * Runs the conformance vectors against this platform (Node).
 *
 * The same suite runs in the backend, the web app and the mobile app, each
 * against its own real provider. This copy is the baseline the others are
 * compared to, so a failure here means the format changed rather than that one
 * platform drifted.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { runVectorSuite, type VectorFile, type VectorAssert } from './testvectors.js';
import { sealRecord, openRecord, generateDataKey, vaultKeypairFromDataKey } from './crypto.js';

const vectors = JSON.parse(
  readFileSync(resolve(__dirname, '..', 'testvectors', 'v1.json'), 'utf8'),
) as VectorFile;

const assert: VectorAssert = {
  equal(actual, expected, message) {
    expect(actual, message).toEqual(expected);
  },
  ok(value, message) {
    expect(value, message).toBeTruthy();
  },
};

describe('v1 conformance vectors', () => {
  it('passes every vector', () => {
    const result = runVectorSuite(vectors, assert);
    expect(result.failures).toEqual([]);
    expect(result.failed).toBe(0);
    expect(result.passed).toBeGreaterThan(0);
  });

  it('covers every section', () => {
    // A section silently emptied would make the suite pass while testing nothing.
    expect(vectors.geohash.length).toBeGreaterThan(0);
    expect(vectors.species.length).toBeGreaterThan(0);
    expect(vectors.cursor.length).toBeGreaterThan(0);
    expect(vectors.pad.length).toBeGreaterThan(0);
    expect(vectors.payload.length).toBeGreaterThan(0);
    expect(vectors.aad.length).toBeGreaterThan(0);
    expect(vectors.keypair.length).toBeGreaterThan(0);
    expect(vectors.seal.length).toBeGreaterThan(0);
    expect(vectors.wrap.length).toBeGreaterThan(0);
    expect(vectors.recovery.length).toBeGreaterThan(0);
  });
});

describe('seal and open', () => {
  const dataKey = generateDataKey();
  const { publicKey, secretKey } = vaultKeypairFromDataKey(dataKey);
  const binding = {
    userId: 'usr_1',
    table: 'FishCatch',
    recordKey: 'cat_1',
    fieldGroup: 'all',
  };

  it('round-trips a payload', () => {
    const payload = { lat: 45.6789, lng: -111.0429, sp: 'Brown trout' };
    const blob = sealRecord({ payload, recipientPublicKey: publicKey, binding });
    expect(openRecord({ blob, secretKey, binding })).toEqual(payload);
  });

  it('produces different ciphertext for the same input', () => {
    // The ephemeral keypair is fresh per record, which is what makes nonce
    // reuse impossible. Identical blobs would mean it is not.
    const payload = { sp: 'Cutthroat' };
    const a = sealRecord({ payload, recipientPublicKey: publicKey, binding });
    const b = sealRecord({ payload, recipientPublicKey: publicKey, binding });
    expect(a).not.toEqual(b);
    expect(openRecord({ blob: a, secretKey, binding })).toEqual(payload);
    expect(openRecord({ blob: b, secretKey, binding })).toEqual(payload);
  });

  it('hides plaintext length within a bucket', () => {
    // Two species of very different length must seal to the same size, or the
    // ciphertext length gives the species away without any decryption.
    const short = sealRecord({
      payload: { sp: 'Ide' },
      recipientPublicKey: publicKey,
      binding,
    });
    const long = sealRecord({
      payload: { sp: 'Yellowstone cutthroat trout' },
      recipientPublicKey: publicKey,
      binding,
    });
    expect(short.length).toBe(long.length);
  });

  const rebindings: Array<[string, Record<string, string>]> = [
    ['userId', { userId: 'usr_2' }],
    ['table', { table: 'Spot' }],
    ['recordKey', { recordKey: 'cat_2' }],
    ['fieldGroup', { fieldGroup: 'loc' }],
  ];

  it.each(rebindings)('refuses to open with a different %s', (_label, override) => {
    const blob = sealRecord({
      payload: { sp: 'Brown trout' },
      recipientPublicKey: publicKey,
      binding,
    });
    expect(() =>
      openRecord({ blob, secretKey, binding: { ...binding, ...override } }),
    ).toThrow();
  });

  it('refuses to open with the wrong key', () => {
    const blob = sealRecord({
      payload: { sp: 'Brown trout' },
      recipientPublicKey: publicKey,
      binding,
    });
    const other = vaultKeypairFromDataKey(generateDataKey());
    expect(() => openRecord({ blob, secretKey: other.secretKey, binding })).toThrow();
  });

  it('refuses a tampered blob', () => {
    const blob = sealRecord({
      payload: { sp: 'Brown trout' },
      recipientPublicKey: publicKey,
      binding,
    });
    // Flip a character in the ciphertext body, past the 40-byte header.
    const chars = blob.split('');
    const i = chars.length - 5;
    chars[i] = chars[i] === 'A' ? 'B' : 'A';
    expect(() => openRecord({ blob: chars.join(''), secretKey, binding })).toThrow();
  });
});
