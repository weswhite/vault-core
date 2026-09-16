/**
 * @waterlands/vault-core/testvectors
 *
 * The actual contract between the three platforms.
 *
 * Node, a browser worker running WASM, and Hermes must all produce identical
 * bytes. Unit tests written per repo cannot prove that — each one only shows
 * that a platform agrees with itself. These vectors are known-answer tests, so a
 * platform that drifts fails loudly instead of silently writing records the
 * other two cannot open.
 *
 * Every consuming repo runs this suite in CI against its own real provider.
 * Mobile must NOT mock the crypto away to make it pass: a mocked run verifies
 * nothing on the platform that most needs verifying.
 *
 * APPEND ONLY once a version ships. If a vector fails after a change, the change
 * is wrong. Never edit a released vector to make CI green — that is how a format
 * silently forks and users lose data.
 */

import {
  buildRecordAad,
  buildWrapAad,
  padPlaintext,
  unpadPlaintext,
  encodePayload,
  decodePayload,
  encodeCell,
  cellCentroid,
  normalizeSpecies,
  encodeCursor,
  decodeCursor,
  base64UrlEncode,
  base64UrlDecode,
  PAD_BUCKET_NONE,
} from './index.js';

import {
  sealRecord,
  openRecord,
  wrapDataKey,
  unwrapDataKey,
  vaultKeypairFromDataKey,
  fingerprintPublicKey,
  recoveryCodeToKey,
  normalizeRecoveryCode,
} from './crypto.js';

/** Minimal assertion surface, so this runs under vitest, jest, or bare node. */
export interface VectorAssert {
  equal(actual: unknown, expected: unknown, message: string): void;
  ok(value: unknown, message: string): void;
}

export interface VectorSuiteResult {
  passed: number;
  failed: number;
  failures: string[];
}

export interface VectorFile {
  version: number;
  generatedAt: string;
  geohash: Array<{ lat: number; lon: number; precision: number; cell: string }>;
  species: Array<{ input: string; output: string }>;
  cursor: Array<{ ts: number; id: string; encoded: string }>;
  pad: Array<{ plaintextHex: string; padBucket: number; paddedHex: string }>;
  payload: Array<{ payload: Record<string, unknown>; jsonBytesHex: string }>;
  aad: Array<{
    headerHex: string;
    userId: string;
    table: string;
    recordKey: string;
    fieldGroup: string;
    encVersion: number;
    aadHex: string;
  }>;
  keypair: Array<{ dataKeyHex: string; publicKeyHex: string; fingerprint: string }>;
  seal: Array<{
    dataKeyHex: string;
    ephemeralSecretHex: string;
    payload: Record<string, unknown>;
    userId: string;
    table: string;
    recordKey: string;
    fieldGroup: string;
    encVersion: number;
    blob: string;
  }>;
  wrap: Array<{
    dataKeyHex: string;
    secretUtf8: string;
    saltHex: string;
    nonceHex: string;
    memKiB: number;
    timeCost: number;
    lanes: number;
    userId: string;
    wrapType: number;
    keyVersion: number;
    vaultPubKeyFp: string;
    blob: string;
    /** Slow vectors use production Argon2 costs; skipped unless includeSlow. */
    slow?: boolean;
  }>;
  recovery: Array<{ raw: string; normalized: string; entropyHex: string }>;
}

export interface RunOptions {
  /** Run the production-cost Argon2 vectors. Off by default so CI stays fast. */
  includeSlow?: boolean;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error(`odd-length hex: ${hex.length}`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

/**
 * Runs every section. Returns counts rather than throwing on the first failure,
 * because when a platform drifts you want the whole picture, not the first
 * symptom.
 */
export function runVectorSuite(
  vectors: VectorFile,
  assert: VectorAssert,
  options: RunOptions = {},
): VectorSuiteResult {
  const result: VectorSuiteResult = { passed: 0, failed: 0, failures: [] };

  const check = (label: string, fn: () => void): void => {
    try {
      fn();
      result.passed++;
    } catch (err) {
      result.failed++;
      result.failures.push(`${label}: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  for (const v of vectors.geohash) {
    check(`geohash ${v.lat},${v.lon}@${v.precision}`, () => {
      assert.equal(encodeCell(v.lat, v.lon, v.precision), v.cell, 'cell');
      const c = cellCentroid(v.cell);
      assert.ok(
        Math.abs(c.lat) <= 90 && Math.abs(c.lon) <= 180,
        'centroid in range',
      );
    });
  }

  for (const v of vectors.species) {
    check(`species "${v.input}"`, () => {
      const out = normalizeSpecies(v.input);
      assert.equal(out, v.output, 'normalized');
      assert.equal(normalizeSpecies(out), out, 'idempotent');
    });
  }

  for (const v of vectors.cursor) {
    check(`cursor ${v.id}`, () => {
      assert.equal(encodeCursor({ ts: v.ts, id: v.id }), v.encoded, 'encoded');
      const back = decodeCursor(v.encoded);
      assert.equal(back.ts, v.ts, 'ts round-trip');
      assert.equal(back.id, v.id, 'id round-trip');
    });
  }

  for (const v of vectors.pad) {
    check(`pad ${v.plaintextHex.length / 2}B`, () => {
      const padded = padPlaintext(hexToBytes(v.plaintextHex));
      assert.equal(padded.padBucket, v.padBucket, 'bucket');
      assert.equal(bytesToHex(padded.bytes), v.paddedHex, 'padded bytes');
      const back = unpadPlaintext(padded.bytes, padded.padBucket);
      assert.equal(bytesToHex(back), v.plaintextHex, 'unpad round-trip');
    });
  }

  for (const v of vectors.payload) {
    check(`payload ${JSON.stringify(v.payload)}`, () => {
      const bytes = encodePayload(v.payload as never);
      assert.equal(bytesToHex(bytes), v.jsonBytesHex, 'encoded');
      assert.equal(
        JSON.stringify(decodePayload(bytes)),
        JSON.stringify(v.payload),
        'round-trip',
      );
    });
  }

  for (const v of vectors.aad) {
    check(`aad ${v.table}/${v.recordKey}`, () => {
      const aad = buildRecordAad({
        header: hexToBytes(v.headerHex),
        userId: v.userId,
        table: v.table,
        recordKey: v.recordKey,
        fieldGroup: v.fieldGroup,
        encVersion: v.encVersion,
      });
      assert.equal(bytesToHex(aad), v.aadHex, 'aad bytes');
    });
  }

  for (const v of vectors.keypair) {
    check(`keypair ${v.fingerprint.substring(0, 8)}`, () => {
      const kp = vaultKeypairFromDataKey(hexToBytes(v.dataKeyHex));
      assert.equal(bytesToHex(kp.publicKey), v.publicKeyHex, 'public key');
      assert.equal(fingerprintPublicKey(kp.publicKey), v.fingerprint, 'fingerprint');
    });
  }

  for (const v of vectors.seal) {
    check(`seal ${v.table}/${v.recordKey}`, () => {
      const kp = vaultKeypairFromDataKey(hexToBytes(v.dataKeyHex));
      const binding = {
        userId: v.userId,
        table: v.table,
        recordKey: v.recordKey,
        fieldGroup: v.fieldGroup,
        encVersion: v.encVersion,
      };
      const blob = sealRecord({
        payload: v.payload as never,
        recipientPublicKey: kp.publicKey,
        binding,
        ephemeralSecret: hexToBytes(v.ephemeralSecretHex),
      });
      assert.equal(blob, v.blob, 'sealed blob');

      const opened = openRecord({ blob: v.blob, secretKey: kp.secretKey, binding });
      assert.equal(JSON.stringify(opened), JSON.stringify(v.payload), 'opened payload');

      // Wrong binding must fail. This is the property that stops a blob being
      // moved between rows, so it is worth asserting on every vector.
      let rejected = false;
      try {
        openRecord({
          blob: v.blob,
          secretKey: kp.secretKey,
          binding: { ...binding, recordKey: binding.recordKey + 'x' },
        });
      } catch {
        rejected = true;
      }
      assert.ok(rejected, 'wrong recordKey rejected');
    });
  }

  for (const v of vectors.wrap) {
    if (v.slow && !options.includeSlow) continue;
    check(`wrap type=${v.wrapType} m=${v.memKiB}`, () => {
      const binding = {
        userId: v.userId,
        wrapType: v.wrapType,
        keyVersion: v.keyVersion,
        vaultPubKeyFp: v.vaultPubKeyFp,
      };
      const secret = new TextEncoder().encode(v.secretUtf8);
      const blob = wrapDataKey({
        dataKey: hexToBytes(v.dataKeyHex),
        secret,
        binding,
        params: { memKiB: v.memKiB, timeCost: v.timeCost, lanes: v.lanes },
        salt: hexToBytes(v.saltHex),
        nonce: hexToBytes(v.nonceHex),
      });
      assert.equal(blob, v.blob, 'wrap blob');
      assert.equal(
        bytesToHex(unwrapDataKey({ blob: v.blob, secret, binding })),
        v.dataKeyHex,
        'unwrapped data key',
      );
    });
  }

  for (const v of vectors.recovery) {
    check(`recovery "${v.raw.substring(0, 24)}"`, () => {
      assert.equal(normalizeRecoveryCode(v.raw), v.normalized, 'normalized');
      assert.equal(bytesToHex(recoveryCodeToKey(v.raw)), v.entropyHex, 'entropy');
    });
  }

  check('base64url round-trip', () => {
    for (let len = 0; len <= 8; len++) {
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) bytes[i] = (i * 37 + 11) & 0xff;
      assert.equal(
        bytesToHex(base64UrlDecode(base64UrlEncode(bytes))),
        bytesToHex(bytes),
        `len ${len}`,
      );
    }
  });

  check('oversized payload is written unpadded', () => {
    const big = new Uint8Array(5000);
    const padded = padPlaintext(big);
    assert.equal(padded.padded, false, 'not padded');
    assert.equal(padded.padBucket, PAD_BUCKET_NONE, 'bucket none');
  });

  return result;
}
