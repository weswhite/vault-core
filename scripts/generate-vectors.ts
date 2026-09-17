/**
 * Generates testvectors/v1.json.
 *
 * Run once when a version is first defined, then never again for that version.
 * The output is APPEND-ONLY: if a future change makes these vectors fail, the
 * change is wrong, not the vectors. Regenerating v1 to make CI green silently
 * forks the format and makes existing user records unopenable.
 *
 *   npx tsx scripts/generate-vectors.ts
 *
 * Every input here is a fixed constant, never random, so the output is
 * reproducible on any machine.
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  buildRecordAad,
  padPlaintext,
  encodePayload,
  encodeCell,
  normalizeSpecies,
  encodeCursor,
  ENVELOPE_VERSION,
  WRAP_TYPE_PIN,
  WRAP_TYPE_RECOVERY,
} from '../src/index.js';

import {
  sealRecord,
  wrapDataKey,
  vaultKeypairFromDataKey,
  fingerprintPublicKey,
  recoveryCodeToKey,
  normalizeRecoveryCode,
  ARGON2_TEST_ONLY,
  ARGON2_INTERACTIVE,
} from '../src/crypto.js';

import { bytesToHex, hexToBytes, type VectorFile } from '../src/testvectors.js';
import { encodeUtf8 } from '../src/envelope/utf8.js';

// Fixed inputs. Chosen once, frozen forever.
const DATA_KEY_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const EPHEMERAL_HEX = '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f';
const SALT_HEX = '404142434445464748494a4b4c4d4e4f';
const NONCE_HEX = '505152535455565758595a5b5c5d5e5f6061626364656667';
const USER_ID = 'cku1a2b3c4d5e6f7g8h9i0j1';

// A known-good 24-word BIP-39 mnemonic. All-zero entropy, so it is verifiable
// against any other BIP-39 implementation.
const RECOVERY_CODE =
  'abandon abandon abandon abandon abandon abandon abandon abandon ' +
  'abandon abandon abandon abandon abandon abandon abandon abandon ' +
  'abandon abandon abandon abandon abandon abandon abandon art';

const keypair = vaultKeypairFromDataKey(hexToBytes(DATA_KEY_HEX));
const fingerprint = fingerprintPublicKey(keypair.publicKey);

function sealVector(
  table: string,
  recordKey: string,
  fieldGroup: string,
  payload: Record<string, unknown>,
) {
  return {
    dataKeyHex: DATA_KEY_HEX,
    ephemeralSecretHex: EPHEMERAL_HEX,
    payload,
    userId: USER_ID,
    table,
    recordKey,
    fieldGroup,
    encVersion: ENVELOPE_VERSION,
    blob: sealRecord({
      payload: payload as never,
      recipientPublicKey: keypair.publicKey,
      binding: { userId: USER_ID, table, recordKey, fieldGroup, encVersion: ENVELOPE_VERSION },
      ephemeralSecret: hexToBytes(EPHEMERAL_HEX),
    }),
  };
}

function wrapVector(
  secretUtf8: string,
  wrapType: number,
  params: { memKiB: number; timeCost: number; lanes: number },
  slow = false,
) {
  const binding = { userId: USER_ID, wrapType, keyVersion: 1, vaultPubKeyFp: fingerprint };
  return {
    dataKeyHex: DATA_KEY_HEX,
    secretUtf8,
    saltHex: SALT_HEX,
    nonceHex: NONCE_HEX,
    memKiB: params.memKiB,
    timeCost: params.timeCost,
    lanes: params.lanes,
    userId: USER_ID,
    wrapType,
    keyVersion: 1,
    vaultPubKeyFp: fingerprint,
    slow,
    blob: wrapDataKey({
      dataKey: hexToBytes(DATA_KEY_HEX),
      secret: encodeUtf8(secretUtf8),
      binding,
      params,
      salt: hexToBytes(SALT_HEX),
      nonce: hexToBytes(NONCE_HEX),
    }),
  };
}

const payloads: Record<string, unknown>[] = [
  { lat: 45.6789, lng: -111.0429, sp: 'Brown trout' },
  { lat: 45.6789, lng: -111.0429 },
  { sp: 'Cutthroat' },
  { nm: 'Cedar Hole', ds: 'Below the bridge', nt: '150 yards below the gravel bar' },
  // Non-ASCII, to catch a platform whose UTF-8 encoder disagrees. Written as
  // code points so the source stays ASCII and cannot be mangled by an editor
  // or a codemod: o-umlaut, a-ring, an em dash, e-acute, and a 4-byte emoji.
  {
    sp: 'sj' + String.fromCharCode(0x00f6) + 'ring',
    nt:
      String.fromCharCode(0x00e5) +
      'ngstr' +
      String.fromCharCode(0x00f6) +
      'm ' +
      String.fromCharCode(0x2014) +
      ' caf' +
      String.fromCharCode(0x00e9) +
      ' ' +
      String.fromCharCode(0xd83d, 0xdc1f),
  },
];

const headerForAad = hexToBytes('574c5631' + '01' + '01' + '01' + '00');

const vectors: VectorFile = {
  version: ENVELOPE_VERSION,
  generatedAt: new Date(0).toISOString(),

  geohash: [
    { lat: 42.6, lon: -5.6, precision: 5, cell: encodeCell(42.6, -5.6, 5) },
    { lat: 45.6789, lon: -111.0429, precision: 4, cell: encodeCell(45.6789, -111.0429, 4) },
    { lat: 0, lon: 0, precision: 4, cell: encodeCell(0, 0, 4) },
    { lat: 90, lon: 180, precision: 4, cell: encodeCell(90, 180, 4) },
    { lat: -90, lon: -180, precision: 4, cell: encodeCell(-90, -180, 4) },
  ],

  species: [
    'Brown Trout',
    '  brown   trout  ',
    'BROWN TROUT',
    'sj' + String.fromCharCode(0x00f6) + 'ring',
    'rainbow-trout',
    '',
    '   ',
  ].map((input) => ({ input, output: normalizeSpecies(input) })),

  cursor: [
    { ts: 0, id: 'a' },
    { ts: 1757980800000, id: 'cku1a2b3c4d5e6f7g8h9i0j1' },
  ].map((c) => ({ ...c, encoded: encodeCursor(c) })),

  pad: [
    new Uint8Array(0),
    new Uint8Array([0x7b, 0x7d]),
    new Uint8Array(61),
    new Uint8Array(62),
    new Uint8Array(200),
  ].map((plaintext) => {
    const padded = padPlaintext(plaintext);
    return {
      plaintextHex: bytesToHex(plaintext),
      padBucket: padded.padBucket,
      paddedHex: bytesToHex(padded.bytes),
    };
  }),

  payload: payloads.map((payload) => ({
    payload,
    jsonBytesHex: bytesToHex(encodePayload(payload as never)),
  })),

  aad: [
    { table: 'FishCatch', recordKey: 'cat_1', fieldGroup: 'all' },
    { table: 'Spot', recordKey: 'cat_1', fieldGroup: 'all' },
    { table: 'FishCatch', recordKey: 'cat_1', fieldGroup: 'loc' },
  ].map((b) => ({
    headerHex: bytesToHex(headerForAad),
    userId: USER_ID,
    table: b.table,
    recordKey: b.recordKey,
    fieldGroup: b.fieldGroup,
    encVersion: ENVELOPE_VERSION,
    aadHex: bytesToHex(
      buildRecordAad({
        header: headerForAad,
        userId: USER_ID,
        table: b.table,
        recordKey: b.recordKey,
        fieldGroup: b.fieldGroup,
        encVersion: ENVELOPE_VERSION,
      }),
    ),
  })),

  keypair: [
    {
      dataKeyHex: DATA_KEY_HEX,
      publicKeyHex: bytesToHex(keypair.publicKey),
      fingerprint,
    },
  ],

  seal: [
    sealVector('FishCatch', 'cat_1', 'all', payloads[0]),
    sealVector('Spot', 'spot_1', 'all', payloads[3]),
    sealVector('FishCatch', 'cat_2', 'sp', payloads[4]),
  ],

  wrap: [
    wrapVector('123456', WRAP_TYPE_PIN, ARGON2_TEST_ONLY),
    wrapVector('a longer passphrase for web', WRAP_TYPE_PIN, ARGON2_TEST_ONLY),
    wrapVector(RECOVERY_CODE, WRAP_TYPE_RECOVERY, ARGON2_TEST_ONLY),
    // Production cost. Skipped unless includeSlow, so CI stays fast but the
    // real parameters are still pinned somewhere.
    wrapVector('123456', WRAP_TYPE_PIN, ARGON2_INTERACTIVE, true),
  ],

  recovery: [RECOVERY_CODE, `  ${RECOVERY_CODE.toUpperCase()}  `].map((raw) => ({
    raw,
    normalized: normalizeRecoveryCode(raw),
    entropyHex: bytesToHex(recoveryCodeToKey(raw)),
  })),
};

const here = dirname(fileURLToPath(import.meta.url));
const outPath = resolve(here, '..', 'testvectors', 'v1.json');
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(vectors, null, 2) + '\n');

console.log(`wrote ${outPath}`);
console.log(`  seal vectors:  ${vectors.seal.length}`);
console.log(`  wrap vectors:  ${vectors.wrap.length}`);
console.log(`  fingerprint:   ${fingerprint}`);
