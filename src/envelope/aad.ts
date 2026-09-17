/**
 * Additional authenticated data.
 *
 * AAD is authenticated but never stored. It is rebuilt at open time from the row
 * being opened, which is what stops a sealed blob being moved to another row,
 * another table, another account, or another field.
 *
 * See FORMAT.md for the layout and the attack each component rules out.
 */

import { VaultFormatError } from './format.js';
import { encodeUtf8 } from './utf8.js';

/** ASCII Unit Separator. Not legal in any component value. */
const SEP = 0x1f;

const PREFIX_RECORD = 'wlv1';
const PREFIX_WRAP = 'wlw1';

/**
 * The field groups a user can choose between. One toggle in the UI maps to one
 * of these; the group is bound into the AAD so a notes blob cannot be pasted
 * into a location column.
 */
export const FIELD_GROUPS = {
  LOCATION: 'loc',
  SPECIES: 'sp',
  TEXT: 'txt',
  /** Everything the user chose, sealed as one record. The common case. */
  ALL: 'all',
} as const;

export type FieldGroup = (typeof FIELD_GROUPS)[keyof typeof FIELD_GROUPS];

/** Tables that can hold a sealed record. Bound into AAD; cuids are not unique across tables. */
export const SEALABLE_TABLES = [
  'Spot',
  'FishingSession',
  'FishCatch',
  'Observation',
  'DuckShot',
  'UplandBirdShot',
  'Read',
] as const;

export type SealableTable = (typeof SEALABLE_TABLES)[number];

export interface RecordAadInput {
  /** The first 8 bytes of the record, covering version, suite, flags, padBucket. */
  header: Uint8Array;
  userId: string;
  table: SealableTable | string;
  /**
   * Primary key of the row, known to the CLIENT at seal time. A Prisma
   * `@default(cuid())` id is assigned server-side after sealing and cannot be
   * used for a create — supply the key from the client, or use a client-minted
   * field such as `eid`. See FORMAT.md.
   */
  recordKey: string;
  fieldGroup: FieldGroup | string;
  encVersion: number;
}

export interface WrapAadInput {
  /** The first 16 bytes of the wrap. */
  header: Uint8Array;
  userId: string;
  wrapType: number;
  keyVersion: number;
  /** base64url SHA-256 of the vault public key. */
  vaultPubKeyFp: string;
}

function assertNoSeparator(label: string, value: string): void {
  if (value.length === 0) {
    throw new VaultFormatError(`${label} must not be empty`, 'VAULT_BAD_AAD');
  }
  if (value.indexOf('\u001F') !== -1) {
    throw new VaultFormatError(
      `${label} must not contain the AAD separator`,
      'VAULT_BAD_AAD',
    );
  }
}

function concat(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (let i = 0; i < parts.length; i++) total += parts[i].length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (let i = 0; i < parts.length; i++) {
    out.set(parts[i], offset);
    offset += parts[i].length;
  }
  return out;
}

function joinWithSeparator(prefix: string, fields: string[]): Uint8Array {
  const parts: Uint8Array[] = [encodeUtf8(prefix)];
  for (let i = 0; i < fields.length; i++) {
    parts.push(new Uint8Array([SEP]));
    parts.push(encodeUtf8(fields[i]));
  }
  return concat(parts);
}

export function buildRecordAad(input: RecordAadInput): Uint8Array {
  if (input.header.length < 8) {
    throw new VaultFormatError('record AAD needs 8 header bytes', 'VAULT_BAD_AAD');
  }
  assertNoSeparator('userId', input.userId);
  assertNoSeparator('table', input.table);
  assertNoSeparator('recordKey', input.recordKey);
  assertNoSeparator('fieldGroup', input.fieldGroup);

  if (!Number.isInteger(input.encVersion) || input.encVersion < 1) {
    throw new VaultFormatError('encVersion must be a positive integer', 'VAULT_BAD_AAD');
  }

  return concat([
    input.header.subarray(0, 8),
    joinWithSeparator(PREFIX_RECORD, [
      input.userId,
      input.table,
      input.recordKey,
      input.fieldGroup,
      String(input.encVersion),
    ]),
  ]);
}

export function buildWrapAad(input: WrapAadInput): Uint8Array {
  if (input.header.length < 16) {
    throw new VaultFormatError('wrap AAD needs 16 header bytes', 'VAULT_BAD_AAD');
  }
  assertNoSeparator('userId', input.userId);
  assertNoSeparator('vaultPubKeyFp', input.vaultPubKeyFp);

  if (!Number.isInteger(input.wrapType) || input.wrapType < 1) {
    throw new VaultFormatError('wrapType must be a positive integer', 'VAULT_BAD_AAD');
  }
  if (!Number.isInteger(input.keyVersion) || input.keyVersion < 1) {
    throw new VaultFormatError('keyVersion must be a positive integer', 'VAULT_BAD_AAD');
  }

  return concat([
    input.header.subarray(0, 16),
    joinWithSeparator(PREFIX_WRAP, [
      input.userId,
      String(input.wrapType),
      String(input.keyVersion),
      input.vaultPubKeyFp,
    ]),
  ]);
}
