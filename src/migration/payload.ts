/**
 * What gets sealed from each row the migration walk hands out.
 *
 * The most data-sensitive file in the vault, for one reason: when a sealed row
 * is written back, the server clears every private field on it -- species,
 * name, description, notes, custom location name, exact position -- and keeps
 * only what is in the ciphertext. A field this file forgets to put in the
 * payload is not hidden. It is deleted, permanently, with nothing to say it
 * ever existed.
 *
 * So the rule is: every field the server's migration page selects goes into the
 * payload, for every table, whether or not the app happens to display it. The
 * test for this file checks each table against that list.
 *
 * Null fields are omitted rather than written. Once opened, an absent field
 * reads as empty (vault-core 0.2.1), which is what it was.
 *
 * Pure. No crypto.
 *
 * It lives in the package because both clients walk the same history: a user
 * who enrolls on the phone and one who enrolls on the web have to seal the same
 * fields, and a copy of this file per app is a copy that can drift into
 * deleting a column on one platform only.
 */

import type { VaultPayload } from '../envelope/payload';

export const MIGRATION_TABLES = [
  'Spot',
  'FishingSession',
  'FishCatch',
  'Observation',
  'DuckShot',
  'UplandBirdShot',
  // Appended, never inserted: the walk's cursor encodes a table name, so
  // reordering this list strands anyone whose cursor points at a table that
  // has moved. Appending only extends the walk for everyone already past it.
  'Read',
] as const;

export type MigrationTable = (typeof MIGRATION_TABLES)[number];

/**
 * A row as `GET /api/vault/migration/next` returns it.
 *
 * One shape for every table. Where a column is named differently in the
 * database -- a Read stores its position as pointLat/pointLon and its note as
 * `note` -- the server renames it into this shape, so the payload rules below
 * stay one set of rules rather than one per table.
 */
export interface MigrationRow {
  id: string;
  latitude: number | null;
  longitude: number | null;
  species?: string | null;
  name?: string | null;
  description?: string | null;
  notes?: string | null;
  customLocationName?: string | null;
  title?: string | null;
  createdAt: string;
}

/**
 * The private fields each table's page carries, mirroring the backend's
 * selectFor. Kept as data so the test can hold this file to it, and so a
 * backend change that adds a field fails loudly here instead of quietly
 * deleting that field from every migrated row.
 */
export const PRIVATE_FIELDS: Record<MigrationTable, ReadonlyArray<keyof MigrationRow>> = {
  Spot: ['latitude', 'longitude', 'name', 'description', 'notes'],
  FishingSession: ['latitude', 'longitude', 'notes', 'customLocationName'],
  FishCatch: ['latitude', 'longitude', 'species', 'notes'],
  Observation: ['latitude', 'longitude', 'notes'],
  DuckShot: ['latitude', 'longitude', 'species', 'notes'],
  UplandBirdShot: ['latitude', 'longitude', 'species', 'notes'],
  // `title` is deprecated and no longer written, but old rows still carry one
  // and a field left out of the payload is deleted rather than hidden.
  Read: ['latitude', 'longitude', 'notes', 'title'],
};

export interface PreparedRow {
  id: string;
  payload: VaultPayload;
  /** Where to compute the geohash-4 cell from. Null when the row has no position. */
  cellLat: number | null;
  cellLng: number | null;
}

const present = (v: string | null | undefined): v is string => typeof v === 'string' && v !== '';

export function preparePayload(table: MigrationTable, row: MigrationRow): PreparedRow {
  const fields = PRIVATE_FIELDS[table];
  const payload: VaultPayload = {};

  const hasPosition =
    fields.includes('latitude') && row.latitude != null && row.longitude != null;
  if (hasPosition) {
    payload.lat = row.latitude as number;
    payload.lng = row.longitude as number;
  }

  if (fields.includes('species') && present(row.species)) payload.sp = row.species;
  if (fields.includes('name') && present(row.name)) payload.nm = row.name;
  if (fields.includes('description') && present(row.description)) payload.ds = row.description;
  if (fields.includes('notes') && present(row.notes)) payload.nt = row.notes;
  if (fields.includes('customLocationName') && present(row.customLocationName)) {
    payload.cln = row.customLocationName;
  }
  if (fields.includes('title') && present(row.title)) payload.tl = row.title;

  return {
    id: row.id,
    payload,
    cellLat: hasPosition ? (row.latitude as number) : null,
    cellLng: hasPosition ? (row.longitude as number) : null,
  };
}

/**
 * Tables the server refuses to seal without a cell, because their coordinate
 * columns are NOT NULL and the centroid is the only legal value left.
 *
 * A row in one of these with no position cannot be sealed at all. The walk
 * skips it rather than sending something the server will reject, and the
 * server's recount at the end reports it as remaining.
 */
export const REQUIRES_CELL: ReadonlySet<MigrationTable> = new Set(['Spot', 'Observation']);
