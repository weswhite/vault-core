/**
 * Row plus decrypted payload, out come `Enc` fields.
 *
 * The short wire keys (`sp`, `nm`, `ds`, `nt`, `cln`) are frozen by the envelope
 * format, and this is the only place outside the payload codec that names them.
 * Spreading them through app code would put a format detail in fifty files and
 * turn renaming one into a migration across every client at once.
 */

import { PLACEHOLDER_SPECIES, PLACEHOLDER_SPOT_NAME } from '../constants';
import type { VaultPayload } from '../envelope/payload';
import { encField, type Enc, type SealedColumns } from './enc';
import { encLocation, type EncLocation, type RowLocation } from './location';

/** What a client's decrypt step returns for one row. */
export interface OpenedRecord {
  payload?: VaultPayload;
  failed?: boolean;
}

function pick<T>(opened: OpenedRecord | undefined, value: T | undefined) {
  if (!opened) return undefined;
  return { value, failed: opened.failed };
}

export interface SpeciesRow extends SealedColumns {
  species?: string | null;
}

/**
 * Species.
 *
 * The placeholder is the server's own constant, so rendering `row.species` and
 * rendering this agree, and a screen nobody has converted yet degrades to the
 * same words rather than to nonsense.
 */
export function encSpecies(row: SpeciesRow, opened?: OpenedRecord): Enc<string> {
  return encField(row, row.species ?? PLACEHOLDER_SPECIES, pick(opened, opened?.payload?.sp));
}

export interface NamedRow extends SealedColumns {
  name?: string | null;
}

export function encName(row: NamedRow, opened?: OpenedRecord): Enc<string> {
  return encField(row, row.name ?? PLACEHOLDER_SPOT_NAME, pick(opened, opened?.payload?.nm));
}

export interface TextRow extends SealedColumns {
  description?: string | null;
  notes?: string | null;
  customLocationName?: string | null;
}

/**
 * Free text is nullable in the database, so a sealed row holds null rather than
 * a placeholder string. Null is the honest placeholder: there is nothing to
 * show, and the app decides whether that means hiding the section or marking it
 * locked.
 */
export function encDescription(row: TextRow, opened?: OpenedRecord): Enc<string | null> {
  return encField(row, row.description ?? null, pick(opened, opened?.payload?.ds));
}

export function encNotes(row: TextRow, opened?: OpenedRecord): Enc<string | null> {
  return encField(row, row.notes ?? null, pick(opened, opened?.payload?.nt));
}

export function encCustomLocationName(row: TextRow, opened?: OpenedRecord): Enc<string | null> {
  return encField(row, row.customLocationName ?? null, pick(opened, opened?.payload?.cln));
}

export function encCoords(row: RowLocation, opened?: OpenedRecord): EncLocation {
  if (!opened) return encLocation(row);
  return encLocation(row, {
    lat: opened.payload?.lat,
    lng: opened.payload?.lng,
    failed: opened.failed,
  });
}
