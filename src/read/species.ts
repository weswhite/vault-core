/**
 * Counting species across rows that may not be readable.
 *
 * The trick is that `count` is never encrypted, so totals stay exact even when
 * not one species name is readable. A vault user still sees "41 fish"; what they
 * do not see, until they unlock, is which 41.
 *
 * Without this, every aggregation renders "Encrypted x 41", because
 * PLACEHOLDER_SPECIES is a real string sitting in the species column and no
 * generic group-by has any idea it is a stand-in.
 */

import { PLACEHOLDER_SPECIES } from '../constants';
import { isSealed, type SealedColumns } from './enc';
import type { OpenedRecord } from './payload';

export interface SpeciesTally {
  /** Readable species and their counts, most first. */
  entries: Array<[string, number]>;
  /** Fish or birds whose species is sealed and not open yet. */
  lockedCount: number;
  /** Rows whose record would not open at all. */
  failedCount: number;
  /** Everything, readable or not. Always exact, because counts are plaintext. */
  total: number;
}

export interface SpeciesRowInput extends SealedColumns {
  id: string;
  species?: string | null;
}

export const EMPTY_TALLY: SpeciesTally = {
  entries: [],
  lockedCount: 0,
  failedCount: 0,
  total: 0,
};

/**
 * @param countOf how many fish or birds a row represents. A catch carries a
 *   `count`; a shot is one bird, and only if it was killed.
 */
export function tallySpecies<T extends SpeciesRowInput>(
  rows: T[],
  countOf: (row: T) => number,
  opened: Map<string, OpenedRecord> = new Map(),
): SpeciesTally {
  const byName = new Map<string, number>();
  let lockedCount = 0;
  let failedCount = 0;
  let total = 0;

  for (const row of rows) {
    const count = countOf(row);
    if (count <= 0) continue;
    total += count;

    if (!isSealed(row)) {
      const name = row.species || 'Unknown';
      byName.set(name, (byName.get(name) ?? 0) + count);
      continue;
    }

    const record = opened.get(row.id);
    if (record?.failed) {
      failedCount += count;
      continue;
    }

    const species = record?.payload?.sp;
    if (species) {
      byName.set(species, (byName.get(species) ?? 0) + count);
      continue;
    }

    // Sealed and not open. Never fall back to row.species: that column holds
    // PLACEHOLDER_SPECIES, and counting it puts the literal word "Encrypted" in
    // a species chip as though it were a fish.
    lockedCount += count;
  }

  const entries = [...byName.entries()]
    .filter(([name]) => name !== PLACEHOLDER_SPECIES)
    .sort(([, a], [, b]) => b - a);

  return { entries, lockedCount, failedCount, total };
}

/** True when a tally has anything the user cannot read yet. */
export function hasHiddenSpecies(tally: SpeciesTally): boolean {
  return tally.lockedCount > 0 || tally.failedCount > 0;
}
