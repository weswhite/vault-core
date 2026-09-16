/**
 * Plaintext placeholders.
 *
 * Several target columns are NOT NULL in the database: Spot.name,
 * Spot.latitude/longitude, Observation.latitude/longitude, and species on both
 * shot tables. Encryption cannot null them, and making them nullable would turn
 * a compile-time guarantee into an `?? 'Unknown'` at every call site across
 * three repos that ship on different schedules.
 *
 * So an encrypted row keeps a plausible, deliberately coarse value in the
 * plaintext column, with the true value only in the sealed blob. Server code
 * that reads these keeps working on degraded-but-valid data.
 *
 * The rule that makes this safe: an API must NEVER return a bare lat/lng for a
 * row marked CELL precision. Return { cell, centroid, precision } and let the
 * client draw a circle. Rendering a cell centroid as if it were a catch pin is
 * a lie about where someone fished, drawn on a map, which is the worst failure
 * this feature could have.
 */

/** Written to Spot.name when the text group is encrypted. */
export const PLACEHOLDER_SPOT_NAME = 'Private spot';

/** Written to species columns that cannot be null. */
export const PLACEHOLDER_SPECIES = 'Encrypted';

/**
 * Marks how much to trust a row's plaintext coordinates.
 *
 * EXACT — the coordinates are real.
 * CELL  — they are a ~20km cell centroid; the real position is sealed.
 *
 * A null value on a legacy row means EXACT when latitude is non-null.
 */
export const LOC_PRECISION = {
  EXACT: 'EXACT',
  CELL: 'CELL',
} as const;

export type LocPrecision = (typeof LOC_PRECISION)[keyof typeof LOC_PRECISION];

/**
 * True when a consumer must not treat the row's plaintext coordinates as a real
 * position. Handles the legacy null case so callers do not each reinvent it.
 */
export function isCoarseLocation(locPrecision: string | null | undefined): boolean {
  return locPrecision === LOC_PRECISION.CELL;
}
