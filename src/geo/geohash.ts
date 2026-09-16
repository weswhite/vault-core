/**
 * Geohash cells for the coarse location a row carries in the clear.
 *
 * A sealed record hides the exact coordinates, but the app still has to answer
 * "which of my spots are near here" and "how did this stretch fish last week"
 * without opening anything. So the row stores a coarse cell in plaintext next
 * to the ciphertext, and every query, aggregate and cache key is built from
 * that cell rather than from the real position.
 *
 * That makes this a data format, not a helper. Cells are written into rows and
 * into counts keyed by cell; if a future build returns a different string for
 * coordinates that already shipped, history silently re-buckets: counts move
 * between cells, nothing errors, and there is no way to tell which rows were
 * written under which rule. Changing the output here is a new field, never an
 * edit. See FORMAT.md.
 *
 * Runs on Node, in a browser worker, and on Hermes. No Buffer, no Array.at, no
 * Unicode property escapes.
 */

import { GEOHASH_PRECISION } from '../version.js';
import { VaultFormatError } from '../envelope/format.js';

/**
 * Standard geohash base32: a, i, l and o are missing so a cell read aloud or
 * typed from a screenshot cannot be confused with 1 and 0. This ordering is the
 * published one, which is what makes our cells comparable with PostGIS,
 * Elasticsearch and every other geohash implementation.
 */
export const GEOHASH_ALPHABET = '0123456789bcdefghjkmnpqrstuvwxyz';

/** Bits contributed by one base32 character. */
const BITS_PER_CHAR = 5;

/**
 * 12 characters is 60 bits, roughly 4cm, and is the conventional maximum. The
 * bisection below only actually runs out of double precision past about 20
 * characters, but capping both encode and decode at the conventional limit
 * keeps them symmetric, bounds the work, and means a cell we produce is one
 * every other implementation can read back.
 */
export const MAX_GEOHASH_PRECISION = 12;

const GEOHASH_LOOKUP = /* @__PURE__ */ (() => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < GEOHASH_ALPHABET.length; i++) {
    table[GEOHASH_ALPHABET.charCodeAt(i)] = i;
  }
  return table;
})();

export interface CellCentroid {
  lat: number;
  lon: number;
}

export interface CellBounds {
  minLat: number;
  maxLat: number;
  minLon: number;
  maxLon: number;
}

function assertCoordinate(label: string, value: number, limit: number): void {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new VaultFormatError(
      `${label} must be a finite number, got ${String(value)}`,
      'VAULT_BAD_COORD',
    );
  }
  if (value < -limit || value > limit) {
    // Clamping here would be worse than throwing. A latitude of 91 is a bug in
    // the caller (a parsed string, a swapped lat/lon) and silently turning it
    // into 90 files the user's session at the pole with no trace.
    throw new VaultFormatError(
      `${label} ${value} is outside [-${limit}, ${limit}]`,
      'VAULT_BAD_COORD',
    );
  }
}

function assertPrecision(precision: number): void {
  if (
    typeof precision !== 'number' ||
    !Number.isInteger(precision) ||
    precision < 1 ||
    precision > MAX_GEOHASH_PRECISION
  ) {
    throw new VaultFormatError(
      `precision must be an integer in 1..${MAX_GEOHASH_PRECISION}, got ${String(precision)}`,
      'VAULT_BAD_COORD',
    );
  }
}

function assertCell(cell: string): void {
  if (typeof cell !== 'string' || cell.length === 0) {
    throw new VaultFormatError('cell must be a non-empty string', 'VAULT_BAD_CELL');
  }
  if (cell.length > MAX_GEOHASH_PRECISION) {
    throw new VaultFormatError(
      `cell is ${cell.length} characters, maximum is ${MAX_GEOHASH_PRECISION}`,
      'VAULT_BAD_CELL',
    );
  }
  for (let i = 0; i < cell.length; i++) {
    const code = cell.charCodeAt(i);
    // Uppercase is rejected rather than folded. Cells are grouping keys, and
    // accepting "EZS42" as a spelling of "ezs42" would let two spellings of one
    // cell accumulate separate counts.
    if (code > 127 || GEOHASH_LOOKUP[code] === -1) {
      throw new VaultFormatError(
        `cell contains a character outside the geohash alphabet at index ${i}: ` +
          JSON.stringify(cell.charAt(i)),
        'VAULT_BAD_CELL',
      );
    }
  }
}

/**
 * Coarse cell for a position. Defaults to GEOHASH_PRECISION (4, ~20km), which
 * is the precision the plaintext column stores.
 *
 * Frozen decisions, because they decide the output string:
 *
 * - Longitude takes the first bit, then the two alternate. Standard geohash.
 * - A coordinate exactly on a division goes to the upper half (`>= mid`). This
 *   is what makes the extremes behave: 90, -90, 180 and -180 land in the cell
 *   whose bounds touch them, so cellCentroid(encodeCell(lat, lon)) is inside
 *   its own bounds everywhere, poles and antimeridian included.
 * - Midpoints are computed as (min + max) / 2 in doubles. Both operations are
 *   correctly rounded by IEEE-754 and neither can overflow inside +/-180, so
 *   every runtime bisects to the identical value. That is the only reason the
 *   three clients agree on a cell without a shared implementation.
 *
 * Note that 180 and -180 are different cells. That is inherent to geohash, not
 * something to paper over: the grid has an edge and it sits on the antimeridian.
 */
export function encodeCell(
  lat: number,
  lon: number,
  precision: number = GEOHASH_PRECISION,
): string {
  assertCoordinate('latitude', lat, 90);
  assertCoordinate('longitude', lon, 180);
  assertPrecision(precision);

  let minLat = -90;
  let maxLat = 90;
  let minLon = -180;
  let maxLon = 180;

  let out = '';
  let evenBit = true;
  let bits = 0;
  let index = 0;

  while (out.length < precision) {
    if (evenBit) {
      const mid = (minLon + maxLon) / 2;
      if (lon >= mid) {
        index = (index << 1) | 1;
        minLon = mid;
      } else {
        index = index << 1;
        maxLon = mid;
      }
    } else {
      const mid = (minLat + maxLat) / 2;
      if (lat >= mid) {
        index = (index << 1) | 1;
        minLat = mid;
      } else {
        index = index << 1;
        maxLat = mid;
      }
    }
    evenBit = !evenBit;

    bits++;
    if (bits === BITS_PER_CHAR) {
      out += GEOHASH_ALPHABET.charAt(index);
      bits = 0;
      index = 0;
    }
  }

  return out;
}

/**
 * The box a cell covers. Half-open in principle, since a point on maxLat or
 * maxLon encodes into the next cell up (except at 90 and 180, where there is
 * no next cell), but the bounds come back as plain numbers and the caller
 * decides what to do with an edge.
 */
export function cellBounds(cell: string): CellBounds {
  assertCell(cell);

  let minLat = -90;
  let maxLat = 90;
  let minLon = -180;
  let maxLon = 180;
  let evenBit = true;

  for (let i = 0; i < cell.length; i++) {
    const index = GEOHASH_LOOKUP[cell.charCodeAt(i)];
    for (let b = BITS_PER_CHAR - 1; b >= 0; b--) {
      const bit = (index >> b) & 1;
      if (evenBit) {
        const mid = (minLon + maxLon) / 2;
        if (bit === 1) minLon = mid;
        else maxLon = mid;
      } else {
        const mid = (minLat + maxLat) / 2;
        if (bit === 1) minLat = mid;
        else maxLat = mid;
      }
      evenBit = !evenBit;
    }
  }

  return { minLat, maxLat, minLon, maxLon };
}

/**
 * Exact centre of a cell: the same midpoint the bisection above computes, so it
 * is always strictly inside the bounds it came from.
 *
 * Deliberately not rounded. Rounding to a fixed number of decimals would be an
 * output decision frozen forever, it would break the "inside its own bounds"
 * property at high precision, and a centroid is already an approximation the
 * caller should treat as one. Round at the display layer instead.
 */
export function cellCentroid(cell: string): CellCentroid {
  const bounds = cellBounds(cell);
  return {
    lat: (bounds.minLat + bounds.maxLat) / 2,
    lon: (bounds.minLon + bounds.maxLon) / 2,
  };
}
