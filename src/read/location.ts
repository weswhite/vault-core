/**
 * Locations, which never get the "always renderable" guarantee the other fields
 * get, because their placeholder is the dangerous one.
 *
 * A sealed row's latitude and longitude are the centroid of a ~20km geohash
 * cell. They are real numbers in a real place, about 20km from the truth, and
 * nothing in a `{lat, lng}` says so. So the type carries the precision, and the
 * only way to get coordinates out is to ask for exact ones and handle null.
 *
 * Two facts about how the server writes these rows, which this file encodes so
 * no client has to rediscover them:
 *
 *   - A sealed row NEVER carries real coordinates. The columns start null and
 *     only ever receive the cell centroid, so `locPrecision === CELL` is exactly
 *     "has a location, and it is hidden", and its absence is exactly "has no
 *     location". There is no third case.
 *   - Event-level tables (FishCatch, DuckShot, UplandBirdShot) keep NULL
 *     coordinates even when they have a cell, because an exact event position
 *     only ever fed the user's own map. So everything drawable comes off the
 *     cell, not off lat/lng.
 */

import { LOC_PRECISION, isCoarseLocation, type LocPrecision } from '../constants';
import { cellBounds, cellCentroid } from '../geo/geohash';
import type { EncState, SealedColumns } from './enc';
import { isSealed } from './enc';

export interface EncLocation {
  state: EncState;
  /** Null when the row has no location at all, or when only a cell is known. */
  lat: number | null;
  lng: number | null;
  precision: LocPrecision | null;
  /** The geohash-4 cell, when the position is coarse. */
  cell: string | null;
}

export interface Coords {
  lat: number;
  lng: number;
}

export interface RowLocation extends SealedColumns {
  latitude?: number | null;
  longitude?: number | null;
}

export function encLocation(
  row: RowLocation,
  opened?: { lat?: number; lng?: number; failed?: boolean },
): EncLocation {
  if (!isSealed(row)) {
    return {
      state: 'plain',
      lat: row.latitude ?? null,
      lng: row.longitude ?? null,
      // A legacy row with no locPrecision and a real latitude is EXACT.
      precision: row.latitude == null ? null : LOC_PRECISION.EXACT,
      cell: null,
    };
  }

  if (!isCoarseLocation(row.locPrecision)) {
    return { state: 'plain', lat: null, lng: null, precision: null, cell: null };
  }

  if (opened && !opened.failed && opened.lat != null && opened.lng != null) {
    return {
      state: 'open',
      lat: opened.lat,
      lng: opened.lng,
      precision: LOC_PRECISION.EXACT,
      cell: row.geohash4 ?? null,
    };
  }

  return {
    state: opened?.failed ? 'failed' : 'locked',
    lat: row.latitude ?? null,
    lng: row.longitude ?? null,
    precision: LOC_PRECISION.CELL,
    cell: row.geohash4 ?? null,
  };
}

/**
 * The real position, or null.
 *
 * Every map pin, distance calculation and river-attribution lookup goes through
 * here. A locked row returns null, so the caller decides what to do rather than
 * quietly plotting a point 20km from where someone actually fished.
 */
export function exactCoords(loc: EncLocation): Coords | null {
  if (loc.precision !== LOC_PRECISION.EXACT) return null;
  if (loc.lat == null || loc.lng == null) return null;
  return { lat: loc.lat, lng: loc.lng };
}

export interface CoarseArea {
  center: Coords;
  bounds: { minLat: number; minLng: number; maxLat: number; maxLng: number };
}

/**
 * The area a locked location could be anywhere within.
 *
 * The cell's real bounds, not a radius. A geohash cell is a box whose width in
 * metres shrinks toward the poles, so a radius chosen to look right at one
 * latitude understates the cell at another and leaks more than the cell does.
 */
export function coarseArea(loc: EncLocation): CoarseArea | null {
  if (loc.precision !== LOC_PRECISION.CELL || !loc.cell) return null;

  const box = cellBounds(loc.cell);
  const centre = cellCentroid(loc.cell);

  return {
    center: { lat: centre.lat, lng: centre.lon },
    bounds: {
      minLat: box.minLat,
      minLng: box.minLon,
      maxLat: box.maxLat,
      maxLng: box.maxLon,
    },
  };
}

/**
 * True when the row has a position of some kind, exact or coarse.
 *
 * Checks the cell as well as the coordinates, because a sealed FishCatch has a
 * cell and null coordinates. Testing lat/lng alone reports "no location" for
 * every locked catch, and a map draws nothing where it should draw cells.
 */
export function hasAnyLocation(loc: EncLocation): boolean {
  return (loc.lat != null && loc.lng != null) || loc.cell != null;
}
