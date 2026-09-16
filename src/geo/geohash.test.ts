import { describe, it, expect } from 'vitest';

import { GEOHASH_PRECISION } from '../version.js';
import {
  GEOHASH_ALPHABET,
  MAX_GEOHASH_PRECISION,
  cellBounds,
  cellCentroid,
  encodeCell,
} from './geohash.js';

function insideBounds(cell: string): boolean {
  const bounds = cellBounds(cell);
  const centroid = cellCentroid(cell);
  return (
    centroid.lat >= bounds.minLat &&
    centroid.lat <= bounds.maxLat &&
    centroid.lon >= bounds.minLon &&
    centroid.lon <= bounds.maxLon
  );
}

describe('encodeCell', () => {
  // Published values. If one of these ever changes, the cell format changed and
  // every stored cell is now keyed differently.
  it('matches published geohashes', () => {
    expect(encodeCell(42.6, -5.6, 5)).toBe('ezs42');
    expect(encodeCell(57.64911, 10.40744, 11)).toBe('u4pruydqqvj');
    expect(encodeCell(37.7749, -122.4194, 9)).toBe('9q8yyk8yt');
    expect(encodeCell(0, 0, 6)).toBe('s00000');
  });

  it('defaults to GEOHASH_PRECISION', () => {
    expect(GEOHASH_PRECISION).toBe(4);
    expect(encodeCell(45.3611, -111.0833)).toBe('c814');
    expect(encodeCell(45.3611, -111.0833)).toHaveLength(GEOHASH_PRECISION);
    expect(encodeCell(42.6, -5.6)).toBe('ezs4');
  });

  it('returns exactly `precision` characters, all in the alphabet', () => {
    for (let precision = 1; precision <= MAX_GEOHASH_PRECISION; precision++) {
      const cell = encodeCell(44.2619, -72.5806, precision);
      expect(cell).toHaveLength(precision);
      for (let i = 0; i < cell.length; i++) {
        expect(GEOHASH_ALPHABET.indexOf(cell.charAt(i))).toBeGreaterThanOrEqual(0);
      }
    }
  });

  it('omits a, i, l and o from the alphabet', () => {
    expect(GEOHASH_ALPHABET).toBe('0123456789bcdefghjkmnpqrstuvwxyz');
    expect(GEOHASH_ALPHABET).toHaveLength(32);
    expect(GEOHASH_ALPHABET.indexOf('a')).toBe(-1);
    expect(GEOHASH_ALPHABET.indexOf('i')).toBe(-1);
    expect(GEOHASH_ALPHABET.indexOf('l')).toBe(-1);
    expect(GEOHASH_ALPHABET.indexOf('o')).toBe(-1);
  });

  it('is a prefix code: a coarser cell prefixes a finer one', () => {
    const finest = encodeCell(42.6, -5.6, MAX_GEOHASH_PRECISION);
    for (let precision = 1; precision < MAX_GEOHASH_PRECISION; precision++) {
      expect(encodeCell(42.6, -5.6, precision)).toBe(finest.slice(0, precision));
    }
  });

  it('handles the corners of the grid', () => {
    expect(encodeCell(90, 180, 12)).toBe('zzzzzzzzzzzz');
    expect(encodeCell(-90, -180, 12)).toBe('000000000000');
    expect(encodeCell(90, -180, 6)).toBe('bpbpbp');
    expect(encodeCell(-90, 180, 6)).toBe('pbpbpb');
  });

  it('treats 180 and -180 as different cells, because they are', () => {
    expect(encodeCell(0, 180, 6)).not.toBe(encodeCell(0, -180, 6));
  });

  it('treats -0 as 0', () => {
    expect(encodeCell(-0, -0, 8)).toBe(encodeCell(0, 0, 8));
  });

  it('rejects coordinates outside the world', () => {
    expect(() => encodeCell(90.0001, 0)).toThrow(/latitude/);
    expect(() => encodeCell(-90.0001, 0)).toThrow(/latitude/);
    expect(() => encodeCell(0, 180.0001)).toThrow(/longitude/);
    expect(() => encodeCell(0, -180.0001)).toThrow(/longitude/);
  });

  it('rejects non-finite coordinates instead of guessing', () => {
    expect(() => encodeCell(Number.NaN, 0)).toThrow(/finite/);
    expect(() => encodeCell(0, Number.NaN)).toThrow(/finite/);
    expect(() => encodeCell(Number.POSITIVE_INFINITY, 0)).toThrow(/finite/);
    expect(() => encodeCell(undefined as unknown as number, 0)).toThrow(/finite/);
    expect(() => encodeCell('45' as unknown as number, 0)).toThrow(/finite/);
  });

  it('rejects a precision it cannot honour', () => {
    expect(() => encodeCell(0, 0, 0)).toThrow(/precision/);
    expect(() => encodeCell(0, 0, -1)).toThrow(/precision/);
    expect(() => encodeCell(0, 0, MAX_GEOHASH_PRECISION + 1)).toThrow(/precision/);
    expect(() => encodeCell(0, 0, 4.5)).toThrow(/precision/);
    expect(() => encodeCell(0, 0, Number.NaN)).toThrow(/precision/);
    expect(() => encodeCell(0, 0, '4' as unknown as number)).toThrow(/precision/);
  });
});

describe('cellBounds', () => {
  it('covers the whole world at precision 1', () => {
    expect(cellBounds('0')).toEqual({ minLat: -90, maxLat: -45, minLon: -180, maxLon: -135 });
    expect(cellBounds('z')).toEqual({ minLat: 45, maxLat: 90, minLon: 135, maxLon: 180 });
    expect(cellBounds('s')).toEqual({ minLat: 0, maxLat: 45, minLon: 0, maxLon: 45 });
  });

  it('gives the published box for ezs42', () => {
    expect(cellBounds('ezs42')).toEqual({
      minLat: 42.5830078125,
      maxLat: 42.626953125,
      minLon: -5.625,
      maxLon: -5.5810546875,
    });
  });

  it('nests: a child cell sits inside its parent', () => {
    const parent = cellBounds('ezs4');
    const child = cellBounds('ezs42');
    expect(child.minLat).toBeGreaterThanOrEqual(parent.minLat);
    expect(child.maxLat).toBeLessThanOrEqual(parent.maxLat);
    expect(child.minLon).toBeGreaterThanOrEqual(parent.minLon);
    expect(child.maxLon).toBeLessThanOrEqual(parent.maxLon);
  });

  it('rejects characters outside the alphabet', () => {
    expect(() => cellBounds('a')).toThrow(/alphabet/);
    expect(() => cellBounds('i')).toThrow(/alphabet/);
    expect(() => cellBounds('l')).toThrow(/alphabet/);
    expect(() => cellBounds('o')).toThrow(/alphabet/);
    expect(() => cellBounds('ez!42')).toThrow(/alphabet/);
    expect(() => cellBounds('ez s4')).toThrow(/alphabet/);
    expect(() => cellBounds('ezs4\u00e9')).toThrow(/alphabet/);
  });

  it('rejects uppercase rather than folding it', () => {
    expect(() => cellBounds('EZS42')).toThrow(/alphabet/);
    expect(() => cellCentroid('Ezs42')).toThrow(/alphabet/);
  });

  it('rejects an empty or over-long cell', () => {
    expect(() => cellBounds('')).toThrow(/non-empty/);
    expect(() => cellBounds(undefined as unknown as string)).toThrow(/non-empty/);
    expect(() => cellBounds('z'.repeat(MAX_GEOHASH_PRECISION + 1))).toThrow(/maximum/);
  });
});

describe('cellCentroid', () => {
  it('is the exact middle of the published box', () => {
    expect(cellCentroid('ezs42')).toEqual({ lat: 42.60498046875, lon: -5.60302734375 });
  });

  it('recovers the original position to within the cell size', () => {
    const centroid = cellCentroid('u4pruydqqvj');
    expect(centroid.lat).toBeCloseTo(57.64911, 4);
    expect(centroid.lon).toBeCloseTo(10.40744, 4);
  });

  it('re-encodes to the cell it came from', () => {
    const cells = ['0', 'z', 's', 'ezs4', 'ezs42', '9q8yyk8yt', 'u4pruydqqvj', 'zzzzzzzzzzzz'];
    for (const cell of cells) {
      const centroid = cellCentroid(cell);
      expect(encodeCell(centroid.lat, centroid.lon, cell.length)).toBe(cell);
    }
  });

  it('stays inside its own bounds everywhere, including the poles and the antimeridian', () => {
    const extremes: Array<[number, number]> = [
      [90, 180],
      [90, -180],
      [-90, 180],
      [-90, -180],
      [90, 0],
      [-90, 0],
      [0, 180],
      [0, -180],
      [0, 0],
      [-0, -0],
    ];
    for (const [lat, lon] of extremes) {
      for (let precision = 1; precision <= MAX_GEOHASH_PRECISION; precision++) {
        const cell = encodeCell(lat, lon, precision);
        expect(insideBounds(cell)).toBe(true);
      }
    }
  });

  it('holds the containment invariant across a sweep of the world', () => {
    for (let lat = -90; lat <= 90; lat += 3.75) {
      for (let lon = -180; lon <= 180; lon += 7.5) {
        for (const precision of [1, 4, 8, 12]) {
          const cell = encodeCell(lat, lon, precision);
          const bounds = cellBounds(cell);

          // the point that produced the cell is in the cell
          expect(lat).toBeGreaterThanOrEqual(bounds.minLat);
          expect(lat).toBeLessThanOrEqual(bounds.maxLat);
          expect(lon).toBeGreaterThanOrEqual(bounds.minLon);
          expect(lon).toBeLessThanOrEqual(bounds.maxLon);

          // and so is the centroid we would hand back for it
          expect(insideBounds(cell)).toBe(true);
        }
      }
    }
  });
});
