/**
 * The read layer.
 *
 * These tests are the reason this code is in the package rather than copied
 * into each client. They pin facts about how the server writes a sealed row --
 * which columns hold placeholders, when a location is hidden versus absent,
 * which tables keep coordinates -- and a client that got any of them wrong on
 * its own would draw a pin on a catch whose position is supposed to be secret.
 */

import { describe, it, expect } from 'vitest';
import {
  encField,
  encLocation,
  encSpecies,
  encName,
  encNotes,
  encDescription,
  encCustomLocationName,
  encCoords,
  exactCoords,
  coarseArea,
  hasAnyLocation,
  isLocked,
  isSealed,
  realValue,
  plain,
  tallySpecies,
  hasHiddenSpecies,
} from '../read';
import { encodeCell, cellCentroid } from '../geo/geohash';
import { LOC_PRECISION, PLACEHOLDER_SPECIES, PLACEHOLDER_SPOT_NAME } from '../constants';

const LAT = 45.123456;
const LNG = -111.654321;
const CELL = encodeCell(LAT, LNG, 4);
const CENTROID = cellCentroid(CELL);

const sealed = { encVersion: 1, encBlob: 'blob' };

/** A sealed FishingSession or Spot: keeps the cell centroid. */
const sealedWithCentroid = {
  ...sealed,
  geohash4: CELL,
  hasLocation: true,
  locPrecision: LOC_PRECISION.CELL,
  latitude: CENTROID.lat,
  longitude: CENTROID.lon,
};

/** A sealed FishCatch: cell, but null coordinates. */
const sealedEventRow = {
  ...sealed,
  geohash4: CELL,
  hasLocation: true,
  locPrecision: LOC_PRECISION.CELL,
  latitude: null,
  longitude: null,
};

describe('isSealed', () => {
  it('keys off encVersion alone', () => {
    expect(isSealed({ encVersion: 1 })).toBe(true);
    expect(isSealed({ encVersion: null })).toBe(false);
    expect(isSealed({})).toBe(false);
    expect(isSealed(null)).toBe(false);
  });
});

describe('encField', () => {
  it('always leaves something renderable', () => {
    // The rule the type exists for. A client that prints field.value and knows
    // nothing about the vault must not print "undefined".
    for (const opened of [undefined, { failed: true }, { value: 'real' }]) {
      expect(encField({ encVersion: 1 }, 'Encrypted', opened).value).toBeTruthy();
    }
  });

  it('moves through its four states', () => {
    expect(encField({ encVersion: null }, 'x', undefined).state).toBe('plain');
    expect(encField({ encVersion: 1 }, 'x', undefined).state).toBe('locked');
    expect(encField({ encVersion: 1 }, 'x', { value: 'real' }).state).toBe('open');
    expect(encField({ encVersion: 1 }, 'x', { failed: true }).state).toBe('failed');
  });

  it('reads an absent field in an opened record as empty, not locked', () => {
    // The payload omits null fields, and every record is sealed whole. So once a
    // record has opened, a missing field was empty -- and showing it as locked
    // would tell the owner, after unlocking, that their own note is hidden.
    const field = encField({ encVersion: 1 }, 'x', { value: undefined }, null as unknown as string);
    expect(field.state).toBe('open');
    expect(field.value).toBeNull();
  });

  it('uses the placeholder as the empty value when none is given', () => {
    expect(encField({ encVersion: 1 }, 'x', { value: undefined })).toEqual({ state: 'open', value: 'x' });
  });

  it('stays locked when the record has not been opened at all', () => {
    expect(encField({ encVersion: 1 }, 'x', undefined).state).toBe('locked');
  });

  it('keeps the placeholder on a record that would not open', () => {
    // Never dropped. A catch that vanishes reads as lost data.
    const field = encField({ encVersion: 1 }, 'Encrypted', { failed: true });
    expect(field.value).toBe('Encrypted');
  });
});

describe('realValue', () => {
  it('is null for anything not readable', () => {
    expect(realValue(encField({ encVersion: 1 }, 'x', undefined))).toBeNull();
    expect(realValue(encField({ encVersion: 1 }, 'x', { failed: true }))).toBeNull();
  });

  it('is the value when it is real', () => {
    expect(realValue(plain('Brown trout'))).toBe('Brown trout');
    expect(realValue(encField({ encVersion: 1 }, 'x', { value: 'Brown trout' }))).toBe('Brown trout');
  });
});

describe('isLocked', () => {
  it('covers failed as well as locked', () => {
    expect(isLocked(encField({ encVersion: 1 }, 'x', undefined))).toBe(true);
    expect(isLocked(encField({ encVersion: 1 }, 'x', { failed: true }))).toBe(true);
    expect(isLocked(plain('x'))).toBe(false);
  });
});

describe('the wire keys', () => {
  const payload = {
    payload: {
      sp: 'Brown trout',
      nm: 'The bend below the bridge',
      ds: 'Deep seam, fishes best at dusk',
      nt: 'Size 18 pheasant tail',
      cln: 'Back channel',
      lat: LAT,
      lng: LNG,
    },
  };

  it('each lands on its own field', () => {
    // A silent swap of `nt` and `ds` would render a spot's notes as its
    // description on every screen at once, and nothing else would notice.
    expect(encSpecies(sealed, payload).value).toBe('Brown trout');
    expect(encName(sealed, payload).value).toBe('The bend below the bridge');
    expect(encDescription(sealed, payload).value).toBe('Deep seam, fishes best at dusk');
    expect(encNotes(sealed, payload).value).toBe('Size 18 pheasant tail');
    expect(encCustomLocationName(sealed, payload).value).toBe('Back channel');
  });

  it('gives coordinates only through the location type', () => {
    expect(exactCoords(encCoords(sealedWithCentroid, payload))).toEqual({ lat: LAT, lng: LNG });
  });
});

describe('placeholders before unlock', () => {
  it('uses the server constants, so an unconverted screen still reads sensibly', () => {
    expect(encSpecies({ ...sealed, species: PLACEHOLDER_SPECIES }).value).toBe(PLACEHOLDER_SPECIES);
    expect(encName({ ...sealed, name: PLACEHOLDER_SPOT_NAME }).value).toBe(PLACEHOLDER_SPOT_NAME);
  });

  it('reads a note that was empty at sealing as empty once opened, never as locked', () => {
    // The bug this release fixes. A session with no notes, sealed and then
    // unlocked, showed "Note locked" to its owner.
    const openedNoNotes = { payload: { lat: LAT, lng: LNG } };
    expect(encNotes(sealed, openedNoNotes)).toEqual({ state: 'open', value: null });
    expect(encDescription(sealed, openedNoNotes)).toEqual({ state: 'open', value: null });
    expect(encCustomLocationName(sealed, openedNoNotes)).toEqual({ state: 'open', value: null });
  });

  it('reads a species that was empty at sealing as empty, not as the placeholder', () => {
    expect(encSpecies({ ...sealed, species: PLACEHOLDER_SPECIES }, { payload: {} })).toEqual({
      state: 'open',
      value: '',
    });
  });

  it('leaves nullable free text as null', () => {
    // A sealed row's notes column is genuinely null. Inventing a placeholder
    // would make "encrypted" and "the user wrote nothing" look identical.
    expect(encNotes(sealed).value).toBeNull();
    expect(encDescription(sealed).value).toBeNull();
    expect(encCustomLocationName(sealed).value).toBeNull();
  });
});

describe('encLocation', () => {
  it('passes a plaintext row through exactly', () => {
    const loc = encLocation({ encVersion: null, latitude: LAT, longitude: LNG });
    expect(exactCoords(loc)).toEqual({ lat: LAT, lng: LNG });
  });

  it('gives no exact coordinates for a locked row', () => {
    // The whole point. The plaintext columns hold a centroid ~20km away.
    expect(exactCoords(encLocation(sealedWithCentroid))).toBeNull();
    expect(exactCoords(encLocation(sealedEventRow))).toBeNull();
  });

  it('returns the real position once open', () => {
    const loc = encLocation(sealedWithCentroid, { lat: LAT, lng: LNG });
    expect(loc.state).toBe('open');
    expect(exactCoords(loc)).toEqual({ lat: LAT, lng: LNG });
  });

  it('treats a sealed row without CELL precision as having no location', () => {
    // buildSealedColumns writes CELL only when a cell was supplied, so its
    // absence means there was never a location, not that one is hidden.
    const loc = encLocation({ ...sealed, locPrecision: null });
    expect(loc.state).toBe('plain');
    expect(hasAnyLocation(loc)).toBe(false);
  });

  it('reports a locked event row as having a location despite null coordinates', () => {
    // FishCatch, DuckShot and UplandBirdShot keep null coordinates even with a
    // cell. Testing lat/lng alone reports "no location" for every locked catch
    // and a map draws nothing where it should draw cells.
    expect(hasAnyLocation(encLocation(sealedEventRow))).toBe(true);
  });

  it('keeps the cell on a failed decrypt', () => {
    const loc = encLocation(sealedWithCentroid, { failed: true });
    expect(loc.state).toBe('failed');
    expect(coarseArea(loc)).not.toBeNull();
  });
});

describe('coarseArea', () => {
  it('contains the true position it is hiding', () => {
    const area = coarseArea(encLocation(sealedEventRow))!;

    expect(LAT).toBeGreaterThanOrEqual(area.bounds.minLat);
    expect(LAT).toBeLessThanOrEqual(area.bounds.maxLat);
    expect(LNG).toBeGreaterThanOrEqual(area.bounds.minLng);
    expect(LNG).toBeLessThanOrEqual(area.bounds.maxLng);
  });

  it('is a box, not a radius', () => {
    // A cell's width in metres shrinks toward the poles. A radius chosen to look
    // right at one latitude understates the cell at another.
    const area = coarseArea(encLocation(sealedWithCentroid))!;
    expect(area.bounds.maxLat - area.bounds.minLat).toBeGreaterThan(0);
    expect(area.bounds.maxLng - area.bounds.minLng).toBeGreaterThan(0);
  });

  it('gives nothing for an exact location', () => {
    // Drawing a 20km box around a known position invents uncertainty.
    expect(coarseArea(encLocation({ encVersion: null, latitude: LAT, longitude: LNG }))).toBeNull();
    expect(coarseArea(encLocation(sealedWithCentroid, { lat: LAT, lng: LNG }))).toBeNull();
  });
});

describe('tallySpecies', () => {
  const countOf = (row: { count?: number }) => row.count ?? 0;
  const plainCatch = (id: string, species: string, count: number) => ({
    id,
    species,
    count,
    encVersion: null,
  });
  const sealedCatch = (id: string, count: number) => ({
    id,
    species: PLACEHOLDER_SPECIES,
    count,
    encVersion: 1,
    encBlob: 'blob',
  });

  it('never counts the placeholder as a species', () => {
    const tally = tallySpecies([sealedCatch('a', 41)], countOf);
    expect(tally.entries).toEqual([]);
    expect(JSON.stringify(tally)).not.toContain(PLACEHOLDER_SPECIES);
  });

  it('counts the fish anyway, because counts are never encrypted', () => {
    const tally = tallySpecies([sealedCatch('a', 41)], countOf);
    expect(tally.lockedCount).toBe(41);
    expect(tally.total).toBe(41);
  });

  it('merges a decrypted species into an existing plaintext one', () => {
    const opened = new Map([['b', { payload: { sp: 'Brown trout' } }]]);
    const tally = tallySpecies([plainCatch('a', 'Brown trout', 3), sealedCatch('b', 5)], countOf, opened);
    expect(tally.entries).toEqual([['Brown trout', 8]]);
  });

  it('separates a record that would not open from one not yet tried', () => {
    const opened = new Map([['a', { failed: true }]]);
    const tally = tallySpecies([sealedCatch('a', 2), sealedCatch('b', 3)], countOf, opened);
    expect(tally.failedCount).toBe(2);
    expect(tally.lockedCount).toBe(3);
    expect(tally.total).toBe(5);
  });

  it('never falls back to the species column for a sealed row', () => {
    // Opened with no species: the catch was logged without one. It is named
    // "Unknown", exactly as a plaintext catch with no species is -- and never
    // "Encrypted", which is what the column holds.
    const opened = new Map([['a', { payload: {} }]]);
    const tally = tallySpecies([sealedCatch('a', 7)], countOf, opened);
    expect(tally.entries).toEqual([['Unknown', 7]]);
    expect(tally.lockedCount).toBe(0);
    expect(JSON.stringify(tally)).not.toContain(PLACEHOLDER_SPECIES);
  });

  it('still counts a sealed row as locked when it has not been opened', () => {
    const tally = tallySpecies([sealedCatch('a', 7)], countOf, new Map());
    expect(tally.lockedCount).toBe(7);
    expect(tally.entries).toEqual([]);
  });

  it('counts the bag, not the shots taken at it', () => {
    const shots = [
      { id: 'a', species: 'Mallard', killed: true, encVersion: null },
      { id: 'b', species: 'Mallard', killed: false, encVersion: null },
    ];
    const tally = tallySpecies(shots, (s) => (s.killed === true ? 1 : 0));
    expect(tally.entries).toEqual([['Mallard', 1]]);
  });

  it('does not count a missed shot as locked', () => {
    // Counting it would inflate the locked number past the bag.
    const shots = [
      { id: 'a', species: PLACEHOLDER_SPECIES, killed: false, encVersion: 1, encBlob: 'b' },
    ];
    expect(tallySpecies(shots, (s) => (s.killed === true ? 1 : 0)).lockedCount).toBe(0);
  });

  it('sorts by count, most first', () => {
    const tally = tallySpecies(
      [plainCatch('a', 'Cutthroat', 1), plainCatch('b', 'Brown trout', 9)],
      countOf,
    );
    expect(tally.entries[0]).toEqual(['Brown trout', 9]);
  });
});

describe('hasHiddenSpecies', () => {
  it('covers both locked and unreadable', () => {
    expect(hasHiddenSpecies({ entries: [], lockedCount: 1, failedCount: 0, total: 1 })).toBe(true);
    expect(hasHiddenSpecies({ entries: [], lockedCount: 0, failedCount: 1, total: 1 })).toBe(true);
    expect(hasHiddenSpecies({ entries: [['a', 1]], lockedCount: 0, failedCount: 0, total: 1 })).toBe(false);
  });
});

describe('the read entry carries no crypto', () => {
  it('exports no seal, open or wrap', async () => {
    // Same reasoning as the root entry. A client importing this to decide what
    // renders locked must not drag key handling in with it.
    const read = await import('../read');
    for (const name of ['sealRecord', 'openRecord', 'wrapDataKey', 'unwrapDataKey']) {
      expect(read).not.toHaveProperty(name);
    }
  });
});
