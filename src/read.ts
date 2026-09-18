/**
 * Reading sealed rows: the interpretation layer.
 *
 * Separate from `.` and from `./crypto` because it is a different kind of
 * thing. The root entry is the format; `./crypto` performs it; this decides
 * what a row MEANS when you cannot open it, which is knowledge every client
 * needs and none of them should work out alone.
 *
 * It holds no strings a user reads. Wording stays in each app, so a copy change
 * never needs a release of this package.
 *
 * Unlike the envelope, this layer is ordinary software and versions like it.
 * A change here does not imply an envelope version: the format it describes is
 * still WLV1.
 */

export {
  type Enc,
  type EncState,
  type OpenedField,
  type SealedColumns,
  encField,
  isLocked,
  isSealed,
  plain,
  realValue,
} from './read/enc';

export {
  type CoarseArea,
  type Coords,
  type EncLocation,
  type RowLocation,
  coarseArea,
  encLocation,
  exactCoords,
  hasAnyLocation,
} from './read/location';

export {
  type NamedRow,
  type OpenedRecord,
  type SpeciesRow,
  type TextRow,
  encCoords,
  encCustomLocationName,
  encDescription,
  encName,
  encNotes,
  encSpecies,
} from './read/payload';

export {
  EMPTY_TALLY,
  type SpeciesRowInput,
  type SpeciesTally,
  hasHiddenSpecies,
  tallySpecies,
} from './read/species';
