/**
 * `Enc<T>`: a field that may or may not be readable right now.
 *
 * This is the read side of the format. A sealed row's plaintext columns hold
 * placeholders, and knowing which columns hold what, and when a placeholder is
 * safe to show, is knowledge about WLV1 rather than about any one app's UI. Two
 * clients working it out separately is how one of them ends up drawing a pin on
 * a catch whose position is supposed to be hidden.
 *
 * What is NOT here: wording. "Locked", "Could not decrypt" and every other
 * string a user reads belongs to the app, so a copy change never needs a release
 * of this package.
 *
 * The governing rule: `value` is always renderable. A component that knows
 * nothing about the vault and prints `field.value` shows the placeholder, not
 * `undefined`, not a crash, not a blank row.
 */

export type EncState =
  /** Never encrypted. Logged before enrollment, or while a subscription lapsed. */
  | 'plain'
  /** Sealed, and this client has not opened it. `value` is a placeholder. */
  | 'locked'
  /** Sealed and decrypted. `value` is what the user recorded. */
  | 'open'
  /** Sealed, and the record would not open. `value` is a placeholder. */
  | 'failed';

export interface Enc<T> {
  state: EncState;
  /** Always renderable. A placeholder when state is locked or failed. */
  value: T;
}

/** The sealed columns every sealable table shares. */
export interface SealedColumns {
  encVersion?: number | null;
  encBlob?: string | null;
  encKeyVersion?: number | null;
  geohash4?: string | null;
  hasLocation?: boolean | null;
  locPrecision?: string | null;
}

/**
 * `encVersion` is the single source of truth for "is this row encrypted".
 * The server writes every sealed column together or none of them.
 */
export function isSealed(row: SealedColumns | null | undefined): boolean {
  return row?.encVersion != null;
}

/** True when `value` is a stand-in rather than what the user recorded. */
export function isLocked<T>(field: Enc<T>): boolean {
  return field.state === 'locked' || field.state === 'failed';
}

/**
 * The real value, or null.
 *
 * For anything that is not display: a search index, an export, a comparison, a
 * map pin. Returning null for a locked field is what stops a placeholder being
 * treated as data.
 */
export function realValue<T>(field: Enc<T>): T | null {
  return field.state === 'plain' || field.state === 'open' ? field.value : null;
}

export function plain<T>(value: T): Enc<T> {
  return { state: 'plain', value };
}

/** What a client's decrypt step returns for one row. */
export interface OpenedField<T> {
  value?: T;
  failed?: boolean;
}

/**
 * Build one field from a row and an optional decrypted value.
 *
 * `opened` is undefined when this record has not been decrypted. When it has,
 * `opened.value` is the field's value from the payload -- and undefined there
 * means the field was EMPTY when the row was sealed, because the payload omits
 * null fields rather than writing them.
 *
 * That distinction is the whole difference between "Locked" and nothing. An
 * earlier version treated an absent field in an opened record as still locked,
 * on the theory that a record might carry only some field groups. No sealing
 * path does that: every record is sealed with the ALL group and the server
 * clears every field on a sealed row. So a session with no notes, once sealed,
 * showed "Note locked" to its owner forever, even after unlocking.
 *
 * `failed` marks a record that would not open. It renders as a warning rather
 * than disappearing, because a catch that vanishes reads as lost data.
 *
 * @param empty what an opened record's absent field reads as. Defaults to the
 *   placeholder; nullable text fields pass null.
 */
export function encField<T>(
  row: SealedColumns,
  placeholder: T,
  opened: OpenedField<T> | undefined,
  empty: T = placeholder,
): Enc<T> {
  if (!isSealed(row)) return { state: 'plain', value: placeholder };
  if (opened?.failed) return { state: 'failed', value: placeholder };
  if (opened) return { state: 'open', value: opened.value !== undefined ? opened.value : empty };
  return { state: 'locked', value: placeholder };
}
