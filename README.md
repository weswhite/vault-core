# @waterlands/vault-core

Wire format and crypto for the Waterlands vault: client-side encryption of catch
locations, species and notes.

Waterlands is a fishing and hunting conditions app. Some people won't log
honestly, because a catch log is competitive intelligence to a tournament angler
and a spot list is something you don't hand over. The vault lets a user encrypt
the sensitive parts of their own log so we can't read them, while leaving enough
in the clear that the conditions engine still works.

This package is published so that claim is checkable. The security of the scheme
doesn't depend on anyone not reading it.

**[FORMAT.md](./FORMAT.md) is the specification.** The TypeScript here is one
implementation of it.

## What is and isn't encrypted

Encrypted: exact coordinates, species, and location-bearing free text (spot
names, descriptions, notes).

Plaintext: catch counts, timestamps, river and station ids, and a coarse ~20km
geohash cell.

That split is deliberate. The prediction engine is anchored to a station id and
runs on conditions, counts and timing, so it keeps working untouched. What it
never needed was the exact point or the species.

This is **not** end-to-end encryption. Data is encrypted on the client and we
hold a wrapped key we can't open, which is a different and weaker claim. The
honest version: we can tell you fished the Madison on Tuesday and caught four,
and we can't tell you where on it or what they were.

## Install

```sh
npm install @waterlands/vault-core
```

Pin an exact version. Not `^`. A patch that changed an Argon2 parameter or the
canonical JSON encoding would silently break cross-platform reads, and because
the format is append-only it can't be taken back.

## Entry points

```ts
// Pure. No crypto, no WASM, no native bindings. Safe on a server.
import { encodeCell, validateRecordShape, PLACEHOLDER_SPECIES } from '@waterlands/vault-core';

// Client only.
import { sealRecord, openRecord } from '@waterlands/vault-core/crypto';

// What a row MEANS when you cannot open it. Pure, and safe on a server.
import { encSpecies, exactCoords, tallySpecies } from '@waterlands/vault-core/read';

// Cross-platform conformance suite.
import { runVectorSuite } from '@waterlands/vault-core/testvectors';
```

The split matters. The backend and server-side rendering legitimately need the
geohash and cursor helpers. If those only existed at the package root, one
`.server.ts` import would pull a crypto module into a server bundle.

### Why `/read` is here and not in each app

A sealed row's plaintext columns hold placeholders, and deciding what they mean
is knowledge about the format, not about any one app's UI. Two clients working
it out separately is how one of them ends up drawing a map pin on a catch whose
position is supposed to be hidden: the coordinates on a sealed row are real
numbers in a real place, about 20km from the truth, and nothing in a
`{lat, lng}` says so.

So `/read` owns the rules. `locPrecision === 'CELL'` means "has a location and
it is hidden", its absence means "has no location", event-level tables keep null
coordinates even with a cell, and a sealed row's species column must never be
read as a species. `exactCoords()` returns null unless a position is genuinely
exact, which forces every pin and distance calculation to handle the case.

What is NOT here: wording. "Locked", "Could not decrypt" and every other string
a user reads stays in each app, so a copy change never needs a release of this
package.

Unlike the envelope, `/read` is ordinary software and versions like it. A change
there does not imply an envelope version; the format it describes is still
WLV1.

## Usage

```ts
import { generateDataKey, vaultKeypairFromDataKey, sealRecord, openRecord }
  from '@waterlands/vault-core/crypto';

const dataKey = generateDataKey();
const { publicKey, secretKey } = vaultKeypairFromDataKey(dataKey);

// Sealing needs only the public key, which is why a phone can log a catch with
// the vault locked and no network.
const blob = sealRecord({
  payload: { lat: 45.6789, lng: -111.0429, sp: 'Brown trout' },
  recipientPublicKey: publicKey,
  binding: {
    userId: 'usr_123',
    table: 'FishCatch',
    recordKey: 'cat_456',
    fieldGroup: 'all',
  },
});

const payload = openRecord({ blob, secretKey, binding: { /* same binding */ } });
```

The binding is authenticated but never stored. It's rebuilt from the row at open
time, so a blob moved to a different row, table, field or account fails to open
rather than decrypting into the wrong place.

`recordKey` has to be known to the client when it seals. A Prisma
`@default(cuid())` id is assigned server-side after sealing, so a create needs
either a client-supplied primary key or a client-minted field such as `eid`.

## Providers

Argon2id and randomness are injectable, because React Native on Hermes has
neither WebCrypto nor a native Argon2, and a pure-JS implementation at realistic
cost takes seconds on a mid-range phone.

```ts
import { setArgon2Provider, setRandomProvider } from '@waterlands/vault-core/crypto';
```

Node and browsers work with no setup. Mobile injects a native binding at boot.

Argon2 parameters travel inside each wrap blob rather than living in a constant,
so a user can enroll on a weak device and still open their vault on a strong one,
and costs can be raised for new enrollments without invalidating old ones.

## The rule

**A version is a data format, not a software version.**

Once one record exists in production at v1, every future build must open v1.
Forever. You may stop writing a version; you may never stop reading one. A user's
log is sealed to a key only they hold, so dropping support is equivalent to
deleting their data.

In practice: `testvectors/` is append-only after release, a failing vector means
the change is wrong, and new fields go in a new version alongside the old one.

## Development

```sh
npm install
npm test
npm run typecheck
npm run build
```

Vectors are generated once per version and then frozen:

```sh
npx tsx scripts/generate-vectors.ts
```

Every consuming repo runs `runVectorSuite` in CI against its own real provider.
Mobile must not mock the crypto to make it pass, since a mocked run verifies
nothing on the platform that most needs verifying.

## License

MIT
