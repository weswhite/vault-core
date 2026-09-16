# Waterlands vault wire format

This document is the contract. The TypeScript is one implementation of it.

Three codebases depend on these bytes agreeing: the Waterlands backend (Node), the
web app (WASM in a browser worker), and the React Native app (JSI on Hermes). They
ship separately and update on different schedules, so the format has to be exact
enough that two of them can be written months apart and still interoperate.

## The rule that governs everything else

**A version is a data format, not a software version.**

Once a single record exists in production sealed as `v1`, every future build must
be able to open `v1`. Forever. You may stop *writing* a version. You may never
stop *reading* one.

This is not a style preference. A user's catch log is sealed to a key only they
hold. If a release drops support for an old version, that user's data is gone and
nobody can recover it, including us. Deleting an `open()` branch is equivalent to
deleting their data.

Practical consequences:

- New fields go in a new version, added alongside the old one.
- Never "fix" a released test vector. Add a vector for the new version.
- Parameters that affect the output bytes (Argon2 cost, padding buckets, HKDF
  info strings, the AAD separator) are frozen per version.
- `testvectors/` is append-only after a version ships.

## Record format: `WLV1`

One record holds every encrypted field for one database row. One row, one blob,
one `open()` call.

Stored and transported as base64url text, not binary. The backend has no `Bytes`
columns and JSON APIs carry this to both clients.

```
offset  size  field
0       4     magic       "WLV1" (0x57 0x4C 0x56 0x31)
4       1     version     1
5       1     suite       1 = X25519 + HKDF-SHA256 + XChaCha20-Poly1305
6       1     flags       bit0 = padded, bits 1..7 reserved, must be 0
7       1     padBucket   index into PAD_BUCKETS, 0xFF when unpadded
8       32    epk         ephemeral X25519 public key
40      N     body        ciphertext || 16-byte Poly1305 tag
```

Minimum length is 57 bytes: 40 header + 1 plaintext + 16 tag.

### Key schedule

```
shared = X25519(esk, recipientPub)
prk    = HKDF-Extract(salt = epk || recipientPub, ikm = shared)
key    = HKDF-Expand(prk, "wlv1-key",   32)
nonce  = HKDF-Expand(prk, "wlv1-nonce", 24)
```

The ephemeral keypair is fresh per record, so `prk` is unique per record and
nonce reuse is structurally impossible rather than merely avoided. This matters
because the alternative, a counter, requires coordinated state across three
clients that write offline.

Including `recipientPub` in the HKDF salt binds the record to the intended
recipient key. Without it, a record could be replayed against a different key.

### This is not libsodium's `crypto_box_seal`

It looks similar and it is not compatible. `crypto_box_seal` derives its nonce as
`blake2b(epk || rpk)` and has **no AAD parameter at all**. We need AAD to bind a
record to its row, so the construction is HPKE-shaped instead.

Anyone implementing from the name rather than from this document will produce
blobs that do not open. Say so in code comments at every call site.

### Additional authenticated data

AAD is authenticated but never stored. It is reconstructed at open time from the
row being opened, which is what makes a blob unusable anywhere except the row it
was sealed for.

```
aad = header[0..8] || "wlv1" 0x1F userId 0x1F table 0x1F recordKey 0x1F fieldGroup 0x1F encVersion
```

`0x1F` is ASCII Unit Separator. It is not valid in any of the field values, so the
concatenation is unambiguous without length prefixes.

Authenticating `header[0..8]` covers `version`, `suite`, `flags` and `padBucket`,
which prevents an attacker downgrading the suite or stripping the padding flag.

The five fields each rule out a specific attack:

| Field | Prevents |
|---|---|
| `userId` | moving a record between accounts |
| `table` | moving a spot blob onto a catch row; cuids are not unique across tables by contract |
| `recordKey` | moving a record between rows in the same table |
| `fieldGroup` | pasting a notes blob into a location column |
| `encVersion` | rolling a row back to an older sealed value |

**`recordKey` must be known to the client at seal time.** Prisma `@default(cuid())`
assigns ids server-side, after the client has already sealed, so a create cannot
use the eventual row id. Either the client supplies the primary key, or the key is
a client-minted field such as `eid`. Do not paper over this by sealing with a
placeholder and re-sealing after insert; that writes a second ciphertext for the
same plaintext and defeats dedup.

### Payload

Plaintext is JSON with deterministic key order and short keys, to keep records
small and to make the padded sizes predictable.

```
lat  number   exact latitude
lng  number   exact longitude
sp   string   species
nm   string   name          (Spot)
ds   string   description   (Spot)
nt   string   notes
cln  string   customLocationName (FishingSession)
```

Absent fields are omitted, not null. A record only carries the groups the user
chose to encrypt.

### Padding

Ciphertext length leaks plaintext length. With a small vocabulary, "Brown trout"
and "Cutthroat" are distinguishable by size alone, and across a whole log the
distribution identifies the species without any decryption.

So the plaintext is length-prefixed and zero-filled to a bucket:

```
padded = uint16BE(len) || plaintext || 0x00 * (bucket - 2 - len)
PAD_BUCKETS = [64, 128, 256, 512, 1024, 2048, 4096]
```

Chosen bucket is the smallest that fits `2 + len`. Above 4096 the record is
written unpadded with `flags.bit0 = 0` and `padBucket = 0xFF`; a note that long is
already unusual enough to stand out, and truncating user data is worse.

Unpad reads the length prefix and ignores the remainder. It must verify the
remainder is all zero, so a modified-but-authenticated payload cannot smuggle data
past a naive reader.

## Wrap format: `WLW1`

Wraps the 32-byte data key under a key derived from a human secret. Two exist per
user: one under the PIN (device-local, never uploaded) and one under the recovery
code (the only one stored server-side).

```
offset  size  field
0       4     magic     "WLW1"
4       1     version   1
5       1     kdf       1 = Argon2id
6       1     wrapType  1 = PIN, 2 = recovery code
7       1     reserved  0
8       4     memKiB    uint32BE, Argon2 memory cost
12      1     timeCost  Argon2 iterations
13      1     lanes     Argon2 parallelism
14      2     reserved  0
16      16    salt
32      24    nonce
56      48    body      32-byte data key ciphertext || 16-byte tag
```

Total 104 bytes.

**Argon2 parameters live in the blob, not in the code.** A low-end Android and a
browser running WASM cannot afford the same cost, and a user must be able to
enroll on a weak device and still open their vault on a strong one. Reading the
parameters from the blob is what allows that. It also allows raising costs later
for new enrollments without invalidating existing vaults.

Wrap AAD:

```
aad = header[0..16] || "wlw1" 0x1F userId 0x1F wrapType 0x1F keyVersion 0x1F vaultPubKeyFp
```

Binding `vaultPubKeyFp` is what makes a server key substitution detectable on a
*fresh* device, where there is no locally pinned key to compare against. Without
it, a server could hand a new device its own public key and read everything
written afterwards.

## Key derivation from the data key

The X25519 keypair is **derived from the data key**, not stored wrapped
alongside it:

```
sk = clamp(HKDF-SHA256(ikm = DK, salt = "", info = "wlv1-x25519-v1", len = 32))
pk = X25519_base(sk)
```

If the private key were stored under its own wrap, a user holding only the
recovery code would recover the data key and still be unable to open a single
record. Deriving it means the recovery code alone is sufficient, which is the
entire point of having one.

`clamp` is the standard X25519 clamping: clear bits 0,1,2 of the first byte, clear
bit 7 and set bit 6 of the last.

Fingerprint is `SHA-256(pk)`, full 32 bytes, base64url in APIs.

## Versioning checklist

Adding `v2` means all of:

1. `SUPPORTED_ENVELOPE_VERSIONS` gains `2`; `1` stays.
2. `open()` keeps its `v1` branch untouched.
3. `testvectors/v2.json` is added; `v1.json` is not edited.
4. All three clients ship `v2` read support **before** any client writes `v2`.
5. The backend accepts both in `validateRecordShape`.

Step 4 is the one that gets skipped under deadline pressure. Skipping it means a
user who enrolls on the new mobile build cannot read their own data on the web.
