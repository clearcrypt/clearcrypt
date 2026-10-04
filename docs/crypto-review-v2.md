# ClearCrypt V2 cryptographic construction review

Date: 4 October 2026. Status: amended internal design review for V2-003. Conditional approval for implementation; independent external review remains required before a production-stable format is published.

## Scope

This review evaluates the construction in [`format-v2.md`](format-v2.md):

- Argon2id-derived KEK and AES-256-GCM archive-key wrapping;
- one fresh 256-bit archive master key (AMK) per archive attempt;
- HKDF-SHA-256 segment-key derivation;
- AES-256-GCM independently applied to every DATA record;
- a separately derived FINAL key;
- 96-bit deterministic nonces;
- exact serialized header and record fields used as AAD;
- per-key and global usage limits.

It does not constitute an independent security audit, a formal proof, certification or review of code. No V2 cryptographic code exists at this stage.

## Review result

The amended construction is internally consistent for implementation with these limits:

1. The AMK never encrypts content directly.
2. Every 1 GiB plaintext segment receives a distinct 256-bit key derived with HKDF-SHA-256.
3. Every non-empty archive begins with segment key zero; an empty archive derives only the separately labelled FINAL key.
4. With the minimum 64 KiB chunk size, one segment key protects at most `2^14` DATA records.
5. The global plaintext limit is 1 PiB (`2^50` bytes), represented and checked with `bigint`.
6. One AMK is used for exactly one archive attempt and is never reused after restart, cancellation or failure.

The 1 GiB segment and 1 PiB global values are conservative engineering limits selected to support archives far beyond the immediate 100 Go use case while keeping each GCM key's data and invocation counts bounded. They are not a claim of a particular formal aggregate security level. An external reviewer must confirm or lower these bounds before the format is declared stable.

## Key hierarchy

```text
password
  └─ Argon2id → KEK
       └─ unwrap → AMK
            ├─ HKDF-SHA-256(segment 0) → DATA key 0
            ├─ HKDF-SHA-256(segment 1) → DATA key 1
            ├─ ...
            └─ HKDF-SHA-256(final) → FINAL key
```

The user supplies one password. Segment keys are deterministic internal values and are not stored in the archive.

Compromise of the password, KEK or AMK compromises every segment. The purpose of segmentation is to bound AES-GCM usage under each derived key, not to protect the archive after its root secret has been compromised.

## HKDF review

V2 uses the full extract-and-expand HKDF construction from RFC 5869 with SHA-256:

```text
segmentKey(i) = HKDF-SHA-256(
  IKM  = AMK,
  salt = archiveId,
  info = ASCII("ClearCrypt/CFENC002/segment-key") || u64be(i),
  L    = 32
)

finalKey = HKDF-SHA-256(
  IKM  = AMK,
  salt = archiveId,
  info = ASCII("ClearCrypt/CFENC002/final-key"),
  L    = 32
)
```

The AMK is uniformly random, the archive ID is independently random and authenticated, and the exact `info` values bind output keys to their protocol role. The fixed labels distinguish DATA from FINAL; the encoded segment number distinguishes every DATA segment.

RFC 5869 describes HKDF as an extract-then-expand construction for deriving one or more strong keys and explains that `info` binds derived material to application-specific context. WebCrypto exposes HKDF with SHA-256 in the browser and Node.js runtimes targeted by ClearCrypt.

An implementation derives a segment key only when it reaches that segment, retains a bounded number of keys and wipes package-owned raw key buffers when possible.

## Nonce review

For global DATA record number `r`:

```text
recordsPerSegment = 2^30 / chunkSize
segmentNumber = floor(r / recordsPerSegment)
localNumber = r mod recordsPerSegment
dataNonce = contentNoncePrefix || u64be(localNumber)
```

This is accepted for implementation because:

- the nonce is exactly 96 bits;
- local record numbers are strictly sequential under a segment key;
- a local number restarts only when the derived key changes;
- at most `2^14` local numbers are used under one segment key;
- the AMK and archive values are fresh for every archive attempt.

FINAL uses a separately derived key and `contentNoncePrefix || u64be(0)`. The numeric nonce may match a DATA nonce because the AES-GCM key is different. The distinct AAD record type adds domain binding but nonce safety relies on the distinct HKDF output key.

NIST SP 800-38D recommends 96-bit IVs and describes a deterministic construction with a fixed field and invocation field. The random prefix is not relied upon for uniqueness under one key; uniqueness comes from the local counter.

## Archive-key wrapping

The password-derived KEK is used only to wrap or unwrap the 32-byte AMK. The AMK is used only as HKDF input keying material.

The archive ID, nonce prefix, Argon2id salt, wrap nonce and AMK are generated independently for every archive attempt. The wrap nonce is a 96-bit random AES-GCM nonce. Implementations must never intentionally recreate an earlier `(KEK, wrapNonce)` pair with different AMK material.

`wrapAad` authenticates magic, version, algorithms, key schedule, chunk size, archive ID, nonce prefix, KDF parameters, wrap algorithm and wrap nonce. Changing any of these fields invalidates the wrapped AMK.

The V1 Argon2id semantic bounds and local resource policy remain applicable. HKDF does not replace Argon2id for passwords; it operates only on the random AMK.

## Record AAD review

DATA uses:

```text
AAD = archiveAad || dataRecordHeader
```

The fixed-size components bind ciphertext to the complete authenticated header, global record number, record type and plaintext length. Moving, duplicating, renumbering or resizing a DATA record makes its authentication fail.

FINAL uses:

```text
AAD = archiveAad || finalRecordHeader
plaintext = empty
```

Its header authenticates global record count and total plaintext length. AES-GCM with empty plaintext and non-empty AAD produces only the tag. Physical end-of-stream is also required after FINAL.

## Usage limits

V2 defines:

```text
SEGMENT_PLAINTEXT_SIZE_V2       = 2^30 bytes = 1 GiB
MAX_DATA_INVOCATIONS_PER_KEY_V2 = 2^14
MAX_PLAINTEXT_LENGTH_V2         = 2^50 bytes = 1 PiB
MAX_SEGMENTS_V2                 = 2^20
MAX_DATA_RECORDS_V2             = 2^34
FINAL_KEY_INVOCATIONS_V2        = 1
```

`MAX_DATA_INVOCATIONS_PER_KEY_V2` is reached only with 64 KiB chunks. A 4 MiB configuration uses 256 invocations per full segment. Every individual AES-GCM plaintext is at most 16 MiB, far below the per-invocation AES-GCM plaintext limit.

At 4 MiB per record, 100 GB decimal uses 23,842 DATA records across 94 segment keys; 100 GiB uses 25,600 records across exactly 100 keys.

The binary counters can structurally represent more than 1 PiB. The smaller global limit bounds implementation time, total derived keys and aggregate cryptographic use. The project must not describe the format as literally unlimited.

## Required enforcement

The writer must:

- reject unknown key schedules and invalid chunk or KDF options before writing the header;
- use checked `bigint` global counters;
- derive the segment and local record numbers from the authoritative global record number;
- never allocate nonce counters speculatively to parallel workers;
- never encrypt or write plaintext beyond 1 PiB;
- derive FINAL with the distinct label and invoke its key exactly once;
- discard an archive attempt after failure rather than resume with the same AMK;
- wipe package-owned KEK, AMK and derived raw keys where possible.

The reader must:

- validate structural and local resource limits before expensive work;
- require every global DATA number to equal the next expected number;
- derive the expected segment key and local nonce from that number;
- reject a DATA length beyond the declared chunk size;
- reject cumulative length beyond 1 PiB before writing the record;
- authenticate FINAL with the distinct final key;
- compare FINAL totals with checked accumulated values;
- require immediate end-of-stream after FINAL.

## Failure and release policy

A failed DATA or FINAL tag is an authentication failure. Wrong password and altered wrapped-key material should remain indistinguishable at the public authentication boundary where practical.

Authenticated earlier DATA records do not make an incomplete archive valid. Applications must keep decryption output temporary until the whole operation succeeds.

Before production-stable publication, the project still requires:

- independent review by a cryptographer or qualified security reviewer;
- confirmation of the 1 GiB per-key and 1 PiB global bounds;
- independent HKDF and archive vectors;
- tests proving key-domain separation and nonce uniqueness at segment transitions;
- mutation tests for every authenticated header and record field;
- tests immediately before and after segment boundaries;
- a review against the then-current NIST SP 800-38D revision status.

## References

- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869.html).
- [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf), especially Sections 5.2 and 8.
- [NIST SP 800-38D Rev. 1 second preliminary call for comments](https://csrc.nist.gov/pubs/sp/800/38/d/r1/2prd), published 1 June 2026.
- [Web Cryptography Level 2: HKDF](https://www.w3.org/TR/webcrypto/#hkdf).
- [Web Cryptography Level 2: AES-GCM](https://www.w3.org/TR/webcrypto/#aes-gcm).
- [ClearCrypt V2 provisional format](format-v2.md).
