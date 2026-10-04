# ClearCrypt encrypted archive format V2 (`CFENC002`)

Status: provisional binary specification produced by V2-002 and amended by the V2-003 internal cryptographic review. Approved for implementation within the limits below; independent external review remains required before production-stable publication.

This document defines the byte-level framing proposed for streaming ClearCrypt archives. `CFENC002` is distinct from `CFENC001`; a V1 reader must reject it and a V2 reader must not reinterpret a V1 archive.

## Conventions

- Offsets are zero-based.
- `u8`, `u32be` and `u64be` are unsigned integers encoded in network byte order.
- All sizes are bytes unless another unit is written explicitly.
- `u64be` values are handled as `bigint` in JavaScript.
- `||` denotes byte concatenation.
- AES-GCM ciphertext has the same length as its plaintext.
- Every AES-GCM operation uses a 128-bit authentication tag.
- A reader treats every archive field as untrusted until it has been structurally and cryptographically validated.

## Goals of the framing

The format must allow a writer and a reader to keep a bounded amount of data in memory. Each data record is authenticated independently, while a mandatory final record authenticates the completeness of the archive.

The framing must detect alteration, removal, duplication, reordering, cross-archive substitution, truncation and bytes appended after the final record. A data record may be delivered only after its own tag succeeds; the complete output may be accepted only after the final record succeeds.

## Complete archive layout

```text
fixed header, 122 bytes
zero or more DATA records
exactly one FINAL record, 33 bytes
end of archive
```

The minimum structurally valid archive is 155 bytes: a 122-byte header followed by the 33-byte final record for an empty plaintext.

No padding, trailer or extension bytes are allowed after `FINAL` in format version 2.

## Fixed header

The V2 header is exactly 122 bytes.

| Offset | Size | Encoding | Field | V2 value or meaning |
| ---: | ---: | --- | --- | --- |
| 0 | 8 | bytes | magic | ASCII `CFENC002`, hex `4346454e43303032` |
| 8 | 1 | `u8` | version | `0x02` |
| 9 | 1 | `u8` | content cipher ID | `0x01` = AES-256-GCM by records |
| 10 | 1 | `u8` | content key schedule ID | `0x01` = HKDF-SHA-256 segmented keys |
| 11 | 4 | `u32be` | chunk size | maximum plaintext bytes in one DATA record |
| 15 | 16 | bytes | archive ID | random identifier and HKDF salt for this archive |
| 31 | 4 | bytes | content nonce prefix | fixed 32-bit field for content nonces |
| 35 | 1 | `u8` | password KDF ID | `0x01` = Argon2id |
| 36 | 16 | bytes | password salt | Argon2id salt |
| 52 | 4 | `u32be` | time cost | Argon2id iteration count |
| 56 | 4 | `u32be` | memory cost | Argon2id memory in KiB |
| 60 | 1 | `u8` | parallelism | Argon2id lanes |
| 61 | 1 | `u8` | archive-key wrap cipher ID | `0x01` = AES-256-GCM |
| 62 | 12 | bytes | wrap nonce | nonce used to wrap the archive master key |
| 74 | 32 | bytes | wrapped archive-key ciphertext | encrypted 32-byte archive master key |
| 106 | 16 | bytes | wrapped archive-key tag | 128-bit AES-GCM tag |

The exact byte range `[0, 74)` is called `wrapAad`. The exact byte range `[0, 122)` is called `archiveAad`.

V2 has a fixed header and no extension-length field. A future incompatible header requires another format version. This keeps the first streaming parser small and prevents ambiguous extension handling.

## Algorithm identifiers

| Registry | ID | Algorithm |
| --- | ---: | --- |
| content cipher | `0x01` | AES-256-GCM, independent invocation per record, 128-bit tag |
| content key schedule | `0x01` | HKDF-SHA-256 segmented keys and distinct FINAL key |
| password KDF | `0x01` | Argon2id version 1.3 (`0x13`, decimal 19) |
| archive-key wrap cipher | `0x01` | AES-256-GCM, 128-bit tag |

A reader must reject an unknown version or algorithm identifier before deriving a key or decrypting content. It must not guess a replacement algorithm.

## Chunk-size rules

The encoded chunk size must:

- be at least 65,536 bytes (64 KiB);
- be at most 16,777,216 bytes (16 MiB);
- be a power of two.

The default writer value is 4,194,304 bytes (4 MiB). The allowed range includes 1, 4 and 8 MiB for qualification benchmarks while keeping every record allocation bounded.

A reader validates the key schedule and chunk size immediately after reading the first 15 header bytes and before allocating a DATA-record buffer.

## Password and KEK derivation

Password handling is identical to the ClearCrypt V1 public policy:

- a string is encoded directly as UTF-8;
- a `Uint8Array` is used byte-for-byte;
- no trimming, case conversion or Unicode normalization is applied;
- the public API accepts 1 through 1,024 password bytes.

Derive a 32-byte key-encryption key (KEK) with Argon2id using the salt and cost fields from the header. V2 retains these semantic bounds:

| Parameter | Minimum | Maximum |
| --- | ---: | ---: |
| time cost | 1 | 10 |
| memory cost | 8,192 KiB | 262,144 KiB |
| parallelism | 1 | 16 |

The reader must validate the semantic bounds and its local resource policy before running Argon2id. The encoded parameters describe the archive; they do not require a reader to exceed its configured resource policy.

## Archive master key generation and wrapping

The writer generates these values independently with a cryptographically secure random generator for every new archive:

- 16-byte archive ID;
- 4-byte content nonce prefix;
- 16-byte Argon2id salt;
- 12-byte wrapping nonce;
- 32-byte archive master key (AMK).

The AMK never encrypts a DATA or FINAL record directly. It is input keying material for the segmented content-key schedule.

After serializing bytes `[0, 74)`, wrap the AMK as follows:

```text
wrappedCombined = AES-256-GCM-ENCRYPT(
  key       = KEK,
  nonce     = wrapNonce,
  plaintext = AMK,
  AAD       = wrapAad,       // exact header bytes [0, 74)
  tagLength = 16 bytes
)

wrappedArchiveKeyCiphertext = wrappedCombined[0, 32)
wrappedArchiveKeyTag        = wrappedCombined[32, 48)
archiveAad = wrapAad || wrappedArchiveKeyCiphertext || wrappedArchiveKeyTag
```

Binding the header prefix to the AMK wrap prevents changing its algorithms, key schedule, KDF parameters, archive ID, nonce prefix or chunk size while retaining a valid wrapped key.

The writer must not reuse an AMK for another archive or another attempt to create the same archive. Restarting an interrupted encryption creates fresh random values and starts a new archive.

## Segmented content-key schedule

The content key schedule uses HKDF-SHA-256 as specified by RFC 5869. The segment size is fixed at 1 GiB (`2^30` plaintext bytes). Every permitted chunk size divides the segment size exactly.

For the chunk size declared in the header:

```text
recordsPerSegment = 2^30 / chunkSize
segmentNumber(recordNumber) = floor(recordNumber / recordsPerSegment)
localRecordNumber(recordNumber) = recordNumber mod recordsPerSegment
```

Derive one 32-byte AES key per segment:

```text
segmentKey(segmentNumber) = HKDF-SHA-256(
  IKM  = AMK,
  salt = archiveId,
  info = ASCII("ClearCrypt/CFENC002/segment-key") || u64be(segmentNumber),
  L    = 32
)
```

Derive a distinct 32-byte key for FINAL:

```text
finalKey = HKDF-SHA-256(
  IKM  = AMK,
  salt = archiveId,
  info = ASCII("ClearCrypt/CFENC002/final-key"),
  L    = 32
)
```

The two exact ASCII labels are protocol constants. Their different values provide domain separation between DATA segment keys and the FINAL key. The segment number provides separation between DATA segment keys.

An implementation derives keys on demand, retains only a bounded number of them and wipes a package-owned segment-key buffer when it is no longer required. Every non-empty archive smaller than 1 GiB uses `segmentKey(0)`; an empty archive derives only `finalKey`. The AMK is never used directly with AES-GCM content records.

## Content nonce construction

Every DATA authentication operation uses a 96-bit nonce:

```text
dataNonce(recordNumber) =
  contentNoncePrefix || u64be(localRecordNumber(recordNumber))
```

The 32-bit prefix remains fixed for the archive. The 64-bit local record number is the invocation field and must never repeat under the same segment key. It restarts at zero only after the segment key changes.

FINAL uses its separately derived key and this nonce:

```text
finalNonce = contentNoncePrefix || u64be(0)
```

Reusing the numeric nonce value for DATA segment 0 and FINAL is safe only because their keys are distinct HKDF outputs. The AAD also carries distinct record types.

This nonce construction follows the 96-bit deterministic GCM layout with a 32-bit fixed field and a 64-bit invocation field described by NIST SP 800-38D. The amended V2-003 internal review accepts it within the normative limits below. Independent external review remains required.

## DATA record

A DATA record has a 13-byte clear record header, a variable-length ciphertext and a 16-byte tag.

| Relative offset | Size | Encoding | Field | Meaning |
| ---: | ---: | --- | --- | --- |
| 0 | 1 | `u8` | record type | `0x01` = DATA |
| 1 | 8 | `u64be` | record number | zero-based sequential index |
| 9 | 4 | `u32be` | plaintext length | ciphertext length for this record |
| 13 | `plaintext length` | bytes | ciphertext | encrypted plaintext chunk |
| `13 + plaintext length` | 16 | bytes | tag | 128-bit AES-GCM tag |

The total encoded size is `29 + plaintext length` bytes.

The plaintext length must be between 1 and the header's chunk size, inclusive. Empty DATA records are invalid.

All DATA records except the final DATA record must have exactly `chunkSize` plaintext bytes. Once a reader observes a short DATA record, the next record must be FINAL.

For the exact 13-byte DATA header `dataRecordHeader`, encrypt as follows:

```text
dataCombined = AES-256-GCM-ENCRYPT(
  key       = segmentKey(segmentNumber(recordNumber)),
  nonce     = dataNonce(recordNumber),
  plaintext = plaintextChunk,
  AAD       = archiveAad || dataRecordHeader,
  tagLength = 16 bytes
)
```

The ciphertext and tag are stored separately in the record. The clear record header is authenticated through AAD.

## FINAL record

Every archive contains exactly one FINAL record. It has no ciphertext and authenticates the totals accumulated by the writer.

| Relative offset | Size | Encoding | Field | Meaning |
| ---: | ---: | --- | --- | --- |
| 0 | 1 | `u8` | record type | `0x02` = FINAL |
| 1 | 8 | `u64be` | data-record count | number of preceding DATA records |
| 9 | 8 | `u64be` | total plaintext length | sum of all DATA plaintext lengths |
| 17 | 16 | bytes | tag | AES-GCM tag over empty plaintext and the FINAL AAD |

The FINAL record is always 33 bytes. It uses the separately derived `finalKey`; its clear data-record count remains the global number of DATA records.

For the exact 17-byte clear FINAL header `finalRecordHeader`, compute:

```text
finalCombined = AES-256-GCM-ENCRYPT(
  key       = finalKey,
  nonce     = finalNonce,
  plaintext = empty byte string,
  AAD       = archiveAad || finalRecordHeader,
  tagLength = 16 bytes
)

finalTag = finalCombined
```

A reader accepts FINAL only when:

- its data-record count equals the next expected DATA index;
- its total length equals the checked sum of authenticated DATA lengths;
- its tag succeeds;
- the source then reaches end-of-stream without another byte.

For an empty plaintext, `dataRecordCount` and `totalPlaintextLength` are zero. FINAL uses `finalKey` and `finalNonce`; no DATA record is emitted.

## Writer procedure

1. Validate the password, KDF options and chunk size.
2. Generate the archive ID, nonce prefix, salt, wrapping nonce and AMK independently.
3. Serialize `wrapAad`.
4. Derive the KEK once with Argon2id.
5. Wrap the AMK using `wrapAad` and serialize the complete 122-byte header.
6. Read the source progressively, filling at most one bounded plaintext chunk plus bounded pipeline buffers.
7. Derive the current segment key on demand. For each non-empty chunk, serialize its DATA header, encrypt it with the derived segment key and local record nonce, then write the complete record under destination backpressure.
8. Maintain checked `bigint` totals for the DATA count and plaintext length.
9. Derive `finalKey`, then serialize and authenticate FINAL with `finalNonce`.
10. Write FINAL and close the destination.
11. Wipe package-owned KEK, AMK, derived keys and plaintext temporary buffers on every exit path where possible.

The writer must not emit a short DATA record until it has observed source end-of-stream. It must not prefetch an unbounded number of chunks.

## Reader procedure

1. Read exactly 122 header bytes incrementally.
2. Check magic, version and algorithm identifiers.
3. Validate the content key schedule, chunk size and KDF semantic bounds.
4. Apply the local resource policy before Argon2id.
5. Derive the KEK once and authenticate the wrapped AMK with exact `wrapAad`.
6. Initialize expected record number and checked total plaintext length to zero.
7. Read one record type byte.
8. For DATA, read the remaining 12 header bytes, validate the exact expected index and length, then read only that ciphertext and its 16-byte tag.
9. Derive the expected segment key from the global record number and authenticate the complete DATA record before writing its plaintext to the destination.
10. Reject another DATA record after a short DATA record.
11. For FINAL, read its remaining 32 bytes, validate its clear totals, derive `finalKey`, authenticate its tag and require immediate end-of-stream.
12. Return success only after FINAL and destination finalization succeed.

If the source ends before FINAL, the reader reports an invalid truncated archive even when every preceding DATA tag was valid.

## Structural and semantic limits

| Quantity | Structural encoding | V2 parsing rule |
| --- | --- | --- |
| header | fixed 122 bytes | exactly 122 bytes |
| DATA plaintext | `u32be` | 1 through validated chunk size |
| DATA encoded size | derived | at most 16 MiB + 29 bytes |
| data-record count | `u64be` | sequential, no repetition or overflow |
| total plaintext length | `u64be` | checked sum, no overflow |
| FINAL | fixed 33 bytes | exactly one, then EOF |

The binary representation can express up to `2^64 - 1` plaintext bytes and record numbers. These are structural capacities, not permission to process that amount of data.

V2 uses a 1 GiB per-key segment limit and these global normative limits:

| Limit | Value |
| --- | ---: |
| segment plaintext size | `2^30` bytes = 1 GiB |
| maximum DATA invocations per segment key | `2^14` = 16,384, reached with 64 KiB chunks |
| maximum plaintext length | `2^50` bytes = 1 PiB |
| maximum segments | `2^20` = 1,048,576 |
| maximum DATA records | `2^34`, reached with 64 KiB chunks |
| FINAL-key invocations | exactly one |

With the default 4 MiB chunk size, each full segment contains 256 DATA records. An archive of 100 GB decimal uses 94 segment keys; 100 GiB uses exactly 100. The 1 PiB global limit is a finite protocol and implementation bound, not a recommended routine archive size or a storage guarantee.

Writers enforce both byte and record limits before the corresponding AES-GCM call. Readers reject a record number or cumulative length beyond either limit before decrypting or writing that record.

## Overhead

For plaintext length `P > 0`, chunk size `S`, and `n = ceil(P / S)` DATA records:

```text
archiveLength = P + 122 + (29 × n) + 33
              = P + 155 + (29 × n)
```

For an empty plaintext, the archive is 155 bytes.

At the default 4 MiB chunk size, DATA framing adds 29 bytes per chunk, approximately 0.00069%, plus the fixed 155 bytes. Segment transitions add no archive bytes. This calculation excludes storage-layer framing outside ClearCrypt.

## Failure conditions

A reader must fail without reporting a complete valid output when any of these occurs:

- wrong magic, version or algorithm identifier;
- truncated header or record;
- invalid chunk size or KDF parameter;
- KDF parameters exceeding local policy;
- wrapped archive-key authentication failure;
- unknown record type;
- DATA index different from the expected index;
- zero or excessive DATA length;
- DATA after a short DATA record;
- DATA or FINAL authentication failure;
- inconsistent record count or total plaintext length;
- absent or duplicate FINAL;
- any byte after FINAL;
- counter, cumulative length or configured V2 limit exceeded.

Wrong passwords and authenticated alterations should share a public authentication-failure result where they reach the same cryptographic boundary. Structural, unsupported-format and resource-policy failures may remain distinct as in V1.

Plaintext from already authenticated DATA records may have reached a temporary destination before a later failure. The operation as a whole remains failed and the caller must not publish that destination.

## Compatibility and format detection

The first eight bytes identify the format:

| Magic | Format | Processing model |
| --- | --- | --- |
| `CFENC001` | V1 | complete input and output buffers |
| `CFENC002` | V2 | authenticated records and streaming API |

A detector may inspect the magic without a password. Detection does not authenticate the archive and must not be reported as proof that the file is valid.

Encryption chooses a format explicitly. `encryptBytesV1` continues to write `CFENC001`; `encryptStreamV2` writes `CFENC002`. No existing V1 API silently changes its output format.

## Cryptographic review status

The V2-003 internal review accepted:

- a fresh AMK restricted to one archive attempt and never used directly for content encryption;
- HKDF-SHA-256 keys derived for each 1 GiB segment and a separately labelled FINAL key;
- `contentNoncePrefix || u64be(localRecordNumber)` under each segment key;
- `wrapAad` for AMK wrapping;
- `archiveAad || recordHeader` for DATA and FINAL;
- the empty-plaintext AES-GCM operation used for FINAL;
- the 1 GiB per-segment and provisional 1 PiB global limits;
- independent generation of the archive ID, nonce prefix, salt, wrap nonce and AMK.

See [the complete internal review](crypto-review-v2.md). An independent external review and a check against the final NIST SP 800-38D revision remain release gates. Any later amendment that changes serialized bytes requires new vectors and a format review.

## References

- [NIST SP 800-38D, Galois/Counter Mode](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf): authenticated encryption, 96-bit IV recommendation, uniqueness requirements and deterministic IV construction.
- [RFC 5869, HKDF](https://www.rfc-editor.org/rfc/rfc5869.html): extract-and-expand key derivation and context binding through `info`.
- [Web Cryptography Level 2, HKDF](https://www.w3.org/TR/webcrypto/#hkdf): browser-facing HKDF operation.
- [Web Cryptography Level 2, AES-GCM](https://www.w3.org/TR/webcrypto/#aes-gcm): browser-facing AES-GCM operation and validation rules.
- [ClearCrypt V1 format](format-v1.md): existing password, KDF and compatibility rules.
- [ClearCrypt v2 streaming API decision](design-v2-streaming-api.md): source/destination lifecycle, backpressure and scope.
- [ClearCrypt V2 cryptographic construction review](crypto-review-v2.md): accepted construction, usage limits and remaining release gates.

