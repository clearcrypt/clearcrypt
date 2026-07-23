# ClearCrypt encrypted archive format V1 (`CFENC001`)

Status: normative specification for format version 1.

This document is sufficient to implement a compatible `CFENC001` reader without
the ClearCrypt npm package. `CFENC001` is an in-memory, single-payload format; it
is not a streaming or chunked format.

## Conventions

- Offsets are zero-based from the first archive byte.
- `u8` is one unsigned byte.
- `u32be` is a 32-bit unsigned integer in network byte order (big-endian).
- Hexadecimal byte strings contain no separators.
- Concatenation is written as `||`.
- Sizes in this document are bytes unless explicitly written as KiB.
- AES-GCM ciphertext has the same length as its plaintext.

## Complete binary layout

The fixed prefix and content AAD are exactly 109 bytes. The final 16 bytes of
the archive are always the content authentication tag. Every byte between offset
109 and that tag is content ciphertext.

| Offset | Size | Encoding | Field | V1 value or meaning |
| ---: | ---: | --- | --- | --- |
| 0 | 8 | bytes | magic | ASCII `CFENC001`, hex `4346454e43303031` |
| 8 | 1 | `u8` | version | `0x01` |
| 9 | 1 | `u8` | content cipher ID | `0x01` = AES-256-GCM |
| 10 | 12 | bytes | content nonce | 96-bit AES-GCM nonce |
| 22 | 1 | `u8` | KDF ID | `0x01` = Argon2id |
| 23 | 16 | bytes | salt | Argon2id salt |
| 39 | 4 | `u32be` | time cost | Argon2id iteration count |
| 43 | 4 | `u32be` | memory cost | Argon2id memory in KiB |
| 47 | 1 | `u8` | parallelism | Argon2id lanes |
| 48 | 1 | `u8` | DEK-wrap cipher ID | `0x01` = AES-256-GCM |
| 49 | 12 | bytes | wrap nonce | 96-bit AES-GCM nonce |
| 61 | 32 | bytes | wrapped DEK ciphertext | encrypted 32-byte DEK |
| 93 | 16 | bytes | wrapped DEK tag | 128-bit AES-GCM tag |
| 109 | variable | bytes | content ciphertext | zero or more bytes |
| `archiveLength - 16` | 16 | bytes | content tag | 128-bit AES-GCM tag |

The minimum valid structural length is 125 bytes: 109 bytes of AAD, zero bytes
of ciphertext, and a 16-byte content tag. There is no plaintext-length field.
For an archive of length `N`, the plaintext and ciphertext length is `N - 125`.
Consequently, bytes cannot be appended after the content tag: appended bytes are
interpreted as ciphertext and authentication fails.

## Algorithm identifiers

V1 defines only these identifiers:

| Registry | ID | Algorithm |
| --- | ---: | --- |
| content cipher | `0x01` | AES-256-GCM with a 128-bit tag |
| KDF | `0x01` | Argon2id version 1.3 (`0x13`, decimal 19) |
| DEK-wrap cipher | `0x01` | AES-256-GCM with a 128-bit tag |

A reader MUST reject an unknown version or algorithm identifier. It MUST NOT
guess an algorithm or treat an unknown identifier as the current default. V1
has no extension fields or mechanism for skipping unknown fields.

## Password bytes and KEK derivation

If the caller supplies a string, encode it directly as UTF-8. Do not add a BOM
or terminating NUL. If the caller supplies bytes, use those bytes verbatim.

Implementations MUST NOT silently:

- trim leading or trailing whitespace;
- change letter case;
- apply Unicode NFC, NFD, NFKC, or NFKD normalization;
- otherwise replace or canonicalize code points.

Visually identical Unicode strings can therefore be different passwords. The
ClearCrypt public API accepts 1 through 1,024 password bytes, measured after UTF-8
encoding for strings. This is a product/API policy and is not encoded in
`CFENC001`; low-level format implementations may need to read legacy archives
whose passwords fall outside that policy.

Derive the 32-byte key-encryption key (KEK) with these Argon2 inputs:

| Argon2 input | Value |
| --- | --- |
| variant | Argon2id |
| version | 1.3 / decimal 19 |
| password | exact bytes described above |
| salt | 16-byte archive salt |
| time cost | archive `timeCost` |
| memory cost | archive `memoryCost`, in KiB |
| parallelism | archive `parallelism` |
| output length | 32 bytes |
| secret value | absent |
| associated data | absent |

The raw 32-byte Argon2 output is the KEK. No PHC string, base64 conversion, hash,
or additional derivation is applied.

### V1 KDF bounds

The following are semantic V1 bounds. Although the integer fields can encode
larger ranges, values outside these bounds are invalid V1 parameters.

| Parameter | Minimum | Maximum |
| --- | ---: | ---: |
| time cost | 1 | 10 |
| memory cost | 8,192 KiB | 262,144 KiB |
| parallelism | 1 | 16 |

These bounds describe what the format can represent validly, not what an
application should agree to execute. A reader MUST apply its local resource
policy before starting Argon2id. ClearCrypt's provisional default policy is
128 MiB, 4 passes, and parallelism 4; callers can override it explicitly.

## DEK generation and wrapping

Each archive has an independent, uniformly random 32-byte data-encryption key
(DEK). Production writers MUST generate it with a cryptographically secure random
number generator.

Wrap the DEK as follows:

```text
wrapCombined = AES-256-GCM-ENCRYPT(
  key       = KEK,
  nonce     = wrapNonce,       // 12 bytes
  plaintext = DEK,             // 32 bytes
  AAD       = empty byte string,
  tagLength = 16 bytes
)

wrappedDekCiphertext = wrapCombined[0..31]
wrapTag              = wrapCombined[32..47]
```

The wrap operation uses zero bytes of AAD, not the archive header. The resulting
wrapped ciphertext, nonce, and tag are later included in the content AAD.

## Content AAD and encryption

The content AAD is the exact serialized byte range `[0, 109)`, from the first
magic byte through the last wrapped-DEK tag byte:

```text
AAD = magic
   || version
   || contentCipherId
   || contentNonce
   || kdfId
   || salt
   || u32be(timeCost)
   || u32be(memoryCostKiB)
   || parallelism
   || wrapCipherId
   || wrapNonce
   || wrappedDekCiphertext
   || wrapTag
```

Do not re-encode integers in native endianness and do not authenticate a parsed
object representation. Authenticate these exact 109 serialized bytes.

Encrypt the payload as follows:

```text
contentCombined = AES-256-GCM-ENCRYPT(
  key       = DEK,
  nonce     = contentNonce,    // 12 bytes
  plaintext = plaintext,
  AAD       = AAD,             // exactly 109 bytes
  tagLength = 16 bytes
)

contentCiphertext = contentCombined[0 .. plaintextLength-1]
contentTag        = contentCombined[plaintextLength .. plaintextLength+15]
archive           = AAD || contentCiphertext || contentTag
```

The salt, both nonces, and the DEK MUST be generated independently by the writer.
They are stored or represented exactly as shown; there are no length prefixes.

## Reader procedure

A conforming reader should perform these operations in order:

1. Require at least 125 bytes.
2. Check the eight magic bytes and version.
3. Read the fixed-width fields using the offsets and endianness above.
4. Reject unknown algorithm identifiers and invalid V1 KDF bounds.
5. Treat bytes `[0, 109)` as AAD, bytes `[109, N-16)` as ciphertext, and the
   final 16 bytes as the content tag.
6. Apply the local resource policy before running Argon2id.
7. Derive the KEK from the exact password bytes.
8. Authenticate and decrypt the wrapped DEK with empty AAD.
9. Authenticate and decrypt the content with the exact archive AAD.
10. Return plaintext only after AES-GCM authentication succeeds.

Readers should use views over the archive where possible. V1 still requires the
complete archive and complete plaintext in memory.

## Failure conditions

A reader MUST fail without returning unauthenticated plaintext when any of these
conditions occurs:

- wrong magic, unsupported version, or unknown algorithm identifier;
- truncation of a fixed field or absence of the final 16-byte tag;
- KDF value outside the V1 bounds;
- KDF value exceeding the reader's local resource policy;
- wrapped-DEK authentication failure;
- content authentication failure;
- wrong password or an alteration that passes structural and policy checks but
  fails either AES-GCM authentication step.

Wrong passwords and cryptographic alteration should share one public
authentication-failure result so they are not distinguishable. Structural,
unsupported-format, and resource-policy failures may be reported separately.
Current ClearCrypt V1 reports unknown versions and algorithms as an invalid or
unsupported format; a reader must not attempt cryptography for them.

## Complete annotated example

The normative vector is
[`unicode-password-binary-plaintext.json`](../test/vectors/v1/unicode-password-binary-plaintext.json).
Its exact password contains two leading spaces, `Café` with precomposed `é`, the
`🔐` emoji, a space, `e` followed by combining acute accent U+0301, and two
trailing spaces. Its UTF-8 bytes are:

```text
2020436166c3a9f09f94902065cc812020
```

The complete 150-byte archive is annotated below. Each line is one field.

```text
offset 0   magic                    4346454e43303031
offset 8   version                  01
offset 9   content cipher ID        01
offset 10  content nonce            101112131415161718191a1b
offset 22  KDF ID                   01
offset 23  salt                     000102030405060708090a0b0c0d0e0f
offset 39  time cost                00000001
offset 43  memory cost (8192 KiB)   00002000
offset 47  parallelism              01
offset 48  wrap cipher ID           01
offset 49  wrap nonce               202122232425262728292a2b
offset 61  wrapped DEK ciphertext   49f5fd0d19ca5f608e2adbd47ac71143587732dc3307a54d71a13736b10c7acb
offset 93  wrapped DEK tag          c48b96969cbc2e9f82233a1008fc7c01
offset 109 content ciphertext       9162bf6dcb603bb6d14112a492a09ebdebcb9c07ee4df147a2
offset 134 content tag              7e6adb978edf76d93fd98ddeac95b606
```

Concatenated archive hex:

```text
4346454e433030310101101112131415161718191a1b01000102030405060708090a0b0c0d0e0f00000001000020000101202122232425262728292a2b49f5fd0d19ca5f608e2adbd47ac71143587732dc3307a54d71a13736b10c7acbc48b96969cbc2e9f82233a1008fc7c019162bf6dcb603bb6d14112a492a09ebdebcb9c07ee4df147a27e6adb978edf76d93fd98ddeac95b606
```

Archive base64:

```text
Q0ZFTkMwMDEBARAREhMUFRYXGBkaGwEAAQIDBAUGBwgJCgsMDQ4PAAAAAQAAIAABASAhIiMkJSYnKCkqK0n1/Q0Zyl9gjirb1HrHEUNYdzLcMwelTXGhNzaxDHrLxIuWlpy8Lp+CIzoQCPx8AZFiv23LYDu20UESpJKgnr3ry5wH7k3xR6J+atuXjt922T/Zjd6slbYG
```

Expected intermediates:

```text
KEK  cbf44c47dcf21836ef5f0578ac0e2b8afe03e2636071675afc85dfb8a6c23381
DEK  303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f
AAD  4346454e433030310101101112131415161718191a1b01000102030405060708090a0b0c0d0e0f00000001000020000101202122232425262728292a2b49f5fd0d19ca5f608e2adbd47ac71143587732dc3307a54d71a13736b10c7acbc48b96969cbc2e9f82233a1008fc7c01
```

The independent verifier reconstructs and decrypts this archive using only
`argon2-browser`, WebCrypto, and the offsets in this document:

```bash
npm run test:vector:v1
```

It does not import the ClearCrypt API or any ClearCrypt format, KDF, wrap, or
encryption module.
