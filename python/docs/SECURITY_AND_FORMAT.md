# SSFS security and binary-format map

## Purpose and evidence

This document maps the security properties and byte layout of the supplied
SSFS variants and independently generated enhanced-LPS fixtures:

1. SAP kernel 753 `rsecssfx` using `SSFS_<SID>.DAT` plus an individual
   `SSFS_<SID>.KEY`.
2. SAP Cloud Connector 2.19.1 using `scc_config/SSFS_SCC.DAT`, the SCC record
   convention, and no external key file in the supplied package.
3. SAP kernel 753 enhanced type-2 `.KEY` files unlocked by a registration
   password or an instance-local `.LKY` containing LPS v2 fallback protection.

The conclusions are based on four evidence classes:

- the supplied Linux x86-64 SAP 753 executable and its successful read/write
  behavior;
- the supplied macOS ARM64 SCC `SecStoreAccess` class, JNI library, and store;
- the public [PySAP SSFS format documentation](https://pysap.readthedocs.io/en/latest/fileformats/SAPSSFS.html)
  and its source implementation;
- SAP's conceptual documentation for
  [Secure Storage in the File System](https://help.sap.com/docs/ABAP_PLATFORM_NEW/1531c8a1792f45ab95a4c49ba16dc50b/a082dd0abbde4696b98a8be133b27f3b.html)
  and [changing SSFS keys](https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/581593c48739431caaccc3d2ef55c23f.html).

Where SAP's public documentation describes behavior rather than private binary
offsets, the tables below record interoperable observed behavior. No secret from
the source archives is printed or copied into the generated development stores.

## Security layers at a glance

| Layer | rsecssfx individual-key store | SCC supplied/default-key store | Actual guarantee |
|---|---|---|---|
| Filesystem access | `.DAT` and `.KEY` can be separated and mode `0600` | `.DAT` is mode `0600`; no `.KEY` | Primary access-control boundary. |
| Record confidentiality | Random per-store 24-byte master key | Compiled default 24-byte key | Legacy RSEC/DES confidentiality; SCC default key is recoverable and therefore obfuscation only. |
| Master-key storage | Type 2 wraps the random key with a compiled or enhanced KEK | No external master-key file | Compiled mode is reversible. Enhanced mode can move the KEK into host-bound LPS, depending on its provider. |
| Record integrity | Fixed-key HMAC-SHA1 | Same | Detects damage and unsophisticated edits; not strong authenticity because the HMAC key is embedded/public. |
| Encrypted payload check | Unkeyed SHA-1 inside ciphertext | Same | Detects wrong keys and blind ciphertext corruption after decryption. |
| Type-2 key-file checks | KEK-keyed HMAC-SHA1 plus CRC32 | Not applicable while no `.KEY` exists | Detects corruption/wrong KEK; compiled mode's fixed KEK remains public. |
| Enhanced local protection | `.LKY` LPS fallback, DPAPI, or TPM selector | No `.LKY` in the supplied SCC archive | Fallback is portable obfuscation; DPAPI/TPM protection remains host/platform-bound. |
| Concurrency | Cooperative `.LCK` plus atomic replace | Native SCC uses the same SSFS locking family | Prevents cooperating writers; does not stop a user who can delete or ignore the lock. |
| Recovery | `.DA_` and `.KE_` backups | `.DA_` when mutated by this implementation | Recoverability, but backups retain old secrets. |

## File family and lifecycle

For SID `DEV`, the conventional names are:

| File | Role | Secret-bearing |
|---|---|---|
| `SSFS_DEV.DAT` | Concatenated current and defunct records | Yes: plaintext records or encrypted secrets. |
| `SSFS_DEV.DA_` | Previous data-file recovery copy | Yes: can contain old values. |
| `SSFS_DEV.KEY` | Individual master key | Yes: enough to decrypt the matching `.DAT`. |
| `SSFS_DEV.KE_` | Previous key-file recovery copy | Yes: may unlock the `.DA_` or older data. |
| `SSFS_DEV.LCK` | Cooperative writer lock | Metadata only. |
| `SSFS_DEV.LKY` | Instance-local LPS-protected key-encryption key | Yes; enough to unlock enhanced `.KEY` when its protection is portable/usable. |

SAP creates some files only when needed. A default-key SCC store can consist of
only `SSFS_SCC.DAT`. The absence of `.KEY` is semantically significant: the
native format reader selects its compiled default key. The Python library does
not infer operator intent from absence alone: callers must select
`KeyMode.DEFAULT`/`--key-mode default` explicitly. Otherwise a missing `.KEY`
is reported as an error.

## Data file

`SSFS_<SID>.DAT` has no file-level header. It is a concatenation of records. A
reader advances by each record's big-endian length field and must reject a
truncated record, an impossible length, or trailing bytes.

### Record layout

All offsets are hexadecimal from the start of one record. Integer fields are
big-endian.

| Offset | Size | Field | Meaning and validation |
|---:|---:|---|---|
| `0x00` | 12 | Preamble | ASCII `RSecSSFsData`. |
| `0x0c` | 4 | Record length | Total header plus data; minimum 176, observed maximum `0x18150`. |
| `0x10` | 1 | Record type | `1` for the supported record family. |
| `0x11` | 7 | Reserved | Zero in supported files. |
| `0x18` | 64 | Record key | UTF-8 text, padded on the right with spaces. |
| `0x58` | 8 | Timestamp | Unsigned Unix epoch seconds. Metadata, not proof of time. |
| `0x60` | 24 | OS user | UTF-8, space padded. Informational, not authenticated identity. |
| `0x78` | 24 | Host | UTF-8, space padded. Informational, not authenticated identity. |
| `0x90` | 1 | Deleted | `0` active, `1` defunct. |
| `0x91` | 1 | Plaintext | `0` RSEC encrypted, `1` stored directly. |
| `0x92` | 1 | Binary | `0` textual convention, `1` binary convention. Encryption is independent of this flag. |
| `0x93` | 9 | Data-header control | Zero for application records. SAP's compacting audit uses `01 00 00 00 00 00 00 00 00`. |
| `0x9c` | 20 | Record MAC | HMAC-SHA1 described below. |
| `0xb0` | variable | Data | Plain bytes or an RSEC ciphertext. |

The implementation treats the first reserved area and Boolean flags strictly.
The second control area is zero for application records; the observed SAP
compacting-audit marker is accepted only with its reserved key, flags, and exact
64-byte payload. This matters because the preamble, total length, record type,
and first reserved area are outside the record MAC.

### Outer record HMAC-SHA1

The 16-byte HMAC key embedded in the legacy implementation is:

```text
e3a0611185416899f30eda877a80cc69
```

The authenticated message is:

```text
record[0x18:0x9c] || record[0xb0:end]
```

This covers the key name, timestamp, user, host, status flags, second reserved
area, and all stored data. It excludes the preamble, length, record type, first
reserved area, and the MAC itself.

Because the key is the same across installations and can be recovered from
public tooling, this HMAC is a format-integrity check, not a trustworthy origin
signature. A knowledgeable attacker who can write the file can modify a record
and calculate a new outer MAC.

### Defunct-history quirk

When SAP replaces or removes a record, it changes the old record's deleted byte
at `0x90` from `0` to `1` without replacing its original HMAC. Consequently:

- a defunct SAP record normally fails a literal HMAC over its current bytes;
- it validates when byte `0x90` is restored to `0` for the calculation;
- the old ciphertext and old secret remain recoverable until compaction;
- a validator that does not model this behavior will falsely label valid SAP
  history as corrupt.

`sapstract` accepts either a current-state valid MAC or this exact historical
form. New history is serialized in the same way.

### Active-record resolution

Records are chronological append history. A replacement marks the former active
version defunct and appends a new active record. Normal lookup scans from the end
and returns the most recent non-defunct matching key. `list --history` exposes
all versions without decrypting values. `compact` rewrites active records and a
fresh internal compacting-audit record.

### Compacting-audit record

SAP `compact` appends an internal record that normal record listings suppress:

```text
RSECSSFS/COMPACTING_AUDIT
```

It is active, plaintext, binary, uses `filler2 = 01 00 00 00 00 00 00 00 00`,
and has a 64-byte outer-HMAC-protected payload:

| Payload offset | Size | Field |
|---:|---:|---|
| `0x00` | 8 | Big-endian compacting timestamp. |
| `0x08` | 24 | Space-padded user. |
| `0x20` | 24 | Space-padded host. |
| `0x38` | 4 | Total records removed across effective compactions. |
| `0x3c` | 4 | Records removed by the most recent effective compaction. |

Python validates SAP-created audit records, excludes them from normal record
results, includes them in full integrity validation, exposes their counters
through `info`, and emits the same structure when Python compacts data. SAP 753
renders the Python-created record under its normal `Compacting Audit` summary.

## Encrypted record payload

Before RSEC encryption, the record data is built as follows. Integers remain
big-endian.

| Offset | Size | Field | Meaning |
|---:|---:|---|---|
| `0x00` | 8 | Random prefix | Fresh random bytes; adds ciphertext variability. |
| `0x08` | 4 | Value length | Number of application bytes beginning at `0x20`. |
| `0x0c` | 20 | SHA-1 | Digest over the prefix, length, value, and padding; the digest field itself is skipped. |
| `0x20` | value length | Value | Application bytes. |
| after value | variable | Random padding | Extends the whole plaintext to the next 128-byte quantum. |

Digest input in exact notation is:

```text
payload[0x00:0x0c] || payload[0x20:end]
```

The first quantum holds up to 96 application bytes because 32 bytes are used by
the header. A 96-byte value encrypts to 128 bytes; a 97-byte value encrypts to
256 bytes. A 500-byte value encrypts to 640 bytes.

The SHA-1 is inside the ciphertext. It is useful for reliably distinguishing a
correct key/plaintext from corruption, but it is unkeyed and is not a modern
message-authentication construction.

Plaintext records set byte `0x91` to `1` and store the application value directly
at `0xb0`; they do not have this inner wrapper. The outer fixed-key HMAC is their
only format check.

## RSEC confidentiality transform

The portable legacy cipher uses a 24-byte key split into `K1`, `K2`, and `K3`,
each eight bytes. Encryption applies three complete stages:

```text
C = E_K3(D_K2(E_K1(P)))
```

Decryption applies the inverse:

```text
P = D_K1(E_K2(D_K3(C)))
```

Each stage uses the standard DES block primitive. Full eight-byte blocks are
chained CBC-style with an all-zero initial vector. SAP's RSEC function also has
a proprietary partial-tail rule: after the last full block, it DES-encrypts the
last full ciphertext block and XORs the needed leading keystream bytes with the
tail. Normal record payloads are a multiple of 128 bytes, while the 57-byte
type-2 key wrapper uses the special tail behavior explicitly.

The implementation validates the standard DES known-answer vector
`0123456789abcdef` under key `133457799bbcdff1` as
`85e813540f0ab405`, then tests RSEC round trips and SAP-generated ciphertext.

DES and three-key Triple-DES-family constructions are legacy. The format does
not provide an authenticated-encryption mode, modern nonce discipline, or an
upgrade marker for AES-GCM. The Python code preserves compatibility and does not
present RSEC as appropriate for new protocols.

## Key selection modes

### No key file: compiled default key

When `SSFS_<SID>.KEY` is absent in an intentional default-key store, the native
implementation selects this 24-byte data key internally:

```text
b1e09244ec19eb3401dfc846ab225820c71bc376581eb3e4
```

The supplied SCC `SSFS_SCC.DAT` has no `.KEY` and validates/decrypts under this
mode. The SCC development store intentionally reproduces it. Python callers
must opt in with `key_mode=KeyMode.DEFAULT`; the CLI requires
`--key-mode default` or `RSEC_SSFS_KEYMODE=default` on each process.

This mode is **obfuscation, not secret key management**. Possession of the data
file plus any compatible implementation is sufficient to recover its values.
OS permissions may still stop an unprivileged process from reading the file,
but file exfiltration defeats confidentiality.

### Type-1 individual key file

Type 1 is 92 bytes and holds a random master key directly.

| Offset | Size | Field |
|---:|---:|---|
| `0x00` | 11 | ASCII `RSecSSFsKey`. |
| `0x0b` | 1 | Type `1`. |
| `0x0c` | 24 | Master key in clear. |
| `0x24` | 8 | Big-endian Unix timestamp. |
| `0x2c` | 24 | Space-padded user. |
| `0x44` | 24 | Space-padded host. |

Type 1 gives confidentiality when the data file and key file are protected and
distributed separately. Theft of both files gives the attacker the decryption
key immediately.

### Type-2 individual key file

The default portable writer emits the 187-byte compiled-KEK type-2 form.

| Offset | Size | Field | Meaning |
|---:|---:|---|---|
| `0x00` | 11 | Preamble | ASCII `RSecSSFsKey`. |
| `0x0b` | 1 | Key-file type | `2`. |
| `0x0c` | 8 | Timestamp | Big-endian Unix epoch seconds. |
| `0x14` | 24 | User | Space padded. |
| `0x2c` | 24 | Host | Space padded. |
| `0x44` | 1 | Key-encryption type | `0` compiled KEK, `1` enhanced KEK. |
| `0x45` | 32 | Salt | Zero in compiled mode; PBKDF2 salt in enhanced mode. |
| `0x65` | 1 | Global key mode | Compiled: zero. Enhanced: `0` fallback disallowed, `1` fallback allowed, `3` standalone. |
| `0x66` | 4 | Wrapped-key length | Big-endian `57`. |
| `0x6a` | 20 | Key-file HMAC | HMAC-SHA1 over the non-checksum fields and wrapped key. |
| `0x7e` | 4 | CRC32 | Big-endian CRC32 over the non-CRC fields and wrapped key. |
| `0x82` | 57 | Wrapped key | RSEC-wrapped master-key structure. |

The fixed 24-byte key-encryption key (KEK) is:

```text
9f60a6dd7e157d070cc357909aa290e9360eee472fda4772
```

The key-file HMAC input is:

```text
key_file[0x00:0x6a] || key_file[0x82:0xbb]
```

Its HMAC key is the same 24-byte KEK used for the wrapped master key: the
constant above in compiled mode or the resolved per-store KEK in enhanced mode.

The CRC32 input, after the HMAC has been placed, is:

```text
key_file[0x00:0x7e] || key_file[0x82:0xbb]
```

The 56 full wrapped bytes decrypt under the KEK to:

| Clear offset | Size | Meaning |
|---:|---:|---|
| `0x00` | 32 | Random bytes. |
| `0x20` | 1 | Wrapped-key subtype `1`. |
| `0x21` | 23 | First 23 bytes of the master key. |

The 24th master-key byte is represented by wrapped byte 57 using RSEC's
partial-tail XOR construction. This explains why a naive 56-byte wrapper can
appear to decrypt most of the key but is rejected by SAP.

The HMAC and KEK are fixed and recoverable. Type 2 therefore prevents casual
inspection but does not make a stolen `.KEY` cryptographically unavailable. Its
important operational benefits are a distinct random data key, rotation, and
the ability to store `.DAT` and `.KEY` under separate access controls.

### Enhanced type-2 key protection

Enhanced type 2 keeps the same 187-byte outer layout and 57-byte wrapped master
key. It changes the 24-byte KEK used for both the wrapper and key-file HMAC.
The KEK can be resolved in either of two ways:

```text
registration_KEK =
  PBKDF2-HMAC-SHA1(password ASCII, salt[32], 10,000 iterations, 24 bytes)
```

or by opening the matching `SSFS_<SID>.LKY`. When both are supplied, the
library requires constant-time equality. A wrong password, wrong LKY, bad
HMAC, bad CRC, unknown mode, or fallback LKY under global
fallback-disallowed policy stops the read.

The registration password is not the record master key. It derives the KEK;
the KEK unwraps the 24-byte master key; that master key decrypts `.DAT`
records.

### Instance-local LKY wrapper

The observed `.LKY` structure is:

| Offset | Size | Field |
|---:|---:|---|
| `0x00` | 11 | ASCII `RSecSSFsLKY`. |
| `0x0b` | 1 | Implementation: `1` real LPS; `0` SAP test mock. |
| `0x0c` | 8 | Big-endian timestamp. |
| `0x14` | 24 | User, space padded. |
| `0x2c` | 24 | Host, space padded. |
| `0x44` | 4 | Big-endian protected-payload length. |
| `0x48` | 4 | Big-endian CRC32 over header-without-CRC plus payload. |
| `0x4c` | variable | LPS container or explicit SAP test mock. |

The real LPS clear value is exactly:

```text
01 || 24-byte key-encryption key
```

Mock LKY material is rejected unless a caller opts in explicitly for a test.

### LPS v1/v2 container

LPS uses length-prefixed big-endian fields:

```text
version[1] || protection[1] ||
context_len[2] || context ||
restriction_len[2] || restriction ||
protected_key_len[2] || protected_key ||
intermediate_len[2] || intermediate ||
encrypted_data_len[2] || encrypted_data ||
HMAC-SHA1[20] || CRC32[4]
```

Version 1 uses a 24-byte Triple-DES EDE key. Version 2 uses a 16-byte
AES-128-CBC key with a zero IV. Both encrypt a one-byte random-prefix length,
that many random bytes, and the actual value. The HMAC key is
`SHA1(clear_encryption_key)`; the CRC covers everything before the CRC.
Contexts are limited and checked against `SSFS_<SID>` when resolving a store.
Nonempty platform restrictions require an explicit validator.

Protection selector `0` is portable fallback. Its root encryption key is
deterministically derived from SAP's observed LCG material and the context, so
it is compatibility obfuscation. Selector `1` is Windows DPAPI and is opened
through `CryptUnprotectData` in its valid Windows protection scope. Selector
`2` is TPM/application-specific and requires an explicit provider callback.
Parsing DPAPI/TPM bytes never implies that they are portable.

### SAP generated-key envelope

`rsecssfx generatekey -getPlainValueToConsole` emits 58 hexadecimal characters,
representing 29 bytes:

```text
01 || 24-byte SSFS master key || 2-byte check value || same 2-byte check value
```

The native `changekey` command also accepts the raw 24-byte/48-hex form. The
Python CLI accepts both forms, checks the envelope subtype and repeated check
field, and uses its embedded 24-byte master key. This permits direct handoff
from official `generatekey` output without manual slicing.

### Remaining host-bound boundary

The library parses all observed enhanced control/LKY/LPS layers and implements
portable fallback directly. It does not manufacture access to a TPM or move a
DPAPI secret between machines. Those modes require their registered host or an
application-supplied provider. Unknown key types, controls, versions,
protections, and restrictions fail closed and are never silently downgraded to
the compiled KEK.

## Lock file

The cooperative `SSFS_<SID>.LCK` file is 70 bytes:

| Offset | Size | Field |
|---:|---:|---|
| `0x00` | 12 | ASCII `RSecSSFsLock`. |
| `0x0c` | 1 | File type, zero in the supported form. |
| `0x0d` | 1 | Lock type, zero in the supported form. |
| `0x0e` | 8 | Big-endian Unix timestamp. |
| `0x16` | 24 | User, space padded. |
| `0x2e` | 24 | Host, space padded. |

Creation uses exclusive create semantics. The writer flushes the lock, writes a
temporary data/key file with mode `0600`, flushes it, atomically replaces the
target, flushes the containing directory, and finally removes the lock.

This is cooperative coordination, not mandatory kernel locking. Only remove a
`.LCK` after verifying that no native SCC, SAP tool, or Python process is using
the store.

## SCC mapping

The supplied `configurator.jar` exposes
`com.sap.scc.jni.SecStoreAccess`. Its relevant API maps as follows:

| SCC Java/JNI operation | SSFS behavior |
|---|---|
| `init(path)` | Configures SID `SCC` with the same directory for data and key paths. |
| `putRecord(String, char[])` | Stores encrypted binary bytes representing the Java characters. |
| `getRecord(String)` | Reads the binary value and reconstructs a Java `char[]`. |
| `putBinaryRecord(String, byte[])` | Stores encrypted binary bytes directly. |
| `removeRecord(String)` | Marks the active record defunct. |
| `changeKey()` | Creates/rotates an individual key and re-encrypts records. |
| `compact(String)` | Removes history according to the SSFS compact operation. |

`getP12Password()` uses the fixed record key:

```text
CLOUD_CONN/JAVA_KEYSTORE_PASSWORD
```

On the supplied little-endian ARM64 package, `char[]` is handed to native SSFS
as two bytes per Java code unit. The portable CLI therefore encodes SCC text as
UTF-16LE and marks it binary. `scc-get` performs the exact inverse. This encoding
has been validated for the supplied package family; an untested big-endian SCC
platform should be checked with a vendor-generated non-secret fixture first.

The supplied SCC data file has no `.KEY`, so its native reader uses the default
key mode described above. The Python-generated SCC placeholder uses the same
record name, encrypted/binary flags, payload wrapper, and key selection.

## Mutation, recovery, and retention

### Normal put or remove

1. Exclusively create `.LCK`.
2. Parse all records and reject malformed structure.
3. Validate current or SAP-history outer HMAC for every record.
4. Decrypt every encrypted record and validate its inner SHA-1.
5. Mark a replaced/removed record defunct without rewriting its historical MAC.
6. Append the new active record when performing a put.
7. Copy the current `.DAT` to `.DA_`, mode `0600`.
8. Atomically replace `.DAT` and flush its directory.
9. Remove `.LCK`.

### Key rotation

1. Perform the same validation under the old key.
2. Decrypt encrypted active and defunct records in memory.
3. Create fresh random inner prefixes/padding and encrypt under a fresh key.
4. Preserve record keys, flags, timestamps, user, host, and defunct state.
5. Save `.DA_` and `.KE_` recovery copies.
6. Replace `.DAT`, then `.KEY`, both mode `0600`.

Two independent files cannot be atomically replaced as one filesystem
transaction. A crash between replacements can leave a new `.DAT` with an old
`.KEY`. The `.DA_`/`.KE_` pair exists for this recovery case. Operators must
restore a matching pair, validate it, and only then discard recovery material.

### Secure deletion caveat

`remove` is logical deletion. `compact` removes defunct bytes from the live data
file but `.DA_`, snapshots, container layers, filesystem journals, SSD remapping,
and backups can retain them. Key rotation also retains `.KE_` and `.DA_` until an
operator handles them. The tool does not claim secure erasure.

## Threat model

### Defended reasonably within the legacy format

- Accidental truncation, record-length corruption, flag corruption, wrong keys,
  and most unintentional byte damage are detected before mutation.
- A process that can read only `.DAT`, but not a separately protected random
  `.KEY`, cannot directly obtain individual-key record plaintext.
- Mode `0600`, mode `0700` directories, and separate secret mounts can prevent
  unrelated OS users from reading or replacing store material.
- Cooperative writers avoid routine lost updates through `.LCK`.
- Recovery copies and atomic per-file replacement reduce damage from interrupted
  writes.

### Not defended by SSFS itself

- An attacker who can read both `.DAT` and portable `.KEY` can decrypt records.
- An attacker who can read a default-key SCC `.DAT` can decrypt records with a
  compatible implementation.
- An attacker who can write a store and knows the published fixed keys can forge
  outer/key-file checksums and chosen plaintext/ciphertext structures.
- Root, the store owner, a debugger, a compromised build agent, or code running
  in the same process can obtain secrets and keys from memory.
- Metadata user/host/timestamp fields do not prove identity or time.
- The format has no rollback counter. Replacing a valid store with an older valid
  snapshot is not detected.
- The cooperative lock does not constrain non-cooperating writers.
- Python immutable `bytes` cannot be guaranteed to be wiped after use.
- Shell history, process arguments, logs, core dumps, backups, and CI artifacts
  can bypass the intended file controls.

## Hardening requirements

For any use beyond the isolated placeholder environment:

1. Provision the intended secret and rotate the Java keystore to the same value.
2. Prefer an individual random key; do not treat SCC default mode as encryption
   against file theft.
3. Mount `.DAT` and `.KEY` from separate secret objects when the runtime allows
   it, both readable only by the service account.
4. Make their parent directories non-writable to other users; mode `0600` on a
   file does not protect against replacement by someone who controls the parent.
5. Supply values through standard input or protected files, not command-line
   arguments.
6. Disable core dumps and prevent debug attachment for the service/build user.
7. Validate before deployment and after rotation with both the Python tool and,
   where available, the target SAP/SCC reader.
8. Keep `.DA_`/`.KE_` only for the documented recovery window and protect them as
   strongly as the live files.
9. Compact history when retention is not required, understanding that this is
   not guaranteed physical erasure.
10. Prefer a vendor-supported host-bound protection mode when its portability
    tradeoff is acceptable; use SAP tooling for those modes.

## Cryptographic assessment

| Component | Status | Consequence |
|---|---|---|
| DES-based RSEC | Legacy | Kept only for byte compatibility; not suitable for a new design. |
| SHA-1 inner digest | Collision-weakened and unkeyed | Useful as corruption/wrong-key detection, not authentication. |
| HMAC-SHA1 construction | HMAC remains structurally stronger than raw SHA-1 | Fixed/public HMAC key removes the trust property. |
| CRC32 | Non-cryptographic | Accidental-corruption check only. |
| Random prefixes/padding | Uses `os.urandom` | Prevents deterministic ciphertext for repeated values, but does not create authenticated encryption. |
| Random per-store master key | 24 bytes from `os.urandom` | Strong entropy; overall protection remains bounded by the legacy cipher and key-file custody. |
| Compiled default/KEK constants | Recoverable | Obfuscation, interoperability, and format checks only. |

The correct security interpretation is: **SSFS is a legacy encrypted file format whose real
security boundary is OS access plus key-file separation.** The Python port makes
that boundary explicit instead of overstating fixed-key checks as modern
cryptographic authenticity.
