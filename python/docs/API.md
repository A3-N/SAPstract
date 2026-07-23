# Python API reference

`sapstract` is a dependency-free, typed Python distribution. Applications
import the `sapstract` package; the same installation provides the `sapstract`
console command.

## Install and import

```sh
python -m pip install sapstract-0.2.0-py3-none-any.whl
```

```python
from sapstract import KeyMode, SSFSStore
```

The supported interpreter range is Python 3.11 and newer. The wheel is pure
Python (`py3-none-any`) and has no runtime dependencies. File permissions,
directory flushes, and locking behavior are designed and tested for POSIX
systems; the distribution does not claim equivalent Windows mutation semantics.

## Key-mode contract

`SSFSStore` never interprets a missing key file as permission to use SAP's
compiled default key.

| Mode | Selection | Required material | Behavior |
|---|---|---|---|
| Individual | `KeyMode.INDIVIDUAL` or `"individual"` | Valid `SSFS_<SID>.KEY` | Safe constructor default; missing key raises `KeyFileError`. |
| Default | `KeyMode.DEFAULT` or `"default"` | No `.KEY` | Explicit compatibility mode; an existing key file raises `KeyModeError`. |

The CLI equivalents are `--key-mode individual|default` and
`RSEC_SSFS_KEYMODE`. Individual mode is the CLI default too.

## `SSFSStore`

```python
SSFSStore(
    sid,
    data_path,
    key_path=None,
    *,
    lky_path=None,
    key_mode=KeyMode.INDIVIDUAL,
    registration_password=None,
    lps_unprotector=None,
    restriction_validator=None,
    allow_mock_lps=False,
    user=None,
    host=None,
)
```

- `sid`: 1–32 ASCII letters or digits; filenames use its uppercase form.
- `data_path`: directory containing `SSFS_<SID>.DAT`.
- `key_path`: directory containing `SSFS_<SID>.KEY`; defaults to `data_path`.
- `lky_path`: directory containing enhanced `SSFS_<SID>.LKY`; defaults to
  `key_path`.
- `key_mode`: explicit master-key policy described above.
- `registration_password`: `str`/`bytes` used to derive an enhanced KEK when
  an instance has not yet persisted a usable `.LKY`.
- `lps_unprotector`: callback for a TPM or application-specific host provider.
  It receives `(protection, protected_key, context, restriction)` and returns
  the 16-byte LPS v2 or 24-byte LPS v1 clear encryption key.
- `restriction_validator`: callback which must explicitly accept a nonempty
  LPS platform restriction before the value can be returned.
- `allow_mock_lps`: test-fixture-only opt-in for SAP's implementation-marker
  zero mock LKY; leave false for operational stores.
- `user`, `host`: optional metadata identities; each is safely bounded to the
  on-disk 24-byte field.

The constructor resolves paths but does not read, create, or modify files.

### Creation

Create the recommended portable individual-key store:

```python
from sapstract import KeyMode, SSFSStore

store = SSFSStore(
    "DEV", "/secure/data", "/secure/key", key_mode=KeyMode.INDIVIDUAL
)
store.initialize_individual_key()  # random type-2 key
store.put("DEV/PASSWORD", b"replace-me")
```

`initialize_individual_key(master_key=None, *, key_type=2)` creates a random
24-byte master key unless one is supplied. Type 2 is the normal portable form;
type 1 is clear-key compatibility mode. Existing key material is never
overwritten. When called on an explicitly opened, nonempty default-key store,
it safely converts the store through full key rotation.

Create or update an intentional default-key SCC-compatible store:

```python
from sapstract import KeyMode, SSFSStore, put_scc_password

store = SSFSStore(
    "SCC", "/opt/sap/scc/scc_config", key_mode=KeyMode.DEFAULT
)
put_scc_password(store, "CHANGE_ME_DEV_ONLY")
```

Default-key mode creates no `.KEY` and provides obfuscation rather than secret
key management.

Create a real LPS v2 fallback KEY/LKY pair for SAP standalone/demo
interoperability:

```python
store = SSFSStore(
    "DEV",
    "/secure/data",
    "/secure/key",
    lky_path="/secure/local-key",
)
store.initialize_enhanced_key()
```

`initialize_enhanced_key(master_key=None, *, key_encryption_key=None)` writes an
enhanced mode-3 `.KEY` and matching `.LKY`. SAP labels standalone LPS setup as
test/demo functionality; its fallback root is portable and is not equivalent
to DPAPI/TPM host binding.

### Reading and inspection

- `get(key_name) -> bytes`: return the newest active value after outer HMAC and
  inner encrypted-payload validation.
- `get_record(key_name) -> Record`: return newest active metadata/ciphertext;
  internal compacting-audit records are excluded.
- `records(history=False) -> list[Record]`: active logical state by default;
  `history=True` includes application defunct versions.
- `load_records() -> list[Record]`: strict raw chronological records, including
  a typed compacting-audit record.
- `validate(decrypt=True) -> list[ValidationResult]`: validate every record.
  `decrypt=False` checks only outer record integrity and deliberately does not
  require a master key.
- `info() -> dict[str, object]`: non-secret paths, key/LKY protection metadata,
  counts, compacting statistics, and parsed lock owner/time metadata.
- `master_key() -> bytes`: resolve and validate key selection. Treat the result
  as secret; most applications should not call this directly.

`key_mode` describes observed state (`individual-…`,
`individual-key-missing`, `default-key-obfuscation`, or
`default-key-conflict`). `configured_key_mode` returns the selected `KeyMode`.

### Mutation and maintenance

- `put(key_name, value, *, plaintext=False, binary=False,
  text_encoding="utf-8") -> Record`: replace the active value by marking it
  defunct and appending a new version. `str` input uses `text_encoding`;
  `bytes` is preserved.
- `remove(key_name) -> None`: mark the newest active version defunct.
- `compact() -> int`: remove defunct versions from the new live `.DAT`, append
  the SAP compacting audit, and return the removed count.
- `change_key(master_key=None, *, key_type=2) -> KeyFile`: validate and decrypt
  every encrypted current/history record, re-encrypt them under a new
  individual key, preserve an existing enhanced KEK/protection mode by default,
  and retain `.DA_`/`.KE_` recovery material.
- `remove_lock() -> bool`: remove a lock only after the caller has established
  it is stale and no writer is active.

Mutations use a cooperative `.LCK`, mode-`0600` temporary files, file and
directory flushes, same-directory atomic replacement, and recovery copies.
Changing `.DAT` and `.KEY` is necessarily a two-file recovery boundary rather
than one atomic transaction.

## SCC helpers

The top-level package exports:

- `SCC_PASSWORD_RECORD`;
- `encode_scc_password(str) -> bytes`;
- `decode_scc_password(bytes) -> str`;
- `put_scc_password(store, password) -> Record`;
- `get_scc_password(store) -> str`.

The encoding is UTF-16LE Java-character data for the supplied little-endian SCC
2.19.1 family. It is stored encrypted with the binary flag. This does not claim
untested big-endian variants or the separate 215-byte SCC key format.

## Strict format and inspection API

Advanced callers can use `KeyFile`, `Record`, `DecryptedPayload`,
`CompactingAudit`, `LocalKeyFile`, `LockFile`, `LPSBlob`, `LPSProtection`,
`KeyFileMetadata`, `parse_records()`, and `serialize_records()`.

- `KeyFile.parse()`/`load()` accept `registration_password=`, `local_key=`,
  `expected_lps_context=`, `lps_unprotector=`, and
  `restriction_validator=`.
- `KeyFile.create_with_registration_password()` creates the enhanced global
  KEY; an instance still needs a matching LKY created by SAP registration or
  `LocalKeyFile.create()`.
- `LocalKeyFile.parse()` validates the full wrapper and exposes a strict LPS
  container; `unprotect()` returns the 24-byte KEK only after all checks pass.
- `LocalKeyFile.create()` and `LPSBlob.protect()` accept an explicit
  `lps_protector` for host-bound DPAPI/TPM provisioning without guessing its
  platform policy.
- `LPSBlob.parse()` supports versions 1 and 2 plus fallback, DPAPI, and TPM
  selectors. `protect_fallback()` creates only the portable fallback form.
- `LockFile.parse()` reads the canonical 70-byte writer metadata.
- `inspect_ssfs_file(path, lenient=False) -> FileInspection` recognizes
  DAT/KEY/LKY/LCK by preamble, returns only structural metadata, and never
  decrypts records or exposes key bytes. Lenient mode is isolated forensic
  triage and does not weaken `SSFSStore`.

`Record.create()` requires `master_key=` for encrypted records. Callers using a
known default-key format at this low level must deliberately import and pass
`sapstract.crypto.DEFAULT_DATA_KEY`. Plaintext record construction does not
need a master key.

Cryptographic compatibility primitives are available from
`sapstract.crypto`, but new application protocols should not use legacy
RSEC/DES, SHA-1, or fixed-key checks.

## Exceptions

All package-specific exceptions derive from `SSFSError`:

| Exception | Meaning |
|---|---|
| `IntegrityError` | Record structure, HMAC, ciphertext wrapper, or inner digest is invalid. |
| `KeyFileError` | Required key material is missing, malformed, or unusable. |
| `KeyModeError` | Explicit key policy conflicts with available material. |
| `UnsupportedFormatError` | Key/record mode is unknown, or a host provider is unavailable. |
| `RecordNotFoundError` | No active application record has the requested name. |
| `LockError` | A cooperative writer lock already exists. |

Argument-domain mistakes such as an invalid SID, oversized key name, incorrect
master-key length, or missing encrypted-record key raise `ValueError`.
Filesystem failures remain ordinary `OSError` subclasses.

## Typing and version

The wheel includes `py.typed`, so type checkers consume the inline annotations.
The installed package exposes `sapstract.__version__`; distribution metadata
uses the same release value.

See [PACKAGING.md](PACKAGING.md) for clean builds and installation checks,
[OPERATIONS.md](OPERATIONS.md) for deployment/recovery policy, and
[SECURITY_AND_FORMAT.md](SECURITY_AND_FORMAT.md) before handling real secrets.
