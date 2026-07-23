# sapstract

`sapstract` is a dependency-free Python 3 reader, writer, validator, and
inspector for SAP Secure Storage in the File System (SSFS). It handles the
legacy RSEC records used by the supplied SAP 753 `rsecssfx` and SAP Cloud
Connector 2.19.1 archives, including clear/compiled keys and enhanced
registration-password/Local Protected Storage (LPS) key protection.

The project deliberately uses only the Python standard library. It runs on
Python 3.11 or newer without SAP shared libraries, Scapy, or a cryptography
package.

> **Security boundary:** this is compatibility software for an inherited
> format, not a modern secret-storage design. Legacy SSFS uses DES-based RSEC,
> SHA-1, and embedded keys for several integrity and key-wrapping operations.
> Read [Security and binary format](docs/SECURITY_AND_FORMAT.md) before choosing
> a key mode.

## Deliverables

- `src/sapstract/`: importable Python package and CLI.
- `CHANGELOG.md`: release history and compatibility-impacting API changes.
- `docs/SECURITY_AND_FORMAT.md`: detailed security and byte-level format map.
- `docs/COMPATIBILITY.md`: supported, rejected, and empirically verified cases.
- `docs/OPERATIONS.md`: deployment, rotation, recovery, and SCC runbook.
- `docs/PYTHON3_PORT.md`: Python 2 reference-to-Python 3 design map.
- `docs/PACKAGING.md`: public API, wheel/sdist build, clean-install
  verification, and package-index release process.
- `docs/API.md`: standalone public-library reference, key-mode contract,
  lifecycle methods, return types, and exceptions.
- `docs/PYSAP_SSFS_COMPARISON.md`: evidence-backed comparison with OWASP
  PySAP, including PySAP-only research features, confirmed flaws, issue/PR
  history, and proposed work for both projects.

## Run without installing

Use the checked-in source tree:

```sh
PYTHONPATH=src python3 -m sapstract --help
```

## Install as a normal package

```sh
python3 -m pip install .
sapstract --help
```

There are no runtime dependencies. Package installation itself uses
`setuptools` through the standard `pyproject.toml` build interface.

The single distribution provides both interfaces:

```sh
python3 -c "from sapstract import SSFSStore; print(SSFSStore)"
sapstract --version
```

See [Python library and pip packaging](docs/PACKAGING.md) for the public API,
editable installation, wheel/sdist builds, clean-environment verification, and
publishing checklist.

## Configuration

Every store has a system ID and data/key directory. CLI options take precedence
over the matching SAP environment variables.

| CLI option | SAP environment variable | Meaning |
|---|---|---|
| `--sid SID` | `SAPSYSTEMNAME` | File suffix, normalized to uppercase. |
| `--data-path DIR` | `RSEC_SSFS_DATAPATH` | Directory containing `SSFS_<SID>.DAT`. |
| `--key-path DIR` | `RSEC_SSFS_KEYPATH` | Directory containing `SSFS_<SID>.KEY`; defaults to the data directory. |
| `--lky-path DIR` | `RSEC_SSFS_LKYPATH` | Directory containing enhanced `SSFS_<SID>.LKY`; defaults to the key directory. |
| `--key-mode MODE` | `RSEC_SSFS_KEYMODE` | `individual` (safe default) or explicit `default` compatibility mode. |
| `--registration-password-file FILE` | — | Read an enhanced registration password without exposing it in the command line. |

The implementation also uses SAP's conventional `.DA_`, `.KE_`, and `.LCK`
names for recovery copies and cooperative locking.

A missing `.KEY` never selects the compiled default key implicitly. Supply
`--key-mode default` (or `RSEC_SSFS_KEYMODE=default`) on every process that is
deliberately opening a known default-key store.

## Create an individual-key store

An individual, randomly generated 24-byte master key is the recommended portable
mode. Keep the data and key files in separately protected deployment secrets
when possible.

```sh
install -d -m 0700 build/ssfs-data build/ssfs-key

sapstract \
  --sid DEV \
  --data-path build/ssfs-data \
  --key-path build/ssfs-key \
  init
```

Write a secret without placing it in the process argument list:

```sh
printf %s 'CHANGE_ME_DEV_ONLY' | \
sapstract \
  --sid DEV \
  --data-path build/ssfs-data \
  --key-path build/ssfs-key \
  put DEV/PASSWORD --value-file -
```

The positional value form is convenient for placeholders, but production
secrets should come from standard input or a mode-`0600` file because command
arguments can be retained in shell history and exposed through process tools.

## Enhanced KEY/LKY support

Existing enhanced type-2 stores open automatically when the matching
`SSFS_<SID>.LKY` is in `--lky-path`. A registration password can instead be
supplied from a protected file when registering or recovering an instance:

```sh
sapstract \
  --sid DEV \
  --data-path data \
  --key-path key \
  --lky-path local \
  --registration-password-file /run/secrets/ssfs-registration-password \
  validate
```

The reader validates the `.LKY` wrapper CRC, LPS CRC/HMAC/context/restriction,
the enhanced `.KEY` HMAC/CRC, and the wrapped-key subtype before returning a
master key. Portable LPS v1/v2 fallback is implemented directly. Windows DPAPI
uses the platform API; TPM/application-specific protection requires an
explicit provider callback on the registered host.

For an isolated interoperability/demo store, `init --enhanced-fallback` creates
a real LPS v2 standalone `.LKY` plus enhanced `.KEY`:

```sh
sapstract \
  --sid DEV --data-path data --key-path key --lky-path local \
  init --enhanced-fallback
```

SAP documents standalone setup as test/demo functionality. Fallback LPS is
portable obfuscation, not host-bound production protection.

## Create or update an SCC store

The SCC convenience command uses the record name found in the supplied Cloud
Connector package and serializes Java character data as encrypted UTF-16LE
binary:

```sh
install -d -m 0700 build/scc_config

sapstract \
  --sid SCC \
  --data-path build/scc_config \
  --key-path build/scc_config \
  init --key-mode default

printf %s 'CHANGE_ME_DEV_ONLY' | \
sapstract \
  --key-mode default \
  --sid SCC \
  --data-path build/scc_config \
  --key-path build/scc_config \
  scc-put --value-file -
```

Default-key mode intentionally creates no `SSFS_SCC.KEY`. It matches the
supplied SCC archive, but it is obfuscation only and should be limited to the
requested isolated development case. Continue passing `--key-mode default` for
reads, validation, updates, and the one-time `changekey` conversion. After
conversion, omit that option and deploy the resulting `.DAT` and `.KEY`
together.

## Safe inspection

These commands do not print decrypted values:

```sh
sapstract --sid DEV --data-path data --key-path key info
sapstract --sid DEV --data-path data --key-path key list
sapstract --sid DEV --data-path data --key-path key validate
sapstract --sid DEV --data-path data --key-path key get DEV/PASSWORD
sapstract --json inspect local/SSFS_DEV.LKY
```

`get` reports metadata and decoded size by default. Use `--output FILE` to write
mode-`0600` bytes or `--reveal` only when deliberate console disclosure is
acceptable. `--json` is available for `info`, `list`, and `validate` when placed
before the subcommand.

## Mutation and maintenance

```sh
# Mark the current version defunct; old ciphertext remains in the data file.
sapstract --sid DEV --data-path data --key-path key remove DEV/PASSWORD

# Permanently omit defunct versions from the live .DAT file.
sapstract --sid DEV --data-path data --key-path key compact

# Generate a random key, re-encrypt records, and write a type-2 .KEY file.
sapstract --sid DEV --data-path data --key-path key changekey

# Remove only a lock known to be stale.
sapstract --sid DEV --data-path data --key-path key removelock
```

`changekey` accepts either a raw 24-byte key represented by 48 hexadecimal
characters or the 58-character envelope emitted by SAP `rsecssfx generatekey`.

Before a mutation, the tool validates every outer record HMAC and decrypts every
encrypted record with its inner SHA-1 check. A failed validation stops the write.
Data writes are atomic within a filesystem and retain `SSFS_<SID>.DA_`; key
rotations additionally retain `SSFS_<SID>.KE_`. See the operations guide for the
two-file recovery boundary and secure disposal implications.

## Python API

```python
from sapstract import KeyMode, SSFSStore

store = SSFSStore(
    "DEV",
    "/run/secrets/ssfs-data",
    "/run/secrets/ssfs-key",
    key_mode=KeyMode.INDIVIDUAL,
)
store.initialize_individual_key()  # only when creating a new store

store.put("DEV/PASSWORD", b"secret")
assert store.get("DEV/PASSWORD") == b"secret"

for result in store.validate():
    if not result.valid:
        raise RuntimeError(result.error)
```

Values and master keys are returned as `bytes`; callers control their further
lifetime. Python does not guarantee that immutable byte strings can be wiped
from process memory.

Cloud Connector conventions are also available without importing the CLI:

```python
from sapstract import KeyMode, SSFSStore, get_scc_password, put_scc_password

store = SSFSStore(
    "SCC",
    "/opt/sap/scc/scc_config",
    key_mode=KeyMode.DEFAULT,
)
put_scc_password(store, "CHANGE_ME_DEV_ONLY")
assert get_scc_password(store) == "CHANGE_ME_DEV_ONLY"
```

The top-level API additionally exports format objects, validation results, SCC
encoding helpers, record parsing/serialization, and the documented exception
family. Low-level RSEC primitives remain in `sapstract.crypto`.

## Scope

Supported cases include type-1 and compiled/enhanced type-2 key files,
registration-password PBKDF2, `.LKY`/LPS v1/v2, portable LPS fallback, Windows
DPAPI dispatch, external TPM/provider dispatch, explicitly selected default-key
stores, encrypted/plain records, text/binary flags, history, compaction,
inspection, and key rotation. Unknown structures fail closed. Host-bound
protection is usable only in its original platform scope; parsing a TPM or
DPAPI blob is not and cannot be a portable bypass.

SAP and related product names are trademarks of SAP SE. This project is an
independent interoperability implementation and is not an SAP product.
