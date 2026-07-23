# Python library and pip packaging

## One distribution, two interfaces

The project is packaged once and exposes two supported interfaces:

| Packaging concept | Name | Purpose |
|---|---|---|
| Distribution | `sapstract` | The name used by `pip`, wheel/sdist files, and a package index. |
| Import package | `sapstract` | The Python namespace used by application code. |
| Console command | `sapstract` | The CLI installed from the same distribution. |

There are not two implementations. The CLI calls the public library, so format
and lifecycle behavior remain in one place.

## Source layout

```text
python/
├── pyproject.toml
├── MANIFEST.in
├── README.md
├── LICENSE
├── src/
│   └── sapstract/
│       ├── __init__.py       # documented public exports
│       ├── crypto.py         # RSEC/DES/AES compatibility primitives
│       ├── format.py         # DAT/KEY binary structures
│       ├── auxiliary.py      # LKY/LCK structures
│       ├── lps.py            # Local Protected Storage containers
│       ├── inspection.py     # non-secret file-family inspection
│       ├── store.py          # high-level store lifecycle
│       ├── scc.py            # Cloud Connector conventions
│       └── cli.py            # command-line presentation
└── docs/
```

The `src/` layout prevents accidental imports from the project directory and
keeps packaging metadata separate from runtime modules.

## Public library API

Most application code should start with:

```python
from sapstract import KeyMode, SSFSStore

store = SSFSStore(
    "DEV", "/secure/data", "/secure/key", key_mode=KeyMode.INDIVIDUAL
)
store.initialize_individual_key()  # creation only
store.put("DEV/PASSWORD", b"secret")
value = store.get("DEV/PASSWORD")
results = store.validate()
```

The top-level package also exports:

- `ValidationResult` and the `SSFSError` exception family;
- `Record`, `KeyFile`, `LocalKeyFile`, `LockFile`, `LPSBlob`,
  `DecryptedPayload`, and `CompactingAudit` for format work;
- `FileInspection` and `inspect_ssfs_file()` for read-only triage;
- `parse_records()` and `serialize_records()` for byte-oriented integrations;
- `put_scc_password()` and `get_scc_password()` plus SCC encoding helpers.

`KeyMode.INDIVIDUAL` is the constructor default. It requires a valid `.KEY`
before encrypted I/O and never falls back because a file is missing. A known
no-`.KEY` SCC store must use `key_mode=KeyMode.DEFAULT` explicitly. The same
policy is available to the CLI as `--key-mode`/`RSEC_SSFS_KEYMODE`.

Cryptographic primitives remain available from `sapstract.crypto` for format
testing, but applications should normally use `SSFSStore` rather than assembling
records or encryption stages themselves.

## Install with pip

Create an isolated environment and install the source tree:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
```

Both interfaces now come from the same installation:

```sh
python -c "from sapstract import SSFSStore; print(SSFSStore)"
sapstract --version
```

For development, use an editable installation:

```sh
python -m pip install --editable ".[dev]"
```

## Build wheel and source distribution

Install the declared development extra, then build both artifact types:

```sh
python -m pip install ".[dev]"
python -m build
```

Expected artifacts:

```text
dist/sapstract-0.2.0-py3-none-any.whl
dist/sapstract-0.2.0.tar.gz
```

The generic `py3-none-any` wheel is appropriate because the package is pure
Python and has no runtime dependencies. The sdist includes sources and
documentation; the wheel contains only install-time package files and
entry-point metadata.

Inspect and validate before distribution:

```sh
python -m pip install --upgrade twine
python -m twine check dist/*
unzip -l dist/*.whl
tar -tzf dist/sapstract-0.2.0.tar.gz
```

## Test the built wheel, not the source tree

Use a fresh environment outside the checkout:

```sh
python3 -m venv /tmp/sapstract-wheel-check
/tmp/sapstract-wheel-check/bin/python -m pip install \
  dist/sapstract-0.2.0-py3-none-any.whl

cd /tmp
/tmp/sapstract-wheel-check/bin/python -c \
  "from sapstract import SSFSStore; print('library import: PASS')"
/tmp/sapstract-wheel-check/bin/sapstract --version
```

## Publish only after choosing an owner and release policy

TestPyPI is the appropriate first publication target:

```sh
python -m twine upload --repository testpypi dist/*
```

After installing and testing from TestPyPI, a release can be uploaded to PyPI:

```sh
python -m twine upload dist/*
```

Before publishing:

1. Confirm the distribution name and version are available and intentional.
2. Add real project, source, issue, and documentation URLs to `pyproject.toml`.
3. Build from a clean tagged revision.
4. Verify the sdist and wheel contain no stores, keys, credentials, or temporary files.
5. Prefer PyPI trusted publishing from a protected GitHub release workflow over
   long-lived API tokens.

Publishing to an external index is not performed automatically by this project.
