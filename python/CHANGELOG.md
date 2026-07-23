# Changelog

All notable distribution changes are recorded here. Versions follow semantic
versioning while the portable SSFS format scope remains explicitly bounded by
the compatibility documentation.

## 0.2.0 — 2026-07-23

### Added

- strict codecs for the 70-byte `.LCK` and variable-length `.LKY` files;
- dependency-free AES-128-CBC and Triple-DES primitives needed by SAP Local
  Protected Storage (LPS), with FIPS/OpenSSL known-answer tests;
- LPS v1/v2 container parsing, CRC32/HMAC validation, context/restriction
  checks, random-prefix handling, and portable fallback read/write;
- enhanced type-2 `.KEY` support through a PBKDF2-HMAC-SHA1 registration
  password or matching LPS `.LKY`;
- Windows DPAPI dispatch through standard-library `ctypes` and an explicit
  provider callback for TPM/application-specific host protection;
- `SSFSStore(..., lky_path=...)`, automatic `.LKY` resolution, enhanced-mode
  preserving key rotation, and `initialize_enhanced_key()` for SAP's
  standalone/demo fallback mode;
- read-only `inspect_ssfs_file()` and `sapstract inspect` for non-secret
  DAT/KEY/LKY/LCK metadata, including a separate lenient forensic view;
- `RSEC_SSFS_LKYPATH`, `--lky-path`, and protected
  `--registration-password-file` CLI configuration.

### Verification

- Added official SAP 753 registration-password and real standalone-LPS
  vectors, LPS v1/v2 round trips, tamper/policy/provider tests, and enhanced
  CLI/store lifecycle tests.
- An enhanced `.KEY`/`.LKY`/`.DAT` set written from scratch by sapstract was
  listed successfully by SAP 753 with zero wrong-key/error records.
- SAP 753 then appended a record to that same store; sapstract authenticated
  and recovered the exact development placeholder.
- sapstract rotated that enhanced store while preserving its LKY/KEK policy;
  SAP 753 accepted both re-encrypted records with zero wrong-key/errors.

### Boundaries

- Portable LPS fallback is compatibility obfuscation. SAP labels standalone
  setup as test/demo functionality.
- A TPM blob remains bound to its original platform provider. DPAPI uses the
  Windows API and remains bound to the Windows protection scope. The library
  parses and routes these modes but does not bypass their security boundary.
- Scapy and third-party crypto packages are deliberately not runtime
  dependencies.

## 0.1.0 — 2026-07-22

Initial standalone Python package release.

### Added

- dependency-free Python 3.11+ `sapstract` library and distribution;
- `sapstract` installed console command and `sapstract.pyz` standalone zipapp;
- strict type-1/type-2 key and data-record codecs;
- fail-closed HMAC, CRC32, wrapped-subtype, ciphertext, and inner-digest checks;
- encrypted/plain/binary records, active/history lookup, remove, compaction,
  audit parsing, locks, backups, and key rotation;
- explicit `KeyMode` API for individual and compiled-default compatibility
  policies;
- SCC UTF-16LE Java-password helpers for the verified little-endian package
  family;
- SAP 58-hex generated-key envelope support;
- typed-package marker, API reference, examples, unit/CLI tests, offline HTML
  guide, wheel, sdist, and clean-install verification.

### Security behavior

- Individual mode is the safe default. A missing `.KEY` raises instead of
  silently enabling the compiled default data key.
- Default-key access requires explicit `KeyMode.DEFAULT`, `key_mode="default"`,
  `--key-mode default`, or `RSEC_SSFS_KEYMODE=default` selection.
- Default mode rejects a conflicting individual key file.
- Encrypted low-level `Record.create()` requires an explicit master key.
- Clear values are not printed by routine `get`/`scc-get` operations without an
  explicit output/reveal request.

### Known boundaries

- RSEC/DES, SHA-1, fixed integrity keys, and compiled default keys are retained
  only for SAP format compatibility; they are not modern cryptographic design.
- Host-bound LPS/DPAPI, `.LKY`, password-derived KEKs, big-endian SCC character
  layout, the separate 215-byte SCC key form, and ABAP RSECTAB decryption are
  not implemented.
- Mutation and permission behavior is designed and tested for POSIX systems;
  Linux ARM64 hosted the package verification, with native compatibility
  evidence from SAP Linux x86-64 tooling and supplied macOS ARM64 SCC material.
