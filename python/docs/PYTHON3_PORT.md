# Python 3 port and lightweight design

## Goal

The older PySAP SSFS work is a valuable format reference, but it is primarily a
packet parser/decryptor inside a much larger SAP protocol toolkit. The shipping
requirement here is different: a small Python 3 component that can create,
validate, mutate, and rotate SAP-compatible SSFS stores in build environments
where SAP native tooling and large Python dependency stacks are unavailable.

The resulting runtime contains seven small modules and uses only the Python
standard library.

## Reference-to-port map

| Concern | Historical reference shape | Python 3 implementation |
|---|---|---|
| Binary packets | Scapy packet/field classes | Explicit `struct`, slices, frozen dataclasses, and strict length checks. |
| DES/RSEC | External or toolkit cipher layer | Dependency-free standard DES primitive plus exact RSEC stage/tail composition. |
| Hashing | Cryptography package objects | `hashlib.sha1`, `hmac`, and constant-time `compare_digest`. |
| CRC | Toolkit/helper code | Standard-library `zlib.crc32`, stored big-endian. |
| Text model | Python 2 strings can mix bytes/text | All on-disk material is `bytes`; names/metadata are explicit UTF-8; SCC text is explicit UTF-16LE. |
| Key files | Type-1 parsing and partial type-2 decrypt | Type-1/type-2 parse and write, type-2 HMAC/CRC validation, subtype check, and inverse key wrapping. |
| Data files | Parse/lookup/decrypt | Parse, validate, create, replace, history, remove, compact, and key rotation. |
| File lifecycle | Mostly caller managed | Mode `0600`, atomic per-file replace, directory flush, backups, and `.LCK`. |
| CLI | Toolkit-specific utilities | One focused `sapstract` console command and `python -m sapstract` entry point. |
| SCC | Not the primary target | Named password record, encrypted binary flags, and Java `char[]` UTF-16LE helpers. |

## Python 3 byte discipline

The port never relies on implicit conversion between text and binary data:

- file preambles, keys, ciphertext, hashes, padding, and values are `bytes`;
- record keys, user names, and host names enter as `str`, encode once as UTF-8,
  and are padded according to the fixed on-disk byte width;
- values supplied as `str` to the API use an explicit encoding argument,
  defaulting to UTF-8;
- arbitrary files and normal `put --value-file` input remain byte-exact;
- SCC text uses UTF-16LE because it represents Java 16-bit characters in the
  supplied little-endian JNI implementation;
- output is not decoded unless the caller requests SCC text handling.

This avoids the most common Python 2-to-3 failure mode in binary protocols:
accidental Unicode decoding, concatenating `str` and `bytes`, or measuring
characters where the format requires encoded byte lengths.

## Parser rules

The parser treats every input as untrusted. It checks structure before exposing
application data:

1. exact preamble and supported type;
2. minimum, maximum, and in-file record length;
3. supported reserved/control bytes, including SAP's compacting-audit marker, and Boolean flag domain;
4. valid UTF-8 in fixed metadata fields;
5. exact type-1/type-2 key-file length;
6. supported type-2 control block and remaining length;
7. constant-time HMAC comparisons and exact CRC32;
8. wrapped-key subtype;
9. canonical encrypted-payload quantum and declared value bounds;
10. inner SHA-1 after decryption.

Key selection is also explicit at the high-level boundary. Individual mode is
the default and a missing `.KEY` raises `KeyFileError`; the compiled default key
is used only after `KeyMode.DEFAULT`/`--key-mode default` opt-in. Low-level
encrypted `Record.create()` likewise requires an explicit master key.

Unknown protection modes are not coerced into a supported form. This makes the
port forward-incompatible by design where silently rewriting an unknown SAP
format could destroy access to the store.

## Writer rules

The writer is intentionally more than the inverse parser:

- cryptographic randomness comes from `os.urandom` or `secrets`;
- encrypted records get a new random prefix and padding on every write;
- master keys are exactly 24 bytes;
- output fields are encoded and bounded before any file mutation;
- all existing encrypted records must decrypt before a mutation proceeds;
- replacements retain SAP's original-MAC history convention;
- writes use a same-directory temporary file and `os.replace`;
- files are created mode `0600`, directories default to `0700`, and file plus
  directory data are flushed;
- key rotation retains a recoverable old data/key pair.

## Dependency and distribution choices

The code does not import PySAP, Scapy, `cryptography`, OpenSSL bindings, or an SAP
shared library. This reduces the artifact to roughly tens of kilobytes and
avoids platform-specific native wheels. It also means:

- DES is implemented in Python and is not optimized for high throughput;
- AES-128 and Triple-DES are likewise small standard-library-only
  implementations used for LPS compatibility;
- secrets remain ordinary Python byte objects and cannot be guaranteed wiped;
- portable LPS fallback is built in; Windows DPAPI uses standard-library
  `ctypes`, while TPM/application-specific protection requires a provider on
  the original host;
- the tool is intended for small SSFS configuration stores, not bulk encryption.

The source package supports Python 3.11 and newer and can run directly from a
checkout without an install step:

```sh
PYTHONPATH=src python3 -m sapstract --version
```

## API layering

| Module | Responsibility |
|---|---|
| `crypto.py` | DES, Triple-DES, AES, RSEC, key wrap, and record HMAC. |
| `lps.py` | Strict LPS v1/v2 containers and host-provider dispatch. |
| `auxiliary.py` | `.LKY` and `.LCK` wrappers. |
| `inspection.py` | Non-secret strict/forensic file-family views. |
| `format.py` | Key, payload, record codecs and integrity invariants. |
| `store.py` | Paths, locking, backups, atomic writes, lookup, mutation, rotation. |
| `cli.py` | Argument handling, safe default output, SCC conveniences, exit codes. |
| `errors.py` | Stable format/integrity/lock/not-found exception classes. |
| `__init__.py` | Public Python API and version. |
| `__main__.py` | `python -m sapstract` entry point. |

Callers that only need a reader can use `KeyFile`, `Record`, and `parse_records`.
Applications that need lifecycle correctness should use `SSFSStore` instead of
manually concatenating records.

## Compatibility beyond the historical reader

The inverse operations were derived and verified because a reader-only port is
not enough for builds:

- exact encrypted payload creation and 128-byte padding;
- outer HMAC creation;
- SAP-compatible logical deletion;
- 57-byte type-2 key wrapping, including the last-byte tail;
- key-file HMAC-SHA1 and CRC32 creation;
- type-1 and type-2 key-file serialization;
- SCC encrypted binary `char[]` serialization;
- key rotation across active and defunct records.
- SAP 58-character generated-key envelope input.
- SAP compacting-audit parsing/writing and cumulative removal counters.

The supplied SAP executable successfully reads Python output after initial
creation, replacement/history, and key rotation. That bidirectional check is the
release gate; internal encrypt/decrypt round trips alone are insufficient.

## Deliberate non-goals

- Reimplementing the full PySAP protocol suite.
- Emulating SAP profile parsing or every native `rsecssfx` presentation option.
- Pretending a new cipher can be inserted while remaining SSFS compatible.
- Bypassing host-bound protection or extracting protected keys from a registered
  SAP system.
- Turning the compiled SCC default key into a production recommendation.

The port stays small by implementing the complete portable SSFS path and failing
clearly at platform-bound boundaries.
