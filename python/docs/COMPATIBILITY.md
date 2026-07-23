# Compatibility and verification record

## Reference inputs

| Input | Relevant content | Use |
|---|---|---|
| `sapmnt.tgz-aa` | Linux x86-64 SAP kernel 753 `rsecssfx`, `libsapcrypto`, ICU libraries, existing SSFS examples | Vendor-tool generation and cross-read validation. |
| `sapcc-2.19.1-macosx-aarch64.tar.gz` | SCC 2.19.1 `configurator.jar`, ARM64 JNI library, `scc_config/SSFS_SCC.DAT` | SCC record/API/encoding and default-key validation. |
| `pysap/` and [PySAP documentation](https://pysap.readthedocs.io/en/latest/fileformats/SAPSSFS.html) | Open-source SSFS parser, RSEC decryptor, type-1/type-2 fixtures | Historical format reference and independent read checks. |

Development validation used sanitized stores freshly generated with the
supplied SAP 753 tool and a non-secret placeholder. No SAP binary, SSFS store,
key, or fixture is included in the public source repository.

## Supported matrix

| Capability | Read | Write | Notes |
|---|---:|---:|---|
| Concatenated `RSecSSFsData` record type 1 | Yes | Yes | Strict lengths, control bytes, Boolean flags, and SAP compacting audit. |
| Encrypted records | Yes | Yes | Legacy RSEC with 128-byte inner payload quantum. |
| Plaintext records | Yes | Yes | Explicit `--plain`; discouraged for secrets. |
| Text/binary metadata flag | Yes | Yes | Value bytes are otherwise caller controlled. |
| SAP defunct history | Yes | Yes | Models the unchanged pre-deletion HMAC behavior. |
| Default-key/no-`.KEY` store | Yes | Yes | Explicit opt-in; compatibility/isolated-dev mode only. |
| Type-1 clear individual key | Yes | Yes | `--clear-key-file`; compatibility mode. |
| Type-2 compiled-KEK individual key | Yes | Yes | Includes control byte, HMAC-SHA1, CRC32, subtype, and 57-byte wrapper. |
| Type-2 registration-password KEK | Yes | Yes at low level | PBKDF2-HMAC-SHA1, 32-byte salt, enhanced control modes, HMAC/CRC/wrapper validation. |
| Enhanced `.KEY` through `.LKY` | Yes | Yes, fallback standalone | Automatically resolves the matching instance-local KEK. |
| `.LKY` wrapper | Yes | Yes | Strict preamble, implementation, length, identity fields, and CRC32. |
| LPS v1 fallback | Yes | Yes | Triple-DES EDE, context-derived root, HMAC, CRC, and prefix handling; own round-trip vector. |
| LPS v2 fallback | Yes | Yes | AES-128-CBC, context-derived root, HMAC, CRC, and prefix handling; official SAP vector. |
| LPS DPAPI | Yes on bound Windows host/provider | No | Standard-library Windows API or explicit provider callback. |
| LPS TPM/application-specific | Yes with provider | No | Parses/routs strictly; original host/provider must unprotect the opaque key. |
| LPS restrictions | Yes with validator | No | Nonempty restrictions fail closed unless an explicit validator accepts them. |
| `.LCK` cooperative lock | Yes | Yes | Strict conventional 70-byte form plus metadata inspection. |
| `.DA_`/`.KE_` recovery copies | Yes as manually selected files | Yes | Created before relevant mutations. |
| SCC `char[]` record | Yes | Yes | UTF-16LE encrypted binary convenience commands. |
| SCC binary record | Yes | Yes | Use normal `put --binary`/`get`. |
| Key rotation | Yes | Yes | Re-encrypts active and defunct encrypted records. |
| Compact | Yes | Yes | Omits all defunct records from new live `.DAT`. |
| SAP `generatekey` envelope | Yes | Yes | Accepts raw 48-hex and official 58-hex rotation keys. |
| DAT/KEY/LKY/LCK inspection | Yes | N/A | Strict non-secret metadata plus isolated lenient forensic triage. |

## Explicitly unsupported

| Mode | Behavior | Reason |
|---|---|---|
| Portable TPM decryption | Rejected without provider | A TPM-protected root is intentionally bound to the original host/provider. |
| Cross-host DPAPI decryption | Rejected | Windows DPAPI protection scope is a security boundary, not a missing cipher. |
| Creating new DPAPI/TPM LKY material | Not implemented | Provisioning policy and host ownership belong to the platform/SAP lifecycle. |
| Unknown key types or record types | Rejected | Failing closed prevents silent downgrade or corrupt rewrites. |
| Vendor profile parsing (`pf=...`) | Not implemented | Direct SID/data/key options and SAP environment variables are simpler and portable. |
| Vendor text transcoding modes | Not implemented | CLI uses explicit UTF-8 and SCC UTF-16LE conventions. |
| Big-endian SCC `char[]` | Not claimed | Supplied SCC target is little-endian ARM64; validate other architectures first. |
| Modern cipher upgrade | Not invented | A non-SAP format would cease to be SSFS compatible. |

## Completed cross-compatibility checks

### SAP-generated individual store read by Python

- Parsed the 187-byte type-2 `.KEY`.
- Validated key-file HMAC-SHA1 and CRC32.
- Unwrapped the random 24-byte master key.
- Parsed and validated the `DEV/PASSWORD` record.
- Decrypted and matched `CHANGE_ME_DEV_ONLY`.
- Re-serialized the key file byte-for-byte.

This check was part of development interoperability validation.

### Python-generated individual store read by SAP 753

The Python CLI created SID `PY3`, a fallback type-2 key file, and encrypted
`DEV/PASSWORD`. The supplied SAP tool returned one active encrypted record with
zero wrong-key and error records:

```text
Active  Records : 1 (Encrypted: 1, Plain: 0, Wrong Key: 0, Error: 0)
Defunct Records : 0
```

This exercises the direction most parsers miss: SAP checks the type-2 remaining
length, key-file HMAC, CRC32, encrypted key subtype, wrapped last byte, record
MAC, RSEC payload, and inner digest before reporting the record as encrypted
rather than wrong-key/error.

The same check was repeated after Python created one defunct version and rotated
the type-2 master key. SAP reported one active encrypted record and one encrypted
defunct record, with zero wrong-key/error records. A separately generated type-1
clear-key compatibility store was also accepted as one encrypted record.

### Enhanced LPS in both directions

SAP 753 created a real 168-byte standalone LPS v2 `.LKY`, a 187-byte enhanced
`.KEY`, and an encrypted record. Python independently:

- validated the LKY wrapper CRC and LPS CRC/HMAC;
- derived the portable fallback root from context `SSFS_STD`;
- AES-decrypted and removed the random prefix from the 25-byte KEK compound;
- validated and unwrapped the enhanced `.KEY`;
- validated/decrypted `STD/TEST` to the exact development placeholder.

A separate SAP-generated enhanced `.KEY` was opened with registration password
`Abcd1234`; Python's PBKDF2-derived KEK recovered the official test master-key
vector.

In the other direction, Python created an enhanced mode-3 `.KEY`, real LPS v2
fallback `.LKY`, and encrypted `OWN/TEST`. SAP 753 `list` reported:

```text
Active  Records : 1 (Encrypted: 1, Plain: 0, Wrong Key: 0, Error: 0)
Defunct Records : 0
```

SAP then appended `OWN/OFFICIAL` to the Python-created store. Python reopened
the SAP-written data with the same LKY, authenticated every layer, and matched
the exact 18-byte placeholder. This validates both writer directions rather
than only parsing a captured LPS blob.

The current CLI repeated that test with SID `V20`, then rotated the master key
while preserving the enhanced KEK/salt/mode and existing LKY. SAP 753 listed
both re-encrypted records with `Wrong Key: 0, Error: 0`.
The sanitized validation artifacts are intentionally not included in the
public source repository.

### Python-generated default-key SCC record read by SAP 753

The Python CLI wrote `CLOUD_CONN/JAVA_KEYSTORE_PASSWORD` as encrypted binary
UTF-16LE in SID `SCC`, with no `.KEY`. SAP 753 listed it without a wrong-key or
record error.

### Supplied SCC store read by Python

The Python CLI opened the supplied `SSFS_SCC.DAT` with explicit
`--key-mode default` selection and returned:

```text
CLOUD_CONN/JAVA_KEYSTORE_PASSWORD[0]: OK
```

The value was not printed. This confirms that the default key, encrypted payload
format, record flags, and SCC `char[]` representation match the supplied SCC
family.

### Defunct history

SAP 753 was used to replace a record. A byte comparison showed that the old
version's deleted flag changed while its HMAC remained the active-state HMAC.
Python validates this exact historical convention rather than using naive
current-byte validation.

### Compaction audit in both directions

SAP 753 compacted a store containing two defunct records. Python parsed the
resulting internal `RSECSSFS/COMPACTING_AUDIT`, validated its HMAC, reported two
records removed, and continued reading the remaining records.

Python then compacted a separate store with two defunct records and emitted the
same audit structure. SAP 753 reported two records removed overall and two in
the last effective compaction.

### Official generated key consumed by Python

An official 58-character `generatekey` result was passed directly to Python
`changekey`. The generated type-2 `.KEY` contained the envelope's embedded
24-byte key, and SAP read the rotated encrypted record with zero errors.

### Boundary and primitive checks

- Standard DES known-answer test.
- Standard AES-128 FIPS known-answer test and Triple-DES/OpenSSL vector.
- RSEC round trips with full and partial tails.
- LPS v1/v2 fallback round trips and official LPS v2 fixture.
- LKY/LPS CRC, HMAC, context, restriction, and fallback-policy rejection.
- TPM/provider dispatch without treating host-bound protected bytes as clear.
- Encrypted value boundary at 96 bytes (128-byte ciphertext) and 97 bytes
  (256-byte ciphertext).
- Outer record tampering detection.
- Inner encrypted-payload tampering detection even after recomputing the known
  outer HMAC.
- Type-2 key-file HMAC and CRC tampering detection.
- Put/replace/remove/compact/key-rotation lifecycle.
- CLI exit status: `0` valid, `3` invalid record, `2` key/configuration error.
- Mode-`0600` output and lock cleanup after a failed write.

## Reproduce the vendor-tool read on Linux x86-64

Assuming the supplied tool directory and a Python-created test store:

```sh
export LD_LIBRARY_PATH=/path/to/tools/linux-x86_64
export SAPSYSTEMNAME=PY3
export RSEC_SSFS_DATAPATH=/path/to/validation/data
export RSEC_SSFS_KEYPATH=/path/to/validation/key
export RSEC_SSFS_LKYPATH=/path/to/validation/local-key
/path/to/tools/linux-x86_64/rsecssfx list
```

On a non-x86-64 development host, an x86-64 userspace loader plus
`qemu-x86_64` can perform the same check. That emulator setup is a test-harness
concern and is not needed by the shipped Python implementation.

## Compatibility acceptance rule

A store is considered compatible only when:

1. its native reader reports zero wrong-key/error records;
2. Python validates all record and key-file checks;
3. application bytes match without normalizing encoding;
4. replacements remain readable as native history;
5. a rotation produces a matching, recoverable `.DAT`/`.KEY` pair.

Merely parsing field boundaries or obtaining plausible plaintext is not enough.
