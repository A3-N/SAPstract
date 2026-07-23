# PySAP SSFS comparison and contribution review

Date: 2026-07-23

## Executive conclusion

PySAP's core SSFS cryptography is sound for the cases it implements. Its RSEC
transform, type-1 key extraction, type-2 key unwrap, record HMAC calculation,
and inner payload SHA-1 calculation agree with this project. A randomized
33-vector cross-implementation test, including RSEC partial tails, produced
identical ciphertext and plaintext in both implementations.

PySAP also has a separate generic `SAPLPSCipher` used by its credential/PSE
modules. That code correctly identifies LPS v2 fallback/DPAPI/TPM selectors and
implements fallback AES plus DPAPI dispatch. It is not wired into
`SAPSSFSLKY`/enhanced SSFS key resolution, returns the random-prefix framing,
supports only v2, leaves CRC/HMAC validation as TODOs, and raises for TPM.
Those are important distinctions: PySAP understands useful LPS cryptography,
but does not currently open an enhanced SSFS KEY/LKY store end to end.

The important gaps are around that crypto core:

1. PySAP can return plaintext when the outer record HMAC is invalid, and can
   return bytes after the inner decrypted-payload SHA-1 check fails.
2. Its convenience lookup returns the first matching record even when that
   record is defunct and a newer active version exists.
3. Its encrypted type-2 key parser ignores the key mode, HMAC-SHA1, CRC32, and
   wrapped-key subtype.
4. It reports native SAP defunct history as HMAC-invalid because it does not
   model SAP's unchanged pre-deletion HMAC convention.
5. Its LPS decryptor returns unauthenticated bytes without validating the
   container CRC/HMAC or removing the random prefix.
6. Its bundled `pysaphdbuserstore` command is currently broken on Python 3 and
   was not covered by the recent example-script migration.

Those are concrete, testable contribution opportunities. Full write support,
default-key SCC support, compaction, key rotation, and SCC `char[]` helpers are
larger feature contributions rather than flaws in PySAP's original read-focused
scope.

## Scope and evidence

The comparison used:

- OWASP PySAP `master` at
  [`ab095eb630941d2e64071ff0f6fd230e7a97333b`](https://github.com/OWASP/pysap/commit/ab095eb630941d2e64071ff0f6fd230e7a97333b),
  current on 2026-07-22;
- PySAP's SSFS and LPS sources/fixtures/tests;
- this project's strict codecs and development validation;
- bidirectional native SAP 753 interoperability results;
- the supplied SCC 2.19.1 macOS ARM64 archive and its no-key
  `SSFS_SCC.DAT`;
- sanitized development stores containing type-1 and type-2 keys, default-key
  SCC data, history, rotation, and compacting-audit records;
- all PySAP issues and pull requests found using `SSFS`, `SAPSSFS`,
  `rsecssfs`, and `hdbuserstore` searches.

No stored value was printed during the comparison. Equality, lengths, status
flags, and hashes were used where a value comparison was necessary.

## What agrees

| Area | Result | Notes |
|---|---|---|
| Type-1 key file | Match | Both extract the same 24-byte master key from the 92-byte form. |
| Type-2 key unwrap | Match | Both reproduce SAP's 57-byte partial-tail key unwrap and recover the same 24-byte key. |
| RSEC transform | Match | 33 deterministic lengths, including non-block tails, matched byte for byte. |
| Record HMAC input | Match for active records | Both authenticate bytes `0x18:0x9c` plus stored data with the fixed 16-byte HMAC key. |
| Inner encrypted payload | Match | Both parse the 8-byte prefix, big-endian value length, SHA-1, value, and padding. |
| Basic DAT parsing | Match | PySAP reads both its own fixtures and the ordinary records produced by this project/SAP. |

This means an upstream contribution should retain PySAP's existing RSEC cipher
rather than replace it wholesale. The best value is in validation, state
semantics, tests, and tooling around it.

## Capabilities PySAP has that sapstract does not

PySAP does not implement an additional portable SSFS secret/key mode that
sapstract is missing. Its unique strengths are primarily forensic and
research-oriented:

| PySAP capability | sapstract status | Value and exact limit |
|---|---|---|
| Scapy-native packet objects | Frozen dataclasses and strict codecs | PySAP provides `show()`, field mutation, byte serialization, layers, and Scapy analysis tooling. This is excellent research ergonomics, not stronger validation. |
| Permissive raw parsing | Rejects unknown preambles, types, controls, flags, lengths, and reserved bytes | PySAP lets an analyst inspect malformed or new variants before their semantics are known. Acceptance does not mean the bytes are valid or safe. |
| Named raw/unknown fields | Splits and validates known type-2 fields | PySAP exposes record fillers and the type-2 62-byte region for exploratory comparison. That `unknown` region is not validated as control, HMAC, and CRC. |
| General SAP credential/PSE integration | SSFS-focused LPS implementation | PySAP wires `SAPLPSCipher` into its credential and PSE modules. | This is broader SAP security-artifact coverage, not enhanced SSFS KEY/LKY support. |
| Human-readable timestamp rendering | Exposes integer timestamps | PySAP's `TimestampField` renders UTC date/time in packet displays. This is presentation, not a trust guarantee. |
| Python 3.10 packaging support | Requires Python 3.11+ | Useful for older runtimes, but not an SSFS format capability. |

The earlier practical gaps identified here have now been implemented:
sapstract has strict `.LCK` metadata, full `.LKY`/LPS parsing, enhanced
registration-password and KEY/LKY resolution, and an explicitly separate
lenient inspector. Scapy integration remains unnecessary for the core; a
future adapter could offer packet-workbench ergonomics without adding a runtime
dependency.

## Confirmed PySAP flaws

### P1 — High: the read API fails open on integrity errors

PySAP calculates the inner SHA-1, but
[`decrypt_data()` only logs a warning and still returns `decrypted_payload.data`](https://github.com/OWASP/pysap/blob/ab095eb630941d2e64071ff0f6fd230e7a97333b/pysap/SAPSSFS.py#L170-L179).
It also does not check the outer record HMAC in `get_plain_data()` before
returning either plaintext or decrypted data.

Observed behavior:

```text
wrong_key_returned= True returned_len= 96
plaintext_outer_valid= False returned_tampered= True
encrypted_outer_valid= False returned_plaintext= True
```

Consequences:

- a wrong key can be mistaken for a real value if callers overlook a log;
- a tampered plaintext record is returned directly;
- a correct ciphertext with a tampered header/HMAC is still decrypted and
  returned;
- issue #70's original “integrity is False” symptom still produced output,
  which made diagnosis harder.

Recommended contribution:

- add an `IntegrityError` specific to SSFS;
- make a new strict read path validate the outer HMAC and inner SHA-1 before
  returning bytes;
- decide explicitly whether legacy `decrypt_data()` changes behavior or gains
  a compatibility option such as `strict=True`;
- add wrong-key, outer-HMAC, recomputed-outer-HMAC/inner-corruption, and
  plaintext-tamper tests.

### P2 — High: lookup can return a stale or deleted secret

[`get_record()` returns the first matching record](https://github.com/OWASP/pysap/blob/ab095eb630941d2e64071ff0f6fd230e7a97333b/pysap/SAPSSFS.py#L227-L249).
It does not exclude defunct records or resolve chronological state.
`has_record()` likewise returns true when only a deleted version remains.

Against a native-readable three-version development store:

```text
matching_versions= 3
deleted_flags= [True, True, False]
pysap_get_record_deleted= True
pysap_equals_current= False
```

The 2021 commit named “Filter deleted records” changed only the
`pysaphdbuserstore` display loop; it did not change the library lookup
semantics.

Recommended contribution:

- keep an explicit history iterator for forensic use;
- define current state by processing records chronologically, where a deleted
  version removes the prior active value and a later active version replaces
  it;
- have the ordinary `get_record()`/`get_value()` return the newest active
  record only;
- test replace, remove-only, recreate-after-remove, and duplicate-active input.

### P3 — Medium: type-2 key metadata and checks are ignored

PySAP treats bytes `0x44:0x82` as one 62-byte
[`unknown` field](https://github.com/OWASP/pysap/blob/ab095eb630941d2e64071ff0f6fd230e7a97333b/pysap/SAPSSFS.py#L81-L100).
In the fallback form validated with SAP 753, that region contains:

- 38 bytes of mode/control data;
- a 20-byte HMAC-SHA1;
- a 4-byte big-endian CRC32.

The 57-byte wrapped-key plaintext also contains a subtype byte which PySAP's
[`rsec_decrypt_key()` does not check](https://github.com/OWASP/pysap/blob/ab095eb630941d2e64071ff0f6fd230e7a97333b/pysap/utils/crypto/__init__.py#L381-L413).

Targeted mutations produced:

```text
control pysap_accepted_same_key=True ours_rejected=UnsupportedFormatError
hmac    pysap_accepted_same_key=True ours_rejected=KeyFileError
crc32   pysap_accepted_same_key=True ours_rejected=KeyFileError
```

These checks use recoverable fixed material and are not proof against a
knowledgeable attacker. They are still important corruption and wrong-mode
checks. Ignoring the control region can also make PySAP apply the fallback KEK
to an LPS-, password-, or LKY-backed form it does not support.

Recommended contribution: split the field, accept only understood modes,
verify both checks with constant-time comparison, require wrapped subtype 1,
and add one mutation test per field.

### P4 — Medium: valid native history is reported as corrupt

SAP marks an old version defunct by changing its deletion flag without
replacing the original active-state HMAC. PySAP validates only the current
serialized bytes in
[`SAPSSFSDataRecord.valid`](https://github.com/OWASP/pysap/blob/ab095eb630941d2e64071ff0f6fd230e7a97333b/pysap/SAPSSFS.py#L181-L195).

For a store updated by the compatible writer:

```text
deleted_flags=      [True, True, False]
pysap_valid_flags=  [False, False, True]
strict_sap_valid=   [True, True, True]
```

Recommended contribution: expose both literal integrity and SAP-history-aware
integrity, so forensic callers can see the distinction without false alarms.
Do not “repair” old history by rewriting its HMAC unless the caller is
deliberately rewriting the store.

### P5 — Medium: unauthenticated structural fields are not validated

The record HMAC intentionally excludes the preamble, declared length, record
type, and first reserved area. PySAP's Scapy packet model parses these fields
but does not enforce their allowed values. On an active record, mutations to
the preamble, record type, or reserved byte were accepted while `.valid`
remained true. A wrong key-file preamble and type were also accepted and still
yielded a 24-byte key.

Recommended contribution: add a strict structural validator covering exact
preambles, total and maximum lengths, supported record/key types, Boolean flag
domain, reserved/control bytes, and trailing data. The loose packet view can
remain useful for exploratory reverse engineering, but high-level reads should
use strict validation.

### P6 — High: LPS returns unauthenticated framed plaintext

PySAP's separate `SAPLPSCipher.decrypt()` implements LPS v2 fallback and DPAPI
key recovery, then AES-CBC decrypts the protected data. Its own docstring and
TODOs state that CRC32 and HMAC validation are not implemented. It returns the
entire decrypted block without validating/removing SAP's one-byte
random-prefix framing. TPM raises `NotImplementedError`, restrictions are not
enforced, and version 1 is rejected.

For a credential/PSE analysis tool, exposing the raw block can be useful. For a
high-level secret API, returning unauthenticated prefix-bearing bytes is the
same fail-open class as P1.

Recommended contribution:

- validate exact field boundaries, CRC32, and HMAC before returning bytes;
- make raw-block access an explicitly named forensic method;
- add a strict value method which checks/removes the prefix;
- enforce context/restriction policy;
- add official/sanitized v2 vectors and tamper tests before wiring LPS into
  SSFS LKY resolution.

### P7 — High usability: `pysaphdbuserstore` is broken on Python 3

The current command
[`opens binary SSFS files in text mode`](https://github.com/OWASP/pysap/blob/ab095eb630941d2e64071ff0f6fd230e7a97333b/bin/pysaphdbuserstore#L125-L149).
Running its own HDB fixture failed as follows:

```text
pysaphdbuserstore: Unable to read data in file tests/data/ssfs_hdb_dat
UnboundLocalError: cannot access local variable 'ssfs_data' where it is not associated with a value
exit=1
```

Further source-level Python 3 defects remain:

- `bytes.rstrip(" ")` uses a text argument;
- the error path accesses removed `IOError.e.message`;
- parse failures log and then continue with an unbound variable;
- `get` always instantiates the type-1 `SAPSSFSKey`, even for type-2 files;
- `--decrypt` is declared with inverted `store_false` semantics and is not
  consulted before the command prints a value.

PR #90 migrated 46 example/library/test files, but its changed-file list does
not include `bin/pysaphdbuserstore`. PR #95 changes only HDB protocol code and
Recommended contribution: a small, isolated Python 3 CLI repair with subprocess
tests for type-1, type-2, list, get, deleted filtering, missing files, and an
explicit no-secret-output mode.

### P8 — Low: the manual SSFS test suite omits type-2 decryption

Normal unittest discovery runs six tests, including the type-2 fixture. The
module's hand-built
[`suite()` includes only three test classes](https://github.com/OWASP/pysap/blob/ab095eb630941d2e64071ff0f6fd230e7a97333b/tests/sapssfs_test.py#L174-L184),
so `python -m tests.sapssfs_test` runs five tests and silently omits
`PySAPSSFSDataDecryptETest`.

Recommended contribution: add the missing class or remove the manual suite in
favor of standard discovery.

### P9 — Documentation: the fixed-key HMAC does not prove tool authenticity

The
[notebook says the record HMAC helps ensure “an authentic tool” generated the file](https://github.com/OWASP/pysap/blob/ab095eb630941d2e64071ff0f6fd230e7a97333b/docs/fileformats/SAPSSFS.ipynb#L882).
The HMAC key is fixed and published in PySAP itself, so anyone who knows the
format can recompute it. The check detects accidental damage and unsophisticated
edits; it does not establish origin or vendor-tool authenticity.

Recommended contribution: replace the authenticity wording with a clear
format-integrity caveat. Apply the same caveat to the fixed type-2 key-file HMAC
and compiled key-encryption key.

## Capability differences that are contribution opportunities

These are useful gaps, but should not be labeled vulnerabilities in PySAP:

| Capability | PySAP | This project / evidence | Suggested upstream shape |
|---|---|---|---|
| RSEC encryption | Decrypt only | Encrypt/decrypt and cross-vectors | Add inverse primitive plus known-answer and tail tests. |
| Store writer | None | Create, put, replace, remove | Separate writer API; never mutate through packet parsing implicitly. |
| Key rotation | None | Type-1/type-2 write and full re-encryption | Separate PR after strict readers are merged. |
| Lock/backups/atomic replace | None | Cooperative `.LCK`, recovery copies, atomic replace | Needed before any upstream writer is called production-safe. |
| Defunct history | Exposed as raw records | Native state semantics and history-aware HMAC | Add explicit current/history views first. |
| Compaction audit | Ordinary record | Parsed/written and tested both directions | Add a typed internal-record view and suppress it from normal secret listing. |
| No-key/default mode | No selection helper | SAP/SCC-compatible fixed default key | Require explicit opt-in and label it obfuscation. |
| SCC `char[]` | No helper | UTF-16LE encrypted/binary helper for supplied family | Optional helper module, architecture-scoped. |
| SAP `generatekey` envelope | No helper | Validates 58-hex envelope and raw 48-hex key | Add a small representation parser, not RSECTAB claims. |
| Enhanced SSFS KEY/LKY | LKY preamble only; generic LPS is not connected | Strict wrapper/LPS/KEY chain, password and provider paths, official vectors | Reuse/refactor `SAPLPSCipher` only after adding integrity/prefix checks, then add the missing SSFS KEK policy layer. |
| Native interoperability tests | Read-only fixtures | Python→SAP and SAP→Python lifecycle transcript | Upstream sanitized fixtures/transcripts, never SAP binaries. |

PySAP's Scapy model remains valuable for packet introspection and field-level
research. This project's standard-library model is stronger for strict
validation, lifecycle operations, and packaging. The two designs can coexist:
strict helpers can sit above the packet classes without removing the
exploratory API.

## Past issues and pull requests

### Issue #70 and PR #71 — type-2 `rsecssfx` key support

[#70](https://github.com/OWASP/pysap/issues/70) correctly identified the
92-byte HDB key versus 187-byte `rsecssfx` key distinction. The community PoC
recovered the fallback KEK and partial-tail unwrap, and the reporter confirmed
that it fixed decryption.

Merged [PR #71](https://github.com/OWASP/pysap/pull/71) added
`SAPSSFSKeyE`, `rsec_decrypt_key()`, a type-2 fixture, and a decryption test.
That work got the cryptographic core right. Its remaining opportunity is to
replace the documented “unknown” 62 bytes with the now-observed control, HMAC,
and CRC fields, then validate them and the wrapped subtype.

### PR #76 — abandoned Python 3 migration

[PR #76](https://github.com/OWASP/pysap/pull/76) touched SSFS code but was
closed unmerged. Its discussion explicitly says tests excluding SSFS were
successful and SSFS migration was split out after decryption trouble. The later
2026 migration fixed bytes/text handling in the SSFS library tests, but changed
only the shebang in `pysaphdbuserstore`, leaving the command defects described
above.

### PR #90 and PR #95 — recent Python 3 work

[PR #90](https://github.com/OWASP/pysap/pull/90) is a broad example-script
migration, but it does not include the SSFS command. [PR #95](https://github.com/OWASP/pysap/pull/95)
fixes HDB protocol bytes/text handling only. Neither should be assumed to have
validated SSFS lifecycle or its CLI.

Three other merged 2026 maintenance PRs touched SSFS files incidentally:

- [PR #88](https://github.com/OWASP/pysap/pull/88) modernized logging so a
  successful inner-integrity result is debug-only and a failure is a warning,
  but left the unconditional return in place;
- [PR #89](https://github.com/OWASP/pysap/pull/89) cleaned the SSFS tests and
  renamed their manual suite function, but the suite still omits the type-2
  test class;
- [PR #91](https://github.com/OWASP/pysap/pull/91) supplied safer empty/default
  field values for Scapy construction, without adding strict validation.

These changes explain the current source accurately, but they do not close P1,
P3, P5, or P7.

### Issue #80 — RSECTAB remains open

[#80](https://github.com/OWASP/pysap/issues/80) reports a 29-byte plaintext key
stored in SSFS and difficulty decrypting ABAP `RSECTAB`. SAP 753
`rsecssfx generatekey -getPlainValueToConsole` also produced a 29-byte portable
envelope in this research:

```text
01 || 24-byte SSFS master key || 2-byte check || repeated 2-byte check
```

This is a useful, testable hypothesis for the issue only if the reporter's
29-byte value has the same subtype and repeated check bytes. It is not proof
that the RSECTAB problem is solved. RSECTAB may still require its own CBC/IV,
SID, installation-number, record-layout, or derivation logic. A responsible
contribution would first add a byte-shape diagnostic and ask for sanitized
known-plaintext vectors; it should not feed arbitrary 24-byte slices into the
SSFS RSEC routine.

### Issue #82 — SCC is not actually implemented in PySAP

[#82](https://github.com/OWASP/pysap/issues/82) asks about a 215-byte SCC key
file. It was closed after a comment linked
[`SAP_Cloud_Connector_SSFS_Decryption`](https://github.com/redrays-io/SAP_Cloud_Connector_SSFS_Decryption).
That PoC calls SCC's proprietary `libsapscc20jni.so` `getRecord` export; it does
not document or portably parse the 215-byte key format.

This project's supplied SCC 2.19.1 sample is a different case: it has only
`SSFS_SCC.DAT`, selects the compiled default data key, and stores the Java
`char[]` as UTF-16LE encrypted binary data. That creates an upstream SCC
contribution opportunity, but it must be described as **no-key/default-key SCC
support**, not as a solution for the 215-byte SCC key from #82. A sanitized
215-byte fixture and native known-plaintext result are still needed.

## Recommended contribution sequence

Keep contributions small enough to review independently:

1. **Repair `pysaphdbuserstore` on Python 3.** This is easily reproduced,
   low-ambiguity, and does not require new format claims.
2. **Add fail-closed SSFS reads.** Start with tests for outer HMAC, wrong key,
   and inner SHA-1 failure; preserve a clearly named raw/forensic path if API
   compatibility matters.
3. **Correct active/history lookup.** Add native-shaped history fixtures and
   explicit current-versus-history APIs.
4. **Validate type-2 key files.** Split the 62-byte region, enforce fallback
   control, HMAC, CRC, exact length/preamble/type, and subtype.
5. **Add strict structural validation and compacting-audit typing.** Keep loose
   Scapy parsing available for research.
6. **Correct security documentation.** Fixed keys mean format checks and
   obfuscation, not trusted origin or strong key protection.
7. **Add inverse encryption and writers only after reader hardening.** Include
   atomic replacement, permissions, locks, recovery, rotation, and native
   cross-read evidence rather than only round-trip tests against the same code.
8. **Add SCC/default-key helpers as an explicitly scoped module.** Do not claim
   the 215-byte form or untested big-endian SCC variants.

Good upstream fixtures are deterministic synthetic stores or redistributable,
sanitized files with no operational names or secrets. SAP executables,
CommonCryptoLib, SCC JNI libraries, and customer stores must not be committed.

## Corrections and remaining limitations in this project

This implementation is broader, but it is not universal:

1. **Resolved after this review:** `SSFSStore` now defaults to explicit
   individual mode and raises when `.KEY` is absent. Default-key access requires
   `KeyMode.DEFAULT`, `key_mode="default"`, `--key-mode default`, or the matching
   environment setting. Encrypted low-level `Record.create()` also requires an
   explicit master key. Tests cover missing-key refusal, explicit default mode,
   mode/key-file conflicts, CLI process boundaries, and default-to-individual
   conversion.
2. SCC `char[]` validation covers the supplied 2.19.1 little-endian ARM64
   family. Big-endian platforms and the 215-byte key form are not claimed.
3. **Resolved after this review:** enhanced type-2 controls,
   registration-password PBKDF2, strict `.LKY`, and LPS v1/v2 fallback are now
   implemented and tested against official SAP 753 material. DPAPI dispatch is
   implemented with the Windows API, and TPM/application-specific protection
   has an explicit provider contract. Host-bound blobs still require their
   original protection scope; this is a security boundary, not a missing
   portable decryption algorithm.
4. Native bidirectional testing used SAP 753. Strict reserved-field checks may
   need versioned allowances when a sanitized, vendor-accepted counterexample
   is found.
5. No official LPS v1, Windows DPAPI, or TPM SSFS fixture was available in the
   supplied archives. Those paths have primitive/provider tests but should not
   be labeled vendor-validated until sanitized host-specific vectors exist.
6. The project does not implement ABAP RSECTAB decryption. The SSFS
   `generatekey` envelope observation should be contributed as a hypothesis and
   parser test, not as a completed RSECTAB solution.

## Licensing boundary

PySAP is GPL-2.0-or-later; this package is MIT. MIT-owned code can generally be
contributed for inclusion in a GPL project under compatible terms, but PySAP's
GPL implementation must not be copied back into this MIT package. Keep the
work based on independently verified format behavior, contributor-owned code,
synthetic fixtures, and public documentation. This is a practical engineering
boundary, not legal advice.

## Reproduction summary

Commands used for the local comparison:

```bash
# PySAP's declared runtime/test dependencies were installed in a temporary venv.
/tmp/pysap-comparison-venv/bin/python -m pytest tests/sapssfs_test.py -q
# Result: 6 passed

PYTHONPATH=/path/to/pysap \
  /path/to/venv/bin/python -m tests.sapssfs_test
# Result: 5 tests, PASS; the type-2 class is omitted by suite().

PYTHONPATH=/path/to/pysap \
  /path/to/venv/bin/python \
  /path/to/pysap/bin/pysaphdbuserstore \
  -c list -d /path/to/pysap/tests/data/ssfs_hdb_dat
# Result: exit 1, text-mode parse failure followed by UnboundLocalError.
```

Native SAP command transcripts and sanitized store artifacts are intentionally
not included in the public source repository.
