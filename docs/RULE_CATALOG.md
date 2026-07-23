# SAPstract rule catalog

Rules are evaluated only against observed local evidence. The report includes
the exact asset, evidence, impact, remediation and source. A rule's severity
does not prove remote reachability or exploitability.

| ID | Default severity | Trigger |
|---|---|---|
| `ABAP-001` | High | `abap/path_normalization` is explicitly off/false/zero |
| `ACL-001` | High | SAP ACL/route file contains a broad permit wildcard |
| `ACL-002` | Medium | SAP ACL exists but contains no active rules |
| `ACL-003` | High | Profile references an absolute ACL path that is missing in the audited root |
| `AUTH-001` | High | `auth/rfc_authority_check=0` disables incoming RFC authorization checks |
| `AUTH-002` | High | `login/no_automatic_user_sapstar=0` enables the kernel SAP* fallback |
| `AUTH-003` | Medium | Detailed ABAP logon errors are enabled |
| `AUTH-004` | Medium | Existing passwords are not checked against the current password policy |
| `AUTH-005` | Medium | `login/password_downwards_compatibility` retains backward-compatible hashes |
| `AUTH-006` | Medium | Profile minimum password length is below 12; a security policy may override it |
| `AUTH-007` | Medium | RFC accepts expired passwords |
| `AUTH-008` | Medium | ICF accepts expired passwords |
| `CFG-001` | High | Secret-like parameter has a literal-looking non-empty value; value is redacted |
| `DIAG-001` | Medium | Non-loopback 32NN Dispatcher/DIAG listener requires SNC/boundary validation |
| `ENQ-001` | High | Process-attributed Enqueue/replication listener is bound beyond loopback |
| `FILE-001` | Critical | SAP executable is world-writable |
| `FILE-002` | High | Other security-relevant SAP path is world-writable |
| `FILE-003` | High | SAP executable is group-writable |
| `FILE-004` | Medium | Profile, ACL, credential or SSFS data is group-writable |
| `FILE-005` | High | Credential or encrypted secret-bearing data is world-readable |
| `FILE-006` | High | SAP directory is world-writable |
| `GUI-001` | High | Known SAP GUI input-history file/directory is present |
| `GW-001` | Medium | Cleartext RFC Gateway 33NN listener is reachable beyond loopback |
| `GW-002` | High | `gw/acl_mode=0` |
| `GW-003` | High | `gw/sim_mode=1` |
| `GW-004` | High | `gw/acl_mode_proxy=0` |
| `GW-005` | High | `gw/reg_no_conn_info=0` disables bitmask protections |
| `GW-006` | High | `gw/monitor` is greater than local-only value 1 |
| `GW-007` | High | `gw/rem_start` is not disabled or `SSH_SHELL` |
| `ICM-001` | Medium | Detailed ICM/Web Dispatcher errors are enabled |
| `ICM-002` | Low | ICM/Web Dispatcher server header is enabled |
| `ICM-003` | Critical | ICM file alias maps a root or parent-relative `DOCROOT` |
| `ICM-004` | Medium | ICM is configured to accept invalid HTTP Host headers |
| `ICM-005` | Medium | `icf/set_HTTPonly_flag_on_cookies` disables HttpOnly for an ICF cookie class |
| `ICM-006` | High | ABAP logon tickets are not restricted to HTTPS |
| `IGS-001` | High | IGS HTTP listener contains the `administration` option |
| `JAVA-001` | High | NetWeaver Java telnet/shell port 5NN08 is exposed beyond loopback |
| `LOG-001` | Medium | ABAP `rec/client` table-change logging is off/zero |
| `LOG-002` | Medium | Static `rsau/enable=0`; effective dynamic Security Audit Log settings require validation |
| `MS-001` | High | Message Server internal port 39NN is broadly bound |
| `MS-002` | Medium | Message Server monitor/admin function has a non-zero value |
| `MS-003` | Medium | Message Server external port 36NN listens beyond loopback |
| `MS-004` | Medium | `system/secure_communication` is explicitly not `ON` |
| `NET-001` | High | High-impact administration port is network-reachable |
| `NET-002` | High | Internal SAP service is bound beyond loopback |
| `NET-003` | High | Cleartext SAP Host Agent/Start management endpoint is reachable |
| `NET-004` | Medium | SAP HTTP administration/application endpoint is reachable |
| `NET-005` | Medium | SAProuter is network-reachable; route/patch review is required |
| `NET-006` | Medium | SAP administrative service listens beyond loopback |
| `NET-007` | Medium | Recognized SAP database listener is bound beyond loopback |
| `OSCMD-001` | High | `rdisp/call_system=1` enables ABAP `CALL 'SYSTEM'` |
| `OSCMD-002` | High | Instance profile contains `EXECUTE_XX` command execution |
| `RFC-001` | High | `rfc/callback_security_method` is below full active/inactive-list enforcement value 3 |
| `RFC-002` | High | Legacy target-independent trusted RFC tickets are allowed |
| `ROUTER-001` | High | Observed SAProuter command line contains exact `-X` loopback administration option |
| `SNC-001` | Medium | SNC permits insecure communication/start fallback |
| `SNC-002` | Medium | An `snc/accept_insecure_*` connection class is enabled |
| `SNC-003` | Medium | SNC min/use/max QoP is below privacy level 3 |
| `SNC-004` | Medium | `snc/only_encrypted_gui=0` |
| `SNC-005` | Medium | `snc/enable=0` disables SNC initialization |
| `SSFS-001` | Critical | SSFS key/LKY material is broadly writable |
| `SSFS-002` | High | SSFS key/LKY material is group-writable on Unix |
| `SSFS-003` | Critical | SSFS key/LKY material is broadly/world-readable |
| `SSFS-004` | Medium | SSFS key/LKY material is group-readable on Unix |
| `SSFS-005` | High | SCC SSFS data has no matching individual key in audited paths |
| `SSFS-006` | High | HANA user-store data has no matching host key in audited paths |
| `SSFS-007` | High | Other SSFS data has no matching individual key in audited paths |
| `SSFS-008` | Medium | SSFS key exists without matching data in audited paths |
| `START-001` | High | Start Service uses `NONE`, legacy `DEFAULT`, or empty protected-webmethod setting |
| `TOOL-001` | High | SAP tool is in a broadly writable parent directory |
| `TOOL-002` | High | Windows SAP executable has invalid/untrusted Authenticode status |
| `UCON-001` | Medium | Explicit `ucon/rfc/active` value is not recommended active value 1 |

## Important interpretation notes

- `SSFS-005` through `SSFS-008` are pair/path findings, not proof of data loss
  or corruption. Profiles can place data and key files in separate
  directories. Validate with the owning account and official SAP tool before
  changing anything. SCC support for an individual key is product/version
  specific.
- Listener rules do not prove firewall or Internet exposure. They state that
  a local bind is not loopback and therefore requires network-path validation.
- Group access may be operationally required. Review actual group membership
  and service design before removing it.
- A profile file may not be the effective runtime source. Confirm active
  values in the SAP-supported administration interface.
- `AUTH-004`, `AUTH-006`, and related password findings may be overridden by
  client-specific security policies. `LOG-002` cannot observe the dynamic
  Security Audit Log configuration. Treat these as required authenticated
  validation prompts, not proof that the runtime is unprotected.
- Patch/CVE status is intentionally not guessed from filenames or version
  strings. Use SAP for Me/System Recommendations and applicable Security
  Notes.
- `TOOL-002` is Windows-only; Unix has no equivalent Authenticode mechanism.

## Scoring

Each unique `rule ID + asset` pair contributes Critical 30, High 18, Medium 8
or Low 3 points. Duplicate observations are de-duplicated. Findings are
assigned to five report sections:

| Section | Rule families |
|---|---|
| Network & exposed services | `NET`, `DIAG`, `ENQ`, `JAVA`, and listener-specific `GW`/`MS` rules |
| Configuration & access controls | `ABAP`, `ACL`, `AUTH`, `CFG`, `GW`, `ICM`, `IGS`, `MS`, `RFC`, `SNC`, `START`, `UCON` |
| Files & executable integrity | `FILE`, `TOOL` |
| SSFS, credentials & client data | `SSFS`, `GUI` |
| Operations, logging & command execution | `LOG`, `OSCMD` |

Each section score is capped independently at 100. The original aggregate
score remains in JSON for backward compatibility and is also capped at 100.
Grades are A (0–9), B (10–24), C (25–49), D (50–74), and F (75–100).
