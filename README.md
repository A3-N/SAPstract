# SAPstract

SAPstract is an all-in-one SAP security repository with two deliberately
separated components:

- a read-only, host-local SAP footprint and security-posture collector for
  Linux/Unix and Windows; and
- a dependency-free Python library and CLI for reading, writing, validating
  and inspecting SAP Secure Storage in the File System (SSFS).

The host collector can run on a live SAP host or against a mounted offline
filesystem. It discovers what SAP software is present, which SAP services are
running or connected, and which local configuration, permission or exposure
conditions deserve remediation. It produces a self-contained HTML report and
a JSON evidence companion.

The design is similar to PingCastle in one important respect: the report
prioritizes observed risks and explains why each matters and what to change.
The score is a triage aid, not an SAP certification or a claim that a finding
is remotely exploitable.

## Repository layout

| Path | Purpose | Runtime | License |
|---|---|---|---|
| `SAPaudit.sh` | Linux/Unix host posture collector | Bash 4+ | GPL-3.0 |
| `SAPaudit.ps1` | Windows/cross-platform host posture collector | Windows PowerShell 5.1+ or PowerShell 7+ | GPL-3.0 |
| `python/` | Importable `sapstract` SSFS package, CLI and source documentation | Python 3.11+ | MIT |
| `docs/` | Host-audit rule catalog and OWASP CBAS traceability | None | Repository documentation |

The audit collector and Python SSFS package have independent versions. Their
shared repository name does not mean the collector imports the Python package.

## Host-audit collectors

- `SAPaudit.sh`: Bash 4+ for Linux/Unix hosts.
- `SAPaudit.ps1`: Windows PowerShell 5.1+ and PowerShell 7+ on Windows,
  Linux and macOS.

The retired Python host collector remains removed. The shell collectors have
no PySAP, Scapy, Python, package-manager, browser-CDN or network-scanner
runtime dependency. PySAP is used only as a research reference for SAP
protocol and file-format recognition.

## Python SSFS package

The separate component under [`python/`](python/) is the previously standalone
`sapstract` 0.2.0 package. It supports the Python API and command-line
interface without PySAP, Scapy, `cryptography` or other runtime dependencies.

Run it directly from the checkout:

```bash
cd python
PYTHONPATH=src python3 -m sapstract --help
```

Install it as a normal package:

```bash
python3 -m pip install ./python
sapstract --version
```

The package covers legacy/compiled and enhanced type-2 SSFS keys, LKY/LPS,
explicit SCC default-key compatibility, individual keys, history, validation,
mutation, inspection and key rotation. Missing key material never selects the
compiled default implicitly. Start with the
[Python package guide](python/README.md), [API reference](python/docs/API.md)
and [operations guide](python/docs/OPERATIONS.md).

Unlike the passive host collector, the Python package can deliberately return
clear bytes to its caller and can modify stores. Use protected input files or
standard input, preserve matched backups, validate with official SAP tooling,
and never use the development-only SCC/default-key mode as a modern
secret-storage design. SAP-proprietary binaries and local validation stores are
not bundled in this repository or Python distribution.

## What it audits

- SAP services and processes, executable paths and service accounts.
- Listening and connected sockets, including SAP port families and SAP-owned
  processes on nonstandard ports. Port numbers alone are not promoted as SAP:
  accepted sockets require an SAP process owner, a discovered SID/instance
  match, a dedicated SAP port, or matching product runtime evidence.
- An evidence-backed mini topology graph that groups enabled/observed SAP
  services, maps established peers, and distinguishes locally observed,
  remotely observed, configured-only and undetermined database placement.
- Capability indicators for ABAP, Java, WebGUI, ICM HTTP(S), RFC Gateway,
  SNC, SCC, SAProuter, Web Dispatcher, IGS, Host Agent and the data tier.
  WebGUI host artifacts are reported separately from authoritative SICF state.
- SID and instance footprints for ABAP, Java, HANA, Host Agent, SCC,
  SAProuter, Web Dispatcher, IGS, ASE and related tools.
- Profiles and security parameters for RFC Gateway, Message Server, SNC,
  Start Service, ICM/Web Dispatcher, IGS, logging, RFC callback/UCON,
  identity/password policy, OS commands, HANA INI and secure-store paths.
- `secinfo`, `reginfo`, `prxyinfo`, `saprouttab`, message-server and ICM ACL
  presence, permissions, empty files and broad wildcard rules.
- Standard SAP paths, owners, Unix modes and Windows ACL summaries.
- Executable hashes; Windows Authenticode status and signer when available.
- Audit/system/trace files, PSE/Credv2/Java key stores, transport directories,
  SAP archives, Java `SecStore`/Download Manager artifacts and SAP GUI
  input-history metadata.
- SSFS metadata for ABAP/RSEC, HANA instance SSFS, HANA System-PKI,
  hdbuserstore, enhanced `LKY`/type-2 key protection and SAP Cloud Connector.
  It recognizes safe headers, record counts and data/key pair state without
  exposing record names, values or key bytes.
- A framework assessment map that says which areas were automated, which have
  only partial host evidence, and which require authenticated or active work.

Research traceability—including every reviewed OWASP CBAS project page, all
100 SSVS controls, all 74 playbook pages and every Attack Surface Discovery
check—is in [docs/OWASP_CBAS_COVERAGE.md](docs/OWASP_CBAS_COVERAGE.md).
The expanded source-by-source gap ledger covers the complete PySAP
documentation/notebooks and every HackTricks SAP/SAProuter reference in
[docs/SECURITY_SOURCE_GAP_ANALYSIS.md](docs/SECURITY_SOURCE_GAP_ANALYSIS.md).
The complete detection list and interpretation caveats are in
[docs/RULE_CATALOG.md](docs/RULE_CATALOG.md).
The topology evidence, database-port mappings, confidence levels and known
limitations are documented in
[docs/TOPOLOGY_MODEL.md](docs/TOPOLOGY_MODEL.md).

## Host-collector safety boundary

The host collectors do not:

- connect to or scan another host;
- call SAPControl, RFC, HTTP or administrative methods;
- try credentials, brute-force users or register an RFC program;
- exploit a vulnerability or execute an SAP/OS command;
- decrypt SSFS, PSE, Credv2 or SAP GUI history;
- read key bytes, private keys, passwords, tokens or SSFS values;
- label a product vulnerable from a version string alone; or
- change permissions, profiles, services, registry values or SAP data.

The generated report can still contain sensitive topology, usernames, paths,
profile values that are not classified as secrets, and hashes. Protect it as
audit evidence.

## Run on Linux/Unix

```bash
chmod 750 SAPaudit.sh
sudo ./SAPaudit.sh --output-dir ./reports
```

Elevation is recommended for complete process ownership, socket attribution
and protected-path access. A non-root run is supported and records the
coverage gap.

Useful options:

```text
--output-dir DIR       report directory; defaults to the current directory
--report FILE          explicit HTML path
--json FILE            explicit JSON path
--root DIR             alternate/offline filesystem root
--host-label NAME      override report hostname for an offline image
--report-note TEXT     add a scope/context note to HTML and JSON
--max-files N          cap per broad file scan; default 6000
--quiet                suppress progress except warnings/final paths
--no-color             disable terminal colors
```

Example offline audit:

```bash
sudo mount -o ro /dev/mapper/sap-root /mnt/sap-root
./SAPaudit.sh \
  --root /mnt/sap-root \
  --output-dir ./reports/offline
```

## Run on Windows

From an elevated Windows PowerShell 5.1 or PowerShell 7 terminal:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\SAPaudit.ps1 -OutputDirectory C:\Audit\SAPstract
```

Explicit paths:

```powershell
.\SAPaudit.ps1 `
  -ReportPath C:\Audit\SAPstract\host.html `
  -JsonPath C:\Audit\SAPstract\host.json
```

PowerShell also supports `-RootPath`, `-HostLabel`, `-ReportNote`, `-MaxFiles`
and `-Quiet`. On Windows it records discretionary
ACL summaries and Authenticode evidence in addition to the common
cross-platform fields.

`SAPaudit.ps1` is a single cross-version collector for both Windows
PowerShell 5.1 and PowerShell 7+. Its `#requires -version 5.1` declaration is
the minimum supported version, not a request to run only on 5.1. Keeping one
file ensures both runtimes use the same rules and report schema.

Both collectors display the original SAPstract startup banner during an
interactive run. Use `--quiet` or `-Quiet` to suppress it in automation.

## Output and interpretation

Both collectors emit schema `sapstract-audit/v2`.

The self-contained HTML defaults to a plain light theme and includes a
persistent light/dark toggle whose dark palette is neutral charcoal gray. It
contains:

- five section scores plus the backward-compatible aggregate index;
- a mini service/connection graph and explicit database-placement posture;
- a capability matrix and categorized service catalog;
- five separate severity-colored finding sections, each with its own filter,
  evidence, reason, remediation and source;
- systems, raw services/processes, separately grouped listeners/connections,
  and filesystem categories;
- SSFS, tools, profiles and filesystem/ACL evidence;
- an assessment map for the work that remains; and
- explicit collection coverage and limitations.

Technical inventories are collapsed into focused groups, and every table is
inside a horizontally scrollable region so wide evidence remains usable on a
small screen.

The JSON contains the backward-compatible `risk_score`, `risk_grade` and
`risk_label`, an executive `summary`, the five numeric `section_scores`, and
the same evidence in stable top-level arrays: `findings`, `systems`,
`services`, `processes`, `sockets`, `socket_candidates`, `paths`, `ssfs`,
`tools`, `profiles`, `coverage` and `assessment_catalog`. Accepted socket rows
include `confidence` and `basis`. Ownerless SAP-shaped ports that cannot be
corroborated remain in `socket_candidates`; they cannot create findings,
topology edges, capabilities or SAP evidence. A visible non-SAP process owner
rejects the port match instead of retaining routine ephemeral-port noise. The
additive `topology` object contains `database_posture`, `nodes`, `edges`,
categorized `services`, `capabilities` and `databases`.

Scoring is deterministic:

| Severity | Points per unique rule/asset |
|---|---:|
| Critical | 30 |
| High | 18 |
| Medium | 8 |
| Low | 3 |

Each section total is capped independently at 100. The legacy aggregate is
also retained and capped at 100 for existing automation. Grades are A (0–9),
B (10–24), C (25–49), D (50–74) and F (75–100). Fixing one issue can remove
several attack paths, while multiple findings can share one root cause; do
not interpret any score as a percentage probability.

An empty findings table does not mean the SAP landscape is secure. Read the
assessment map and coverage section. SAP roles, business data, custom ABAP
code, HANA database users, BTP controls, effective firewall reachability,
negotiated TLS/SNC, product patch levels and organizational processes require
separate authenticated or active validation.

## Basic validation

Before deployment, validate syntax and run a scoped local collection:

```bash
bash -n SAPaudit.sh
./tests/test-audit-correlation.sh
./SAPaudit.sh --help
./SAPaudit.sh --output-dir /tmp/sapstract-live
jq '.schema, .risk_score, .coverage, .assessment_catalog' \
  /tmp/sapstract-live/*.json
```

```powershell
$null = [System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path .\SAPaudit.ps1), [ref]$null, [ref]$parseErrors
)
$parseErrors
.\tests\Test-AuditCorrelation.ps1
.\SAPaudit.ps1 -OutputDirectory "$env:TEMP\sapstract-live"
```

## Research and rule maintenance

The research snapshot intentionally separates:

- safe host evidence that SAPstract can collect automatically;
- inventory/context that must not be scored as a vulnerability by itself; and
- active or authenticated assessment that requires authorization and a
  change-controlled procedure.

When adding a rule, require observable evidence, describe the security impact,
give a safe remediation, and cite a primary SAP source or the exact CBAS
project.

## License

The host-audit repository files are GPL-3.0; see [LICENSE](LICENSE). The
independently licensed Python SSFS component remains MIT; see
[python/LICENSE](python/LICENSE). MIT is GPL-compatible, and preserving the
subtree license keeps redistribution terms explicit.
