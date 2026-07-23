# OWASP CBAS research coverage

SAPstract uses the OWASP Core Business Application Security (CBAS) project as
its coverage root. This document records what was traversed, what was turned
into a passive host check, and what still requires authenticated or active
assessment. A missing local artifact is never treated as proof that an
application-layer control passes.

The follow-on review of every Attack Surface Discovery template, the complete
Pentest Playbook and PySAP documentation/notebook corpus, and every HackTricks
SAP/SAProuter reference is recorded in
[SECURITY_SOURCE_GAP_ANALYSIS.md](SECURITY_SOURCE_GAP_ANALYSIS.md). That ledger
contains the pinned snapshots, source-by-source disposition, newly added
rules, deliberately rejected heuristics, and one explicitly documented
unavailable retired article body.

## Crawl boundary and snapshot

Snapshot date: 2026-07-23.

The crawl includes every SAP-security project/resource directly linked by the
CBAS page, each project's versioned documentation and project-owned wiki, and
the research artifacts linked from those pages. Site chrome, donation links,
social profiles, generic tool documentation, and the unbounded outbound
reference graph are inventoried when relevant but are not recursively crawled.
That boundary keeps the result reproducible and focused on SAP risk.

| Resource | Snapshot | Material reviewed |
|---|---:|---|
| CBAS site | `aef1c1247f83` | Main page, project map, news/events, linked talks and research |
| SAP Pentest Playbook | `4b11e1947065` | All 74 Markdown pages |
| SAP Attack Surface Discovery | `9ebc0f7ba917` | 35 checks, 11 Nuclei workflows, tools and README |
| Attack Surface Discovery wiki | `4f1052c4fc81` | All four wiki pages |
| SAP Security Verification Standard | `058b1c953a96` | All 100 English JSON controls and corresponding Markdown |
| SAPKiln | `054e5bdb1423` | All 10 assessment modules and six bundled catalogs |
| HoneySAP | `a08c3948989b` | All service and configuration documentation |
| sncscan | `4ecffcd9c0c2` | SAProuter/DIAG SNC discovery, QoP parsing and limitations |
| SAP security research | `69c60fe1075f` | Both papers, CVE-2025-0055 write-up and defensive script |
| PySAP | local reference checkout | All top-level protocol/file-format modules and documentation indexes |
| SAP Security Matrix | live CBAS-linked page | 4 operational areas × 5 NIST lifecycle functions |

Direct CBAS resources covered are HoneySAP, PySAP, SAPKiln, SAP Pentest
Playbook, SAP Attack Surface Discovery, sncscan, SAP Security Verification
Standard, SAP Security Research, and the SAP Security Matrix.

### Direct-link disposition

Every SAP-risk-bearing link on the CBAS project page and its project tabs has
an explicit disposition:

| Link family | Disposition |
|---|---|
| HoneySAP | Repository, documentation, profiles and tests reviewed |
| PySAP | Local source checkout, top-level protocol/file modules and documentation indexes reviewed as recognition references |
| SAPKiln | Every assessment module and bundled catalog reviewed |
| SAP Pentest Playbook | Every content page reviewed and listed below |
| SAP Attack Surface Discovery | Every check, workflow, tool and project-owned wiki page reviewed |
| sncscan | Implementation, documentation, protocol scope and limitations reviewed |
| SAP Security Verification Standard | Every English control reviewed and listed below |
| SAP security research | Both papers, the CVE-2025-0055 material and defensive script reviewed |
| SAP Security Matrix | All four operational areas, five lifecycle functions and usage guidance reviewed |
| Linked CBAS talks | Event pages/descriptions reviewed; risk themes and unavailable/stale material are recorded below |
| Legacy `NO-MONKEY/CBAS` Internet Research link | Dead at the snapshot date; its maintained successor is SAP Attack Surface Discovery, which is fully inventoried below |
| Legacy SSVS and sncscan organization URLs | Redirect to the current repositories already captured above |

People/contributor profiles, contributor graphs, chat invitations, sponsors,
licenses, badges, generic GitHub/OWASP navigation, event logistics and social
sharing links do not contain SAP control material and were classified as
non-risk site chrome. They were not recursively expanded. This distinction
prevents a misleading claim that an unbounded graph of LinkedIn, GitHub,
conference and vendor navigation was security research.

## Resulting SAPstract coverage

| Area | Passive local evidence | Required follow-up |
|---|---|---|
| Host/OS | Services, processes, sockets, paths, ownership, Unix modes, Windows ACL summaries, binary hashes/signatures | OS baseline, account/group governance, EDR, vulnerability and patch evidence |
| ABAP/Java services | Dispatcher, Gateway, Message Server, ICM, IGS, Start Service, Java telnet, Web Dispatcher and SAProuter listeners/processes | Authorized zone-based reachability, protocol behavior, TLS/SNC and authentication validation |
| Profiles/ACLs | Security parameters; `secinfo`, `reginfo`, `prxyinfo`, `saprouttab`, message/ICM ACL metadata and wildcard checks | Effective runtime values, ordered-rule behavior and business dependency testing |
| SSFS/key material | ABAP/RSEC, HANA instance, HANA System-PKI, hdbuserstore, LKY/type-2 protection and SCC file metadata | Official-tool validation, rotation, backup/recovery, certificate and lifecycle review |
| HANA/ASE | Processes, sockets, standard paths, HANA INI files and secure-store metadata | Read-only authenticated user/role, password, audit, tenant, TLS, replication and patch review |
| SCC/BTP | SCC footprint, listeners, configs, Java key stores and SCC SSFS metadata | Authenticated SCC/BTP identity, destination, trust, HA, alert, audit, patch/JDK and role review |
| Logging | Local audit/system/trace presence, permissions and selected profile settings | SAL, SM21, RAL, table/workload/user logging, Java/HANA/BTP audit, forwarding, alerting and retention |
| Transports/supply chain | Transport/archive paths, tool permissions, hashes and Windows signatures | Import routes, approvals, signing, client libraries, Security Notes and product patch levels |
| ABAP authorization/code/data | Explicitly marked manual/authenticated | Standard users, SAP_ALL, S_RFC/S_RFCACL, critical tables/T-codes, RFC destinations, ATC/SCI/CVA and business-data controls |
| External exposure | Explicitly marked not performed | Separately authorized external or cross-zone inventory; a local listener alone cannot prove reachability |
| Governance/recovery | Explicitly marked manual | Policy, ownership, risk acceptance, incident response, backup/restore and failover exercises |

## SAP Pentest Playbook: every page

All 74 content pages were inspected. Several Java, cloud, object and option
pages are currently index/template stubs; they remain in this inventory so
their lack of substantive upstream content is visible rather than silently
ignored.

```text
Getting_Started/_index.md
Getting_Started/about.md
Getting_Started/contribute.md
Getting_Started/how_to.md
Getting_Started/supporter_and_contributors.md
Getting_Started/template/_index.md
Getting_Started/template/template_know-attack-vector.md
Getting_Started/template/template_object.md
Getting_Started/template/template_option.md
Getting_Started/template/template_reconnaissance.md
Other_SAP_Cloud_Solutions/_index.md
Other_SAP_Cloud_Solutions/_objects/_index.md
Other_SAP_Cloud_Solutions/_options/_index.md
Other_SAP_Solutions/SAP_ASE_DB/_index.md
Other_SAP_Solutions/SAP_ASE_DB/service_discovery.md
Other_SAP_Solutions/SAP_Cloud_Connector/_index.md
Other_SAP_Solutions/SAP_Cloud_Connector/sap_cloud_connector_services.md
Other_SAP_Solutions/SAP_Cloud_Connector/service_discovery.md
Other_SAP_Solutions/SAP_HANA_DB/_index.md
Other_SAP_Solutions/SAP_HANA_DB/service_discovery.md
Other_SAP_Solutions/SAP_Web_Dispatcher/_index.md
Other_SAP_Solutions/SAP_Web_Dispatcher/service_discovery.md
Other_SAP_Solutions/SAProuter/_index.md
Other_SAP_Solutions/SAProuter/service_discovery.md
Other_SAP_Solutions/_index.md
Other_SAP_Solutions/_objects/_index.md
Other_SAP_Solutions/_options/_index.md
SAP_ABAP_Platform/_index.md
SAP_ABAP_Platform/_objects/_index.md
SAP_ABAP_Platform/_objects/cg3z.md
SAP_ABAP_Platform/_objects/object_ws_file_copy.md
SAP_ABAP_Platform/_options/_index.md
SAP_ABAP_Platform/_options/executing_import.md
SAP_ABAP_Platform/_options/transport_files_destination.md
SAP_ABAP_Platform/known_attack_vectors/ABAP_code_review_process.md
SAP_ABAP_Platform/known_attack_vectors/_index.md
SAP_ABAP_Platform/known_attack_vectors/accessing_filesystem-read.md
SAP_ABAP_Platform/known_attack_vectors/accessing_filesystem-write.md
SAP_ABAP_Platform/known_attack_vectors/accessing_restricted_DB_tables.md
SAP_ABAP_Platform/known_attack_vectors/attack_SAPGUI_clients.md
SAP_ABAP_Platform/known_attack_vectors/code_verification.md
SAP_ABAP_Platform/known_attack_vectors/import_transport.md
SAP_ABAP_Platform/known_attack_vectors/latteral_movement.md
SAP_ABAP_Platform/known_attack_vectors/network_file_access.md
SAP_ABAP_Platform/known_attack_vectors/os_command_execution.md
SAP_ABAP_Platform/known_attack_vectors/password_hashes.md
SAP_ABAP_Platform/known_attack_vectors/transport_creation.md
SAP_ABAP_Platform/reconnaissance/_index.md
SAP_ABAP_Platform/reconnaissance/network_service_discovery/_index.md
SAP_ABAP_Platform/reconnaissance/network_service_discovery/sap_dispatcher.md
SAP_ABAP_Platform/reconnaissance/network_service_discovery/sap_icm.md
SAP_ABAP_Platform/reconnaissance/network_service_discovery/sap_igs.md
SAP_ABAP_Platform/reconnaissance/network_service_discovery/sap_message_server.md
SAP_ABAP_Platform/reconnaissance/network_service_discovery/sap_rfc_gateway.md
SAP_ABAP_Platform/reconnaissance/network_service_discovery/sap_start_service.md
SAP_ABAP_Platform/technology_overview/_index.md
SAP_Business_Technology_Platform/_index.md
SAP_Business_Technology_Platform/_objects/_index.md
SAP_Business_Technology_Platform/_options/_index.md
SAP_Business_Technology_Platform/known_attack_vectors/BTP_Destinations.md
SAP_Business_Technology_Platform/known_attack_vectors/_index.md
SAP_Business_Technology_Platform/known_attack_vectors/cloudfoundry_ssh.md
SAP_Business_Technology_Platform/known_attack_vectors/exposed_SOAP_services.md
SAP_Business_Technology_Platform/reconnaissance/_index.md
SAP_Business_Technology_Platform/reconnaissance/cf_url_pattern.md
SAP_Business_Technology_Platform/reconnaissance/kyma_url_pattern.md
SAP_Business_Technology_Platform/technology_overview/_index.md
SAP_NetWeaver_JAVA/_index.md
SAP_NetWeaver_JAVA/_objects/_index.md
SAP_NetWeaver_JAVA/_options/_index.md
SAP_NetWeaver_JAVA/known_attack_vectors/_index.md
SAP_NetWeaver_JAVA/reconnaissance/_index.md
SAP_NetWeaver_JAVA/technology_overview/_index.md
_index.md
```

The substantive risks were mapped as follows:

- Filesystem read/write: AL11, `S_DATASET`, logical/physical paths, CG3Z,
  `WS_FILE_COPY`, network shares and ICM file aliases map to permission,
  profile and manual ABAP-authorization/code review.
- Restricted database tables and hashes: SE16 variants, SM30/34, SQVI,
  RFC_READ_TABLE, USR/USH tables, R3trans, hdbsql and password-code versions
  require authenticated review; SAPstract never extracts hashes.
- OS command execution: SM49/SM69, RSBDCOS0, SAPXPG, `CALL 'SYSTEM'`,
  `EXECUTE_XX`, Gateway program start and service-user/database trust map to
  profile, executable/ACL permission and manual authorization checks.
- Lateral movement: dialog RFC credentials, technical users, S_RFC,
  S_RFCACL, trusted systems and lower-to-higher environment paths require
  authenticated landscape review.
- Transports and client attack paths map to transport permissions, archives,
  SAP GUI history/client footprint and manual import/client controls.
- BTP destinations, Cloud Foundry SSH and SOAP services are represented in
  the assessment map but cannot be proved from an on-premises host scan.

## Attack Surface Discovery: all YAML entries

There are 35 active checks and 11 composition workflows. SAPstract maps each
target service to passive local evidence, but does not run Nuclei, attempt
default credentials, request unauthenticated data, or probe a remote host.

```text
Checks (35)
sap_ase/sap-ase-backupserver-detect.yaml
sap_ase/sap-ase-dataserver-detect.yaml
sap_cloud_connector/sap-cc-default-credentials.yaml
sap_cloud_connector/sap-cloud-connector-detection.yaml
sap_dispatcher/sap-dispatcher-detect.yaml
sap_dispatcher/sap-dispatcher-login-info.yaml
sap_internet_communication_manager/cve-2021-40495.yaml
sap_internet_communication_manager/sap-netweaver-fiori-launchpad.yaml
sap_internet_communication_manager/sap-netweaver-icm-detect.yaml
sap_internet_communication_manager/sap-netweaver-info-leak.yaml
sap_internet_communication_manager/sap-netweaver-webgui.yaml
sap_internet_graphics_server/CVE-2018-2392.yaml
sap_internet_graphics_server/sap-igs-admin-commands.yaml
sap_internet_graphics_server/sap-igs-admin-config-check.yaml
sap_internet_graphics_server/sap-igs-detection.yaml
sap_java_webservices/sap-java-portal-detection.yaml
sap_java_webservices/sap-java-visual-composer-vuln-check.yaml
sap_java_webservices/sap-java-webservice-detection.yaml
sap_java_webservices/sap-netweaver-admin-detection.yaml
sap_message_server/sap-message-server-check-admin-port.yaml
sap_message_server/sap-message-server-check-monitor-status.yaml
sap_message_server/sap-message-server-http-detection.yaml
sap_message_server/sap-message-server-http-parameter-enum.yaml
sap_message_server/sap-message-server-instance-information-leak.yaml
sap_message_server/sap-message-server-internal-service-aclinfo-dump.yaml
sap_message_server/sap-message-server-tcp-service-detection.yaml
sap_rfc/sap-rfc-gateway-detect.yaml
sap_rfc/sap-rfc-gateway-monitor-detect.yaml
sap_rfc/sap-soap-rfc-detection.yaml
sap_rfc/sap-websocket-rfc-http-endpoint-discovery.yaml
sap_start_service/sap-start-service-detect.yaml
sap_web_dispatcher/sap-web-dispatcher-admin-portal.yaml
sap_web_dispatcher/sap-web-dispatcher-detection.yaml
saprouter/sap-router-info-leak.yaml
saprouter/sap-router.yaml

Workflows (11)
wokflow-sap-internet-graphics-server.yaml
workflow-sap-all.yaml
workflow-sap-ase.yaml
workflow-sap-cc.yaml
workflow-sap-dispatcher.yaml
workflow-sap-internet-communication-manager.yaml
workflow-sap-java-webservices.yaml
workflow-sap-message-server.yaml
workflow-sap-rfc.yaml
workflow-sap-web-dispatcher.yaml
workflow-saprouter.yaml
```

All four project-owned wiki pages were inspected:

```text
Additional-Tools-&-Helper.md
Getting-Started.md
Home.md
_Sidebar.md
```

They add an Nmap-to-Nuclei conversion workflow and an ABAP report that calls
every remote-enabled function module without credentials. They also enumerate
SAProuter, SCC, IGS, Message Server, Dispatcher, RFC Gateway, Start Service,
Web Dispatcher, HANA and ASE as external-discovery targets. The workflows are
active tests: they are documented as separately authorized follow-up, not
built into the local collector.

## SSVS: all 100 controls

The current JSON identifies itself as version 0.8 while its filename says
0.8.1. Some verification fields are TODO and three HANA IDs retain a literal
`copy` suffix. SAPstract preserves those upstream identifiers and does not
claim SSVS certification.

Status key:

- `A` — local automated evidence directly contributes.
- `P` — host footprint/configuration contributes, but authenticated/manual
  evidence is still required.
- `M` — manual or authenticated evidence is required.

| Technology | Status | Every upstream control ID |
|---|---|---|
| All (1) | P | `PT-I-PT-M01-001` |
| EAM for SAP (4) | M | `PT-P-PT-M01-1300`, `PT-P-PT-M01-1303`, `DT-P-CM-M01-1301`, `PT-A-IP-M01-1302` |
| LNW-Soft PMS (1) | M | `PT-A-AC-M01-1202` |
| Linux (1) | P | `PT-P-IP-M01-012` |
| Operating System (1) | A | `PT-P-AC-M01-001` |
| RFC Connections (2) | P | `PT-I-IP-M01-005`, `PT-I-IP-M01-006` |
| SAP ABAP (24) | P/M | `PT-C-IP-M01-001`, `IY-C-RA-M01-002`, `IY-C-RA-M01-004`, `PT-P-DS-M01-006`, `PT-P-IP-M01-003`, `PT-P-IP-M01-005`, `PT-I-IP-M01-001`, `PT-A-AC-M01-001`, `PT-A-AC-M01-013`, `PT-PA-IP-M01-001`, `PT-A-AC-M01-011`, `IY-C-RA-M01-001`, `PT-P-IP-M01-001`, `PT-P-DS-M01-009`, `PT-A-AC-M01-009`, `PT-P-DS-M01-002`, `PT-P-PT-M01-001`, `PT-P-IP-M01-004`, `IY-C-RA-M01-005`, `PT-P-PT-M01-014`, `PT-P-DS-M01-005`, `IY-C-RA-M01-003`, `PT-P-PT-M01-009`, `PT-P-PT-M02-012` |
| SAP BTP (25) | M/P | `PT-P-AC-M02-922`, `PT-P-AC-M01-903`, `DT-P-CM-M02-918`, `PT-P-AC-M03-910`, `DT-P-CM-M01-919`, `PT-P-AC-M03-901`, `PT-P-AC-M02-904`, `PT-P-AC-M01-905`, `PT-P-PT-M01-907`, `PT-P-AC-M02-902`, `DT-P-DP-M01-900`, `PT-P-PT-M01-924`, `PT-P-MA-M01-914`, `PT-P-MA-M02-913`, `PT-P-IP-M02-909`, `PT-P-AC-M01-923`, `PT-P-MA-M03-912`, `PT-P-IP-M02-916`, `PT-P-AC-M01-911`, `PT-P-IP-M02-908`, `PT-P-PT-M03-920`, `PT-P-IP-M03-915`, `PT-P-AC-M03-921`, `PT-P-PT-M02-906`, `PT-P-IP-M01-917` |
| SAP ERP (7) | P/M | `DT-P-AE-M01-001`, `DT-P-AE-M01-006`, `DT-P-AE-M01-005`, `DT-P-AE-M01-004`, `DT-P-AE-M01-002`, `DT-P-AE-M01-007`, `DT-P-AE-M01-003` |
| SAP GUI (1) | P | `PT-IP-PT-M01-001` |
| SAP HANA (20) | P/M | `PT-I-PT-M01-001 copy`, `PT-A-AC-M02-002`, `PT-A-AC-M01-018`, `PT-A-AC-M01-010`, `PT-A-AC-M01-017`, `PT-I-PT-M01-002 copy`, `PT-P-IM-M02-001`, `PT-P-IP-M01-014`, `PT-I-PT-M01-003 copy`, `DT-A-AE-M02-001`, `PT-PA-AC-M01-001`, `PT-A-AC-M01-016`, `PT-P-DS-M01-008`, `PT-P-PT-M01-008`, `DT-A-AE-M01-001`, `PT-A-AC-M01-014`, `PT-A-AC-M02-003`, `PT-A-AC-M03-001`, `PT-A-AC-M02-001`, `DT-A-AE-M03-001` |
| SAP Java (10) | P/M | `PT-A-AC-M01-012`, `PT-P-PT-M01-015`, `PT-P-PT-M02-013`, `PT-P-PT-M01-007`, `PT-P-IP-M01-010`, `PT-PA-IP-M01-002`, `PT-P-DS-M01-007`, `PT-P-DS-M01-003`, `PT-P-DS-M01-010`, `PT-P-PT-M01-010` |
| SAProuter (2) | P | `PT-I-PT-M01-002`, `PT-I-PT-M01-003` |
| Windows OS (1) | P | `PT-P-IP-M01-013` |

Host automation is strongest for OS permissions, security artifact presence,
SSFS/PSE metadata, service/listener exposure, selected profile/ACL controls,
tool integrity, and local logging artifacts. Authorization, role, business
data, custom code, BTP, HANA database state and organizational process
controls remain explicitly manual/authenticated.

## SAPKiln: every module and catalog

SAPKiln contains ten GUI-driven modules:

1. Attempt login with default SAP credentials.
2. Enumerate accessible T-codes.
3. Enumerate accessible tables.
4. Enumerate SAP_ALL profile usage.
5. Enumerate password policies.
6. Execute OS commands through RSBDCOS0.
7. Execute OS commands through SAPXPG.
8. Enumerate weak password hashes by hash data.
9. Enumerate users with weak password code versions.
10. Enumerate instances/RFC paths for lateral movement.

Its bundled catalogs contain 54 large/16 small T-codes, 24 large/11 small
table entries, two default credential records and eight password-policy
parameters. These checks require SAP GUI authentication; default-password
attempts and command execution are intrusive. SAPstract records them as
manual/authenticated work and never performs them.

## HoneySAP, PySAP and sncscan

HoneySAP documents SAProuter, Dispatcher and a generic forwarding service.
Its configuration exposes useful recognition concepts such as a route table,
information/admin behavior and optional passwords. SAPstract maps these to
SAProuter process/port/profile/route-table evidence without emulating a
service.

PySAP provides protocol references for NI, DIAG, Enqueue, Router, Message
Server, SNC, IGS, RFC and HDB, and file-format references for SAR/CAR,
Credv2, PSE and SSFS. SAPstract uses those as independent recognition
references only. It does not copy PySAP packet code and has no PySAP, Scapy
or Python runtime dependency.

sncscan actively inspects SAProuter and DIAG SNC; RFC support is described as
in development in the reviewed snapshot. It highlights
`snc/data_protection/{min,use,max}`, `snc/only_encrypted_gui`, mechanism/library
identity and enforcement. SAPstract checks local profile evidence; negotiated
QoP remains an authorized follow-up.

## CBAS research papers

The 37-page *State of SAP Exposure in 2025/2026* paper reports a
November 2025–January 2026 non-intrusive IPv4 study. Its service set is fully
represented in the external-exposure follow-up: SAProuter, Dispatcher, RFC
Gateway, Message Server internal/HTTP, Cloud Connector and NetWeaver Java.
The paper reports thousands of exposed services, internal topology/profile
leakage and still-reachable critical vulnerabilities, including
CVE-2025-31324. SAPstract does not infer Internet exposure or a CVE from a
local listener/version; it calls for a separate authorized external inventory
and patch/Security Note review.

*SAP History Fail: Why XOR is Still Not Secure* covers SAP GUI for Java,
Windows and HTML. It shows that Java history was stored as plaintext
serialized data and older Windows history used reversible, reused-key XOR
encoding. The history can contain IDs, personal/business data, table names and
process context even though password fields are excluded. The paper maps to
CVE-2025-0055 and CVE-2025-0056 and recommends patching, minimizing/disabling
history, excluding sensitive fields and deleting old data through controlled
procedures. SAPstract detects only history-file/directory metadata and never
reads or decodes it.

## SAP Security Matrix and linked events

The Security Matrix's 20 cells are all retained: Integration, Platform,
Access and Customization crossed with Identify, Protect, Detect, Respond and
Recover. These are organizational maturity dimensions, so the HTML report
marks governance and response as manual instead of manufacturing a host-only
pass.

The CBAS events page also links these security talks. Their available event
descriptions were reviewed and their risk themes overlap the versioned project
corpus above:

- BSides Dresden 2025 — BTP misconfiguration, over-permissioned services,
  vulnerable Kyma flows and unsafe Cloud Connector shortcuts. The CBAS event
  link currently resolves to an older conference landing page, so the title
  and public talk description are retained with that limitation.
- BSides Athens 2025 — identify, exploit and defend SAP with open-source
  projects; the event archive confirms the session but exposes no substantive
  abstract beyond the title.
- German OWASP Day 2024 — real-world misconfiguration, insecure code,
  authentication failures and SNC signing/encryption enforcement using
  sncscan.
- BSides Frankfurt 2024 — identify, exploit and defend SAP with open-source
  projects; the linked video page exposes no transcript in its static page.

No talk-only control was found that is absent from the playbook, SSVS,
sncscan, Attack Surface Discovery, SAPKiln, BTP assessment map or SAP security
research already mapped above.

## Known upstream limitations and contribution opportunities

- SSVS is a valuable control catalog but is pre-1.0, contains TODO
  verification text, version-label inconsistency and duplicate `copy` IDs.
  Contributions should stabilize unique IDs, machine-readable verification
  requirements and evidence types.
- The playbook has useful ABAP/service material but multiple Java/cloud index
  and template pages are empty. Contributions can add defensive verification
  and remediation content, especially for Java, HANA, SCC and BTP.
- Attack Surface Discovery is an active network scanner. A useful contribution
  would add explicit authorization/safety metadata, expected false positives,
  version applicability and a defensive mapping from every active check to a
  local configuration or authenticated control.
- SAPKiln's GUI automation demonstrates important authorization risks, but
  default-logon attempts and OS execution are not baseline-audit operations.
  Read-only, evidence-oriented modules and safe failure semantics would make
  it more suitable for continuous assurance.
- PySAP is broad and valuable for protocol/file research, but a passive host
  auditor does not need Scapy packet construction. SAPstract deliberately
  remains a standalone shell/PowerShell implementation.

## Expanded source-review implementation

The follow-on source review added directly observable findings for RFC
authorization/callback/UCON/trusted-ticket settings, SAP* fallback and selected
password policy, SNC enablement, internal Message Server communication,
HttpOnly/HTTPS/Host handling, SAProuter `-X` and positional route wildcards,
Security Audit Log profile state, Enqueue isolation, and SAP database listener
segmentation. It also added ASE port recognition and Java
`SecStore.properties`, `SecStore.key`, and `dlmanager.conf` metadata.

These additions do not turn the collector into a network scanner. Default
account tests, endpoint/CVE probes, transaction and table authorization,
effective callback/UCON lists, dynamic audit configuration, Security Note
applicability, TLS/SNC negotiation, and business-code review remain explicit
authorized follow-up in the 22-area assessment catalog.

## Primary links

- [OWASP CBAS](https://owasp.org/www-project-core-business-application-security/)
- [SAP Pentest Playbook](https://playbook.securitysilverbacks.com/)
- [SAP Attack Surface Discovery](https://github.com/SecuritySilverbacks/SAP-AttackSurfaceDiscovery)
- [SAP SSVS](https://github.com/SecuritySilverbacks/CBAS-SAP-SecurityVerificationStandard)
- [SAP security research](https://github.com/SecuritySilverbacks/sap-security-research)
- [HoneySAP](https://github.com/OWASP/HoneySAP)
- [PySAP](https://github.com/OWASP/pysap)
- [SAPKiln](https://github.com/OWASP/SAPKiln)
- [sncscan](https://github.com/SecuritySilverbacks/sncscan)
- [HackTricks SAP page](https://hacktricks.wiki/en/network-services-pentesting/pentesting-sap.html)
