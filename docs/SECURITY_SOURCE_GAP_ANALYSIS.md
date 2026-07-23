# SAP security source review and gap analysis

This document is the traceability ledger for the SAPstract host-audit rules.
It records what was reviewed, what the source can actually prove, what
SAPstract can prove from local evidence, and what still requires an
authenticated or active assessment.

The review was performed on 2026-07-23. It is intentionally conservative:

- a local listener is not reported as Internet-reachable;
- a version string is not treated as proof that a CVE is present;
- a missing profile parameter is not treated as a failure because kernel
  defaults, dynamic configuration, and release-specific behavior differ;
- SAPstract never tries default passwords, changes configuration, invokes
  administrative protocol operations, or reads secret values;
- old community recommendations are not implemented when they conflict with
  current SAP documentation or have ambiguous comparison semantics.

## Pinned source snapshots

| Source | Reviewed snapshot or retrieval |
|---|---|
| SecuritySilverbacks SAP Attack Surface Discovery | `9ebc0f7ba917eb30f8c703e9992fe7281f664a07` |
| SecuritySilverbacks SAP Pentest Playbook | `4b11e1947065522c4987b54270da02b930f6a0de` |
| OWASP PySAP | `ab095eb630941d2e64071ff0f6fd230e7a97333b` |
| HackTricks source | `7aa23be102ef0ed6f60c191d6f20186db40d08b3` |
| davehardy20/SAP-Stuff | `8809473fe3923ea7d2c4f840109f82d52da18684` |
| shipcod3/mySapAdventures | `63bdd7c7f1f55e21f6813cfd514ba543c6fba4c8` |
| Retired web references | Original pages, current owner copies, or dated Internet Archive captures identified below |

## Missed controls found during this review

This is the implementation ledger. “Automated” means a finding is emitted
only when the insecure value or artifact is directly observed. “Assessment”
means SAPstract records the required authorized follow-up without claiming a
pass or failure.

| Gap found | Disposition |
|---|---|
| `auth/rfc_authority_check=0` disables `S_RFC` checks | Automated profile rule |
| `rfc/callback_security_method` below secure value `3` leaves callback allow-list enforcement incomplete | Automated profile rule |
| `ucon/rfc/active=0` leaves UCON RFC inactive | Automated profile rule |
| `rfc/allowoldticket4tt` permits the old target-independent trusted/trusting ticket | Automated profile rule when explicitly enabled |
| `login/no_automatic_user_sapstar=0` permits automatic SAP* fallback | Automated profile rule |
| `login/show_detailed_errors` can disclose whether a user/client/password condition caused a failed logon | Automated profile rule when explicitly enabled |
| `rsau/enable=0` disables static Security Audit Log profile processing | Automated profile rule, with dynamic-configuration caveat |
| `snc/enable=0` means SNC is disabled | Automated profile rule |
| `system/secure_communication` not `ON` leaves internal server communication unprotected | Automated profile rule when explicitly configured |
| `icf/set_HTTPonly_flag_on_cookies` values 1–3 disable HttpOnly on some or all ICF cookies | Automated profile rule |
| `login/ticket_only_by_https=0` permits logon tickets over non-TLS HTTP | Automated profile rule |
| `icm/HTTP/allow_invalid_host_header=TRUE` accepts protocol-invalid Host headers | Automated profile rule |
| SAProuter started with `-X` explicitly permits routing back to itself for remote administration | Automated process-command rule |
| `saprouttab` target-host wildcards enable over-broad routing and are a prerequisite in the documented CVE-2022-27668 chain | Strengthened ACL rule |
| Enqueue listeners were being classified only as generic 32NN DIAG | Process-aware listener classification and finding |
| SAP ASE ports 4901–4999 were absent from listener classification | Port classification and database-exposure rule |
| HANA/ASE SQL listeners were inventoried but did not produce a segmentation/TLS validation finding | Database-listener rule |
| Java `SecStore.properties`, `SecStore.key`, and Download Manager `dlmanager.conf` were not inventoried as secret-bearing artifacts | Metadata/permission inventory; no content read |
| Default-account state, RFC destinations, UCON function allow-lists, callback allow-lists, SAL filters, and transaction authorization cannot be proven from host files | Expanded authenticated assessment catalog |
| HTTP endpoints and the nuclei CVE probes require network interaction and patch context | Expanded separately authorized active-assessment catalog |
| SAProuter CVE-2022-27668 and RFC CVEs cannot be inferred safely from a filename or banner | Patch/Note assessment, never a guessed automated finding |

## SecuritySilverbacks Attack Surface Discovery

All 35 active templates and all 11 workflows were read in full. Workflows only
compose the active templates and do not add independent detection logic.

| Template | SAPstract coverage decision |
|---|---|
| `sap_ase/sap-ase-backupserver-detect.yaml` | Recognize ASE process and ports; protocol probe remains authorized active work |
| `sap_ase/sap-ase-dataserver-detect.yaml` | Recognize ASE process and ports; protocol probe remains authorized active work |
| `sap_cloud_connector/sap-cc-default-credentials.yaml` | Never try credentials; authenticated standard-account review |
| `sap_cloud_connector/sap-cloud-connector-detection.yaml` | SCC service/process/path/SSFS/keystore/listener footprint |
| `sap_dispatcher/sap-dispatcher-detect.yaml` | Dispatcher process and 32NN listener |
| `sap_dispatcher/sap-dispatcher-login-info.yaml` | Login-information probe and enumeration validation remain active work |
| `sap_internet_communication_manager/cve-2021-40495.yaml` | Patch/Note and authorized endpoint verification; no banner-based verdict |
| `sap_internet_communication_manager/sap-netweaver-fiori-launchpad.yaml` | Fiori endpoint validation remains active work |
| `sap_internet_communication_manager/sap-netweaver-icm-detect.yaml` | ICM process/listener/profile footprint |
| `sap_internet_communication_manager/sap-netweaver-info-leak.yaml` | `/sap/public/info` validation remains active work |
| `sap_internet_communication_manager/sap-netweaver-webgui.yaml` | Host artifact plus explicit SICF/WebGUI follow-up |
| `sap_internet_graphics_server/CVE-2018-2392.yaml` | Patch/Note and authorized endpoint verification |
| `sap_internet_graphics_server/sap-igs-admin-commands.yaml` | IGS administration profile check and active follow-up |
| `sap_internet_graphics_server/sap-igs-admin-config-check.yaml` | IGS listener/profile footprint and active follow-up |
| `sap_internet_graphics_server/sap-igs-detection.yaml` | IGS process and port families |
| `sap_java_webservices/sap-java-portal-detection.yaml` | Java process/port footprint and portal validation |
| `sap_java_webservices/sap-java-visual-composer-vuln-check.yaml` | Authorized endpoint and patch validation |
| `sap_java_webservices/sap-java-webservice-detection.yaml` | Java process/port footprint; web-service inventory remains active/authenticated |
| `sap_java_webservices/sap-netweaver-admin-detection.yaml` | NWA exposure remains authorized active validation |
| `sap_message_server/sap-message-server-check-admin-port.yaml` | `ms/admin_port` profile rule |
| `sap_message_server/sap-message-server-check-monitor-status.yaml` | `ms/monitor` profile rule |
| `sap_message_server/sap-message-server-http-detection.yaml` | 81NN/444NN listener classification |
| `sap_message_server/sap-message-server-http-parameter-enum.yaml` | Locally observed parameters evaluated; HTTP enumeration remains active work |
| `sap_message_server/sap-message-server-instance-information-leak.yaml` | 36NN exposure plus active information-leak validation |
| `sap_message_server/sap-message-server-internal-service-aclinfo-dump.yaml` | 39NN isolation and message ACL metadata |
| `sap_message_server/sap-message-server-tcp-service-detection.yaml` | 36NN/39NN process/listener footprint |
| `sap_rfc/sap-rfc-gateway-detect.yaml` | 33NN/48NN and Gateway process footprint |
| `sap_rfc/sap-rfc-gateway-monitor-detect.yaml` | `gw/monitor`, `gw/sim_mode`, and active monitor validation |
| `sap_rfc/sap-soap-rfc-detection.yaml` | SOAP RFC endpoint/function authorization remains active/authenticated |
| `sap_rfc/sap-websocket-rfc-http-endpoint-discovery.yaml` | WebSocket RFC endpoint remains active work |
| `sap_start_service/sap-start-service-detect.yaml` | Start Service process, 5NN13/5NN14, protected web methods |
| `sap_web_dispatcher/sap-web-dispatcher-admin-portal.yaml` | Web Dispatcher process/profile plus active admin-portal validation |
| `sap_web_dispatcher/sap-web-dispatcher-detection.yaml` | Web Dispatcher process/listener/profile footprint |
| `saprouter/sap-router-info-leak.yaml` | SAProuter process/3299/saprouttab footprint; information request remains active work |
| `saprouter/sap-router.yaml` | SAProuter process and port detection |

Reviewed workflow files:

`wokflow-sap-internet-graphics-server.yaml`, `workflow-sap-all.yaml`,
`workflow-sap-ase.yaml`, `workflow-sap-cc.yaml`,
`workflow-sap-dispatcher.yaml`,
`workflow-sap-internet-communication-manager.yaml`,
`workflow-sap-java-webservices.yaml`, `workflow-sap-message-server.yaml`,
`workflow-sap-rfc.yaml`, `workflow-sap-web-dispatcher.yaml`, and
`workflow-saprouter.yaml`.

The Message Server parameter-enumeration template also supplied a broad
parameter inventory. SAPstract implements only values whose semantics can be
supported by SAP documentation and direct local evidence. Parameters such as
login policy thresholds, CORS, SameSite, RAL, and application-specific ICM
rules remain in the authenticated review because a single universal value is
not safe across releases and application dependencies.

## SecuritySilverbacks SAP Pentest Playbook

All 74 Markdown files (1,815 lines) were read. The substantive coverage was:

- SAP ASE: Data Server 4901, Backup Server 4902, Job Scheduler 4903, and
  configurable range 4901–4999.
- SAP HANA: SQL port family 3NN15 and TLS/authenticated database review.
- SAP Web Dispatcher: detection, admin portal, TLS, ACLs, and request
  smuggling context.
- SAProuter: 3299, information disclosure, route-table scope, pivot risk, and
  patch validation.
- SAP Cloud Connector/BTP: footprint plus authenticated identity, trust,
  destination, role, patch, alerting, and HA review.
- ABAP Dispatcher, ICM, IGS, Message Server, RFC Gateway, and Start Service:
  their port families, administrative functions, ACLs, and information leaks.
- ABAP business risk: filesystem read/write, database table access, OS command
  execution, custom-code review, transports, password hashes, network shares,
  lateral movement, and SAP GUI clients.
- BTP: destinations, exposed SOAP services, Cloud Foundry SSH, Kyma/CF URL
  patterns, and cloud control-plane review.

The complete reviewed file inventory is:

```text
LICENSE.md
README.md
content/Getting_Started/{_index,about,contribute,how_to,supporter_and_contributors}.md
content/Getting_Started/template/{_index,template_know-attack-vector,template_object,template_option,template_reconnaissance}.md
content/Other_SAP_Cloud_Solutions/{_index,_objects/_index,_options/_index}.md
content/Other_SAP_Solutions/{_index,_objects/_index,_options/_index}.md
content/Other_SAP_Solutions/SAP_ASE_DB/{_index,service_discovery}.md
content/Other_SAP_Solutions/SAP_Cloud_Connector/{_index,sap_cloud_connector_services,service_discovery}.md
content/Other_SAP_Solutions/SAP_HANA_DB/{_index,service_discovery}.md
content/Other_SAP_Solutions/SAP_Web_Dispatcher/{_index,service_discovery}.md
content/Other_SAP_Solutions/SAProuter/{_index,service_discovery}.md
content/SAP_ABAP_Platform/{_index,technology_overview/_index}.md
content/SAP_ABAP_Platform/_objects/{_index,cg3z,object_ws_file_copy}.md
content/SAP_ABAP_Platform/_options/{_index,executing_import,transport_files_destination}.md
content/SAP_ABAP_Platform/known_attack_vectors/{_index,ABAP_code_review_process,accessing_filesystem-read,accessing_filesystem-write,accessing_restricted_DB_tables,attack_SAPGUI_clients,code_verification,import_transport,latteral_movement,network_file_access,os_command_execution,password_hashes,transport_creation}.md
content/SAP_ABAP_Platform/reconnaissance/_index.md
content/SAP_ABAP_Platform/reconnaissance/network_service_discovery/{_index,sap_dispatcher,sap_icm,sap_igs,sap_message_server,sap_rfc_gateway,sap_start_service}.md
content/SAP_Business_Technology_Platform/{_index,technology_overview/_index}.md
content/SAP_Business_Technology_Platform/{_objects,_options,reconnaissance}/_index.md
content/SAP_Business_Technology_Platform/known_attack_vectors/{_index,BTP_Destinations,cloudfoundry_ssh,exposed_SOAP_services}.md
content/SAP_Business_Technology_Platform/reconnaissance/{cf_url_pattern,kyma_url_pattern}.md
content/SAP_NetWeaver_JAVA/{_index,technology_overview/_index}.md
content/SAP_NetWeaver_JAVA/{_objects,_options,known_attack_vectors,reconnaissance}/_index.md
content/_index.md
```

## OWASP PySAP

The complete documentation and notebook source were reviewed:

- 18 RST files under `docs/`;
- protocol notebooks for DIAG, Enqueue, HDB, IGS, Message Server, NI, RFC,
  SAProuter, and SNC;
- file-format notebooks for SAPCAR, Credv2, PSE, and SSFS;
- all example scripts and their configuration data;
- relevant protocol and file-format modules used by those documents.

Important additions or confirmations:

- Enqueue has monitor/administrative operations and historic DoS exposure, so
  its listener must not be silently labeled only as DIAG.
- Message Server internal connections can expose parameters and support
  administrative operations; 39NN requires cluster-only isolation.
- RFC Gateway monitor, external registration/start, callbacks, SNC, and UCON
  are separate controls.
- Download Manager configurations before fixed releases stored or weakly
  protected credentials. `dlmanager.conf` is inventoried as secret-bearing
  metadata; version-specific decryption is not performed.
- SAR/CAR signature and tool-version validation belongs in the software
  supply-chain assessment.
- Credv2, PSE, and SSFS are distinct formats. Presence is not a vulnerability,
  but permissions, pairing, key lifecycle, and official-tool validation are
  security relevant.
- SSFS integrity and encryption do not make copied data harmless when key
  material is also accessible.
- HANA client TLS behavior must be validated for encryption, certificate
  validation, and hostname validation rather than inferred from an open port.

PySAP is used only as research input. SAPstract has no PySAP, Scapy, Python,
CDN, or packet-crafting runtime dependency.

## HackTricks page and references

The complete current `pentesting-sap.md` and linked SAProuter page were read.
Every item in the References section was then reviewed as follows:

| Reference | Retrieval and review status | Relevant result |
|---|---|---|
| Rapid7, *SAP Penetration Testing Using Metasploit* | Original 50-page PDF recovered and all pages extracted/read | Host Control, SAPControl, ICF, SOAP RFC, SMB relay, SAProuter, ConfigServlet, and service discovery |
| davehardy20/SAP-Stuff | Complete three-file repository read at pinned commit | Bizploit clients, registered RFC servers, SAProuter, ICM, RFC privileges, external registration, and default-account tests |
| ERPScan, *Default passwords for access to the application* | 2016-01-14 Internet Archive capture read in full | SAP*, DDIC, SAPCPIC, TMSADM, EARLYWATCH; SAP* must be locked/retained and automatic fallback disabled |
| SAP Community, *List of ABAP transaction codes related to SAP security* | 2023-10-03 Internet Archive capture read in full | 46 security/admin transactions plus CUA/HR additions; authenticated authorization review only |
| ERPScan, *Breaking SAP Portal* | Original 84-page PDF recovered and read | Java audit/logging, ConfigServlet, verbs/invoker, `SecStore` pair, descriptors, XXE/SSRF, upload controls, log protection |
| ERPScan, *Top 10 most interesting SAP vulnerabilities and attacks* | Original presentation recovered and read | Historic attack primitives retained as patch/configuration context, not current vulnerability assertions |
| Onapsis, *Assessing the security of SAP ecosystems with bizploit: Discovery* | Original URL now redirects and no page-body capture was found in Internet Archive; linked Bizploit workflow and the complete archived Bizploit package inventory were reviewed instead | Clients, application servers, registered RFC servers, SAProuter, ICM URL scan, Gateway monitor, RFC privilege and default-account discovery |
| Exploit-DB 43859, *Hardcore SAP Penetration Testing* | Original 40-page PDF recovered and read | Java descriptors, UDDI, `SecStore`, SSRF/RCE, old password/storage risks |
| Infosec Institute, *Pentesting SAP applications: An introduction* | 2023-06-04 Internet Archive capture read in full | Default users, DIAG/RFC cleartext risk, SNC levels, account-lockout review |
| shipcod3/mySapAdventures | Complete repository README and attached Bizploit package inventory read at pinned commit | Discovery, default accounts, SAP GUI, web paths, ICF info, management interfaces, RFC/SOAP operations |
| Onapsis, *SAP RFC vulnerabilities in 2023* | Current article read in full; linked SEC Consult RFC research paper also read in full | RFC CVEs, exact SAP Notes, SNC QoP, authorization checks, callback/UCON guidance, old trusted tickets |
| Onapsis, *Risks of SAP RFC callbacks* | Current article read in full | Callback allow-lists, audit/simulation migration, `rfc/callback_security_method` |

The recursively linked SAProuter sources were also reviewed:

- Rapid7, *Piercing SAProuter with Metasploit*: 3299 exposure, administrative
  information leakage, route/ACL mapping, internal hostname/service
  enumeration, and pivoting.
- SEC Consult, *Improper Access Control in SAP SAProuter*: CVE-2022-27668,
  SAP Note 3158375, the `0.0.0.0:3299` loopback bypass, `saprouttab`
  wildcard prerequisite, and the recommendation to remove wildcard target
  values.

## Rejected or manual-only recommendations

These items are deliberately not emitted as automatic failures:

- Default-password login attempts: intrusive, can lock accounts, and require
  explicit authorization.
- `login/fails_to_user_lock < 5`: the cited HackTricks condition is directionally
  inconsistent with account-lockout hardening and conflicts with the older
  PySAP threshold. Review the current SAP recommendation and local policy.
- `rdisp/gui_auto_logout < 5`: a shorter timeout is not inherently weaker.
- `auth/object_disabling_active=Y`: security depends on the effective
  authorization-object design, not this value in isolation.
- `auth/no_check_in_some_cases=Y`: semantics and release compatibility require
  authenticated SAP review.
- `icm/security_log=2`: the cited source does not provide enough unambiguous
  semantics for a universal failure.
- `icm/HTTP/samesite`: `None`, `Lax`, and `Strict` are application/context
  choices; only `OFF` is clearly an absence of the attribute, and even that
  requires application context.
- A missing `snc/enable`, UCON, callback, HTTP cookie, or internal-communication
  parameter: absence in one profile is not proof of the effective value.
- CVE status from a banner or executable name: patch levels and backports must
  be verified through SAP-supported inventory and applicable Security Notes.
- Active Nuclei, Metasploit, PySAP, or Bizploit requests: these are represented
  in the assessment map and must run only in a separately authorized,
  change-controlled test.

## Implementation and verification status

1. Complete — directly observable profile, process, ACL, port, and artifact
   rules were added to both collectors.
2. Complete — Bash and PowerShell use matching rule IDs, severities, evidence,
   remediation, sources, assessment areas, and section mappings.
3. Development validation covered every newly automated rule without using a
   real credential or key; those fixtures are intentionally excluded from the
   public source repository.
4. Complete — the rule catalog now contains 72 rules and the assessment
   catalog contains 22 coverage areas.
5. Complete — development validation covered each rule, listener
   classification, artifact category, redaction behavior, section score, and
   Bash/PowerShell parity.
6. Complete — the public repository contains only source, packaging metadata,
   licenses, and source documentation; generated reports are excluded.
7. Complete — Bash syntax, report behavior, rule/catalog parity, Python
   interoperability, CLI, packaging, and PowerShell 7 behavior were validated
   before publication cleanup. Windows PowerShell 5.1 runtime execution still
   requires a Windows validation host; the shared script retains its
   `#requires -version 5.1` baseline and avoids PowerShell-7-only syntax.
