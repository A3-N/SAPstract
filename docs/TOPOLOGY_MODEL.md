# SAP service topology and database-placement model

SAPstract builds a passive, host-local topology from evidence already
collected by the audit. It does not connect to a peer, resolve an SAP
destination, query SICF, call SAPControl, inspect database catalogs or test
firewall reachability.

## Evidence model

The HTML mini graph and JSON `topology` object use:

- local service-manager entries;
- recognized SAP processes and their owners;
- local listening sockets;
- established sockets owned by recognized SAP processes;
- standard SAP/database paths; and
- selected non-secret profile parameters.

The central graph node is the audited host. SAP processes, services and
listeners are collapsed into technical service groups. Established
connections become database or generic remote-peer nodes. Every edge retains
its source evidence and confidence; the full raw inventories remain in their
original JSON arrays.

`topology` is additive to schema `sapstract-audit/v2`:

```json
{
  "topology": {
    "database_posture": {
      "status": "remote-observed",
      "summary": "A remote/non-loopback database connection was observed from a recognized local socket.",
      "confidence": "high"
    },
    "nodes": [],
    "edges": [],
    "services": [],
    "capabilities": [],
    "databases": []
  }
}
```

## Database recognition

For established connections, SAPstract recognizes these destination-port
families:

| Database | Recognized ports |
|---|---|
| SAP HANA | `3NN13`, `3NN15`, `3NN17`, and `3NN4x`–`3NN9x` |
| Oracle Database | `1521`, `1522`, `2484` |
| Microsoft SQL Server | `1433`, `1434` |
| IBM Db2 | `446` |
| SAP MaxDB | `7200`, `7210` |
| SAP ASE | `4901`, `5000` |
| SAP IQ | `2638` |

Process, service and path names also recognize standard engine identifiers
such as HANA `hdb*`, Oracle `ora_pmon`/`tnslsnr`, Db2 `db2sysc`, SQL Server
`sqlservr`, MaxDB `dbmsrv`, ASE `dataserver`, and IQ `iqsrv`.

The model deliberately does not classify ambiguous broad dynamic-port ranges
as a database. A database on a custom port will remain unknown unless other
engine evidence identifies it.

## Placement statuses

| Status | Meaning |
|---|---|
| `local-observed` | A database process, listener or recognized filesystem footprint was observed locally, with no remote database connection. |
| `remote-observed` | An established recognized socket reached a known database port at a non-loopback address not present among collected local socket addresses. SAP-owned process attribution gives high confidence; a recognized but unattributed socket gives medium confidence. |
| `mixed` | Both local database footprint and a non-loopback database connection were observed. |
| `configured` | A database host/type setting was collected, but no active placement evidence was observed. |
| `undetermined` | The collected sources did not establish database placement. |

“Remote” describes the observed address, not physical ownership. A secondary
address, container, network namespace, NAT path or incomplete socket inventory
can make another endpoint on the same machine appear remote. Confirm the
inferred engine and placement with SAP profiles, SAPControl and the database
owner before changing connectivity.

## Capability interpretation

Capabilities report `Observed`, `Listening`, `Configured`,
`Enabled (host artifact observed)`, `Possible; not confirmed`, or
`Not observed`, plus a confidence and an explicit validation step.

In particular, a WebGUI-named host artifact together with the local ABAP
footprint is shown as `Enabled (host artifact observed)` at medium confidence.
This is useful audit evidence, but it does not prove the database-backed ICF
service is active. Authoritative validation requires an authorized check of
`/sap/bc/gui/sap/its/webgui` in SICF, including its authentication and network
exposure.

`Not observed` never means disabled. Collection privilege, stopped instances,
custom paths, reverse proxies and application-layer configuration can all
hide a capability from a host-local pass.

## Report layout

The report separates topology, capabilities, database evidence, categorized
service evidence, raw runtime evidence, listeners, established connections,
SSFS, profiles and filesystem evidence. Findings are divided into five
independent risk-domain sections instead of one combined findings table:

- Network and exposed services
- Configuration and access controls
- Files and executable integrity
- SSFS, credentials and client data
- Operations, logging and command execution

Each technical inventory table has horizontal scrolling, and each finding
section has its own filter.
