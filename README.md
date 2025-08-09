# sapstract
SAP Enum and Exploit

```
.
├── SAPstract.py                # Main entrypoint; automatically loads commands from `modules/`
├── LICENSE
├── README.md
├── db                          # Database folder (sessions + logs of all gathered info)
│   └── sapstract_sessions.db   # SQLite DB storing sessions and discovered data
├── modules                     # All command modules for SAPstract.py (auto-loaded, excluding ui.py)
│   ├── ui.py                   # UI helper functions (not a command)
│   ├── scan.py                 # Main `scan` command; loads subcommands from `modules/scans/`
│   ├── sap.py                  # Main `sap` command; loads docs/commands from `modules/docs/`
│   ├── target.py               # Command for managing targets in the active session
│   ├── help.py                 # Help menu command
│   ├── session.py              # Session management command
│   ├── exploit.py              # Main `exploit` command; loads subcommands from `modules/exploit/`
│   ├── scans                   # Subcommands for `scan.py`
│   │   ├── ports.py            # Performs port scanning for SAP-related ports
│   │   └── web.py              # Web enumeration logic (calls checks in `modules/src/`)
│   ├── docs                    # Commands & data used by `sap.py`
│   │   ├── wiki.py              # `sap wiki` command (searches JSON docs)
│   │   ├── manual.py            # `sap manual` command (loads m_* JSON manuals)
│   │   ├── 0080_http_generic.json
│   │   ├── 21212_sapinst.json
│   │   ├── 21213_sapinst_https.json
│   │   ├── 395x_its_http.json
│   │   ├── 4NN80_igs_admin.json
│   │   ├── 4239_upgrade_assistant.json
│   │   ├── 443_https_interface.json
│   │   ├── 443NN_icm_https.json
│   │   ├── 444NN_msgserver_https.json
│   │   ├── 5NN00_java_http.json
│   │   ├── 5NN01_java_https.json
│   │   ├── 5NN05_java_p4_http.json
│   │   ├── 5NN06_java_p4_https.json
│   │   ├── 5NN19_sdm_http.json
│   │   ├── 80NN_icm_http.json
│   │   ├── 81NN_msgserver_http.json
│   │   ├── m_ClientSIDOverview.json
│   │   ├── m_DefaultUsers.json
│   │   ├── m_SAP_Tech_Stack.json
│   │   ├── m_TCodes.json
│   │   └── m_TCodes_Attack_Path.json
│   ├── exploit                 # Subcommands for `exploit.py` (one per SAP service/port)
│   │   ├── 80.py
│   │   ├── 80NN.py
│   │   ├── 81NN.py
│   │   ├── 21212.py
│   │   ├── 21213.py
│   │   ├── 4NN80.py
│   │   ├── 4239.py
│   │   ├── 443.py
│   │   ├── 443NN.py
│   │   ├── 444NN.py
│   │   ├── 5NN00.py
│   │   ├── 5NN01.py
│   │   ├── 5NN05.py
│   │   ├── 5NN06.py
│   │   ├── 5NN19.py
│   │   └── ITS.py
│   └── src                     # Sub-checks for `web.py` scan command
│       ├── 80.py
│       ├── 80NN.py
│       ├── 81NN.py
│       ├── 21212.py
│       ├── 21213.py
│       ├── 4NN80.py
│       ├── 4239.py
│       ├── 443.py
│       ├── 443NN.py
│       ├── 444NN.py
│       ├── 5NN00.py
│       ├── 5NN01.py
│       ├── 5NN05.py
│       ├── 5NN06.py
│       ├── 5NN19.py
│       ├── ITS.py
│       ├── ports_label.py       # Mapping of SAP ports to their service labels
│       └── wordlists
│           └── sap_paths.txt    # Misc wordlist for path enumeration
```

### Next on da list

Add the fuzz.py next and do the below checks while running

BIZSPLOIT VULNS ADD:
checkCTC
icmAdmin
icmErrorInfodisc
icmInfo
icmPing
icmSOAPRFC
icmWebgui

---

### TODO 

pysap python3

TODO BIZSPLOIT:
bruteLogin.py
checkAnonKM
checkGwMon
checkRFCEXEC
checkRFCPrivs
connectExtRFC
getDocu
mcInterface
oraAuth
registerEXTServer
sapinfo
saprouterNative

---

```
# Netweaver ABAP + ICM
# 80NN      -> HTTP
# 443NN     -> HTTPS
# 81NN      -> HTTP
# 444NN     -> HTTPS
# 32NN      -> X       (SAP Dispatcher)
# 33NN      -> X       (SAP Gateway)
# 48NN      -> X       (SAP Secure Gateway)
# 36NN      -> X       (SAP Message Server)

# Netweaver JAVA
# 5NN00     -> HTTP
# 5NN01     -> HTTPS
# 5NN05     -> HTTP    (P4 over HTTP)
# 5NN06     -> HTTPS   (P4 over HTTPS)
# 5NN02     -> X       (IIOP Init)
# 5NN03     -> X       (IIOP SSL)
# 5NN04     -> X       (P4 Remoting)
# 5NN07     -> X       (IIOP)
# 5NN08     -> X       (Telnet interface)
# 5NN10     -> X       (JMS / Messaging)

# Admin Services
# 1128      -> X       (SAPHostControl)
# 1129      -> X       (SAPHostControlS)
# 5NN13     -> X       (SAP Start Service)
# 5NN14     -> X       (SAP Start Service)

# SAP IGS
# 4NN80     -> HTTP
# 4NN00     -> X       (IGS Multiplexer)
# 4NN01     -> X       (IGS Portwatcher)
# 4NN02     -> X       (IGS Portwatcher)

# Install Tools
# 5NN19     -> HTTP    (SAP SDM HTTP)
# 5NN17     -> X       (SAP SDM Admin)
# 5NN18     -> X       (SAP SDM GUI)
# 21212     -> HTTP    (SAPinst - sometimes HTTP UI)
# 21213     -> HTTP    (SAPinst - sometimes HTTP UI)
# 59975     -> X       (SAPinst AS400)
# 59976     -> X       (SAPinst AS400)
# 4238      -> X       (Upgrade Monitor)
# 4239      -> HTTP    (Upgrade UA HTTP)
# 4240      -> X       (Upgrade R3up)
# 4241      -> X       (Upgrade UA)

# Utilities
# 3299      -> X       (SAProuter)
# 3298      -> X       (SAP niping)
# 515       -> X       (SAPlpd)

# ITS
# 3950      -> HTTP
# 3951      -> HTTP
# 3954      -> HTTP
# 3964      -> HTTP

# Databases
# 1433      -> X       (MSSQL)
# 1527      -> X       (Oracle)
# 50000     -> X       (DB6)
# 4402      -> X       (DB2)
# 7200      -> X       (MaxDB)
# 7210      -> X
# 7269      -> X
# 7270      -> X
# 7275      -> X

# Common Internet Services
# 80        -> HTTP
# 443       -> HTTPS
# 21        -> X       (FTP)
# 22        -> X       (SSH)
# 23        -> X       (Telnet)
# 25        -> X       (SMTP)
# 110       -> X       (POP)
# 3389      -> X       (RDP)
```
