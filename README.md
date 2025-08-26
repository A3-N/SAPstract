# sapstract


FileSystem Audit. 

---

SAP Enum and Exploit

```
.
├── SAPstract.py
├── LICENSE
├── README.md
├── db/
│   └── sapstract_sessions.db
│
├── modules/
│   ├── ui.py
│   ├── scan.py
│   ├── sap.py
│   ├── target.py
│   ├── help.py
│   ├── session.py
│   ├── exploit.py
│   │
│   ├── scans/
│   │   ├── ports.py
│   │   └── web.py
│   │
│   ├── docs/
│   │   ├── manual.py
│   │   ├── wiki.py
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
│   │
│   ├── exploit/
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
│   │
│   └── src/
│       ├── ports_label.py
│       │
│       ├── wordlists/
│       │   └── sap_paths.txt
│       │
│       ├── web/
│       │   ├── skeleton.py
│       │   ├── 80.py
│       │   ├── 80NN.py
│       │   ├── 81NN.py
│       │   ├── 21212.py
│       │   ├── 21213.py
│       │   ├── 4NN80.py
│       │   ├── 4239.py
│       │   ├── 443.py
│       │   ├── 443NN.py
│       │   ├── 444NN.py
│       │   ├── 5NN00.py
│       │   ├── 5NN01.py
│       │   ├── 5NN05.py
│       │   ├── 5NN06.py
│       │   ├── 5NN19.py
│       │   └── ITS.py
│       │
│       └── vuln/
│           ├── skeleton.py
│           └── checkCTC.py
```

### Next on da list

Add the fuzz.py next and do the below checks while running

#### BIZSPLOIT VULNS ADD:
- checkCTC
- icmAdmin
- icmErrorInfodisc
- icmInfo
- icmPing
- icmSOAPRFC
- icmWebgui

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

---

## GUI4Windows

- SAP 3D Visual Enterprise Viewer
- SAP Business Client
- SAP Business Explorer
- SAP GUI for Windows
- SAPSetup Automatic Workstation Update Service
- ? SNC Client Enccryption 2.0

```
ABAP / ICM & MsgServer HTTP/S
80NN
443NN
81NN
444NN

Java HTTP/S variants
5NN00
5NN01
5NN05
5NN06
5NN19

IGS HTTP Admin
4NN80

ITS (Internet Transaction Server)
ITS

Common fixed HTTP/S
80
443

SAPinst / Upgrade HTTP UIs
21212
21213
4239
```
