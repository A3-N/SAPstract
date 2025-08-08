# sapstract
SAP Enum and Exploit

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

### BUGS
```
ERR - /sap/public/bc/abap/docu (HTTPSConnectionPool(host='dom.local', port=44301))
ERR - /sap/xi/cache (('Connection aborted.', ConnectionResetError(10054, 'An existing connection was forcibly closed by the remote host', None, 10054, None)))
```

Better approach

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
