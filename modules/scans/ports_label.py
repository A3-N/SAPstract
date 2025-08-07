def get_nn_ports(port_pattern, exclude=None):
    """
    Example: '32NN' -> 3200 to 3299
             '5NN01' -> 50001, 51001, ..., 59001
    """
    exclude = exclude or []
    if 'NN' not in port_pattern:
        return []

    parts = port_pattern.split('NN')
    prefix, suffix = parts[0], parts[1]
    return [
        int(f"{prefix}{i:02}{suffix}")
        for i in range(0, 100)
        if int(f"{prefix}{i:02}{suffix}") not in exclude
    ]

def build_port_labels():
    port_labels = {}

    # Reverse proxy
    port_labels[80] = "HTTP"
    port_labels[443] = "HTTPS"

    # Netweaver ABAP + ICM
    for i in get_nn_ports("32NN", [3299]): port_labels[i] = "SAP Dispatcher"
    for i in get_nn_ports("33NN", [3389]): port_labels[i] = "SAP Gateway"
    for i in get_nn_ports("48NN"): port_labels[i] = "SAP Secure Gateway"
    for i in get_nn_ports("80NN"): port_labels[i] = "SAP ICM HTTP"
    for i in get_nn_ports("443NN"): port_labels[i] = "SAP ICM HTTPS"
    for i in get_nn_ports("36NN"): port_labels[i] = "SAP Message Server"
    for i in get_nn_ports("81NN"): port_labels[i] = "SAP MsgServer HTTP"
    for i in get_nn_ports("444NN"): port_labels[i] = "SAP MsgServer HTTPS"

    # Netweaver JAVA
    for i in get_nn_ports("5NN00"): port_labels[i] = "SAP J2EE HTTP"
    for i in get_nn_ports("5NN01"): port_labels[i] = "SAP J2EE HTTPS"
    for i in get_nn_ports("5NN02"): port_labels[i] = "SAP J2EE IIOP Init"
    for i in get_nn_ports("5NN03"): port_labels[i] = "SAP J2EE IIOP SSL"
    for i in get_nn_ports("5NN04"): port_labels[i] = "SAP J2EE P4"
    for i in get_nn_ports("5NN05"): port_labels[i] = "SAP J2EE P4 HTTP"
    for i in get_nn_ports("5NN06"): port_labels[i] = "SAP J2EE P4 HTTPS"
    for i in get_nn_ports("5NN07"): port_labels[i] = "SAP J2EE IIOP"
    for i in get_nn_ports("5NN08"): port_labels[i] = "SAP J2EE Telnet"
    for i in get_nn_ports("5NN10"): port_labels[i] = "SAP J2EE JMS"

    # Admin services
    port_labels[1128] = "SAPHostControl"
    port_labels[1129] = "SAPHostControlS"
    for i in get_nn_ports("5NN13"): port_labels[i] = "SAP Start Service"
    for i in get_nn_ports("5NN14"): port_labels[i] = "SAP Start Service"

    # SAP IGS
    for i in get_nn_ports("4NN00"): port_labels[i] = "SAP IGS Multiplexer"
    for i in get_nn_ports("4NN01"): port_labels[i] = "SAP IGS Portwatcher"
    for i in get_nn_ports("4NN02"): port_labels[i] = "SAP IGS Portwatcher"
    for i in get_nn_ports("4NN80"): port_labels[i] = "SAP IGS HTTP Admin"

    # Install tools
    for i in get_nn_ports("5NN17"): port_labels[i] = "SAP SDM Admin"
    for i in get_nn_ports("5NN18"): port_labels[i] = "SAP SDM GUI"
    for i in get_nn_ports("5NN19"): port_labels[i] = "SAP SDM HTTP"
    port_labels[21212] = "SAPinst"
    port_labels[21213] = "SAPinst"
    port_labels[59975] = "SAPinst AS400"
    port_labels[59976] = "SAPinst AS400"
    port_labels[4238] = "SAP Upgrade Monitor"
    port_labels[4239] = "SAP Upgrade UA-HTTP"
    port_labels[4240] = "SAP Upgrade R3up"
    port_labels[4241] = "SAP Upgrade UA"

    # Utilities
    port_labels[3299] = "SAProuter"
    port_labels[3298] = "SAP niping"
    port_labels[515] = "SAPlpd"

    # ITS
    for p in [3950, 3951, 3954, 3964]: port_labels[p] = "SAP ITS"

    # DBs
    port_labels[1433] = "MSSQL"
    port_labels[1527] = "Oracle"
    port_labels[50000] = "DB6 (AIX)"
    port_labels[4402] = "DB2 (OS/400)"
    for p in [7200, 7210, 7269, 7270, 7275]: port_labels[p] = "MaxDB"

    # Normal ports
    port_labels.update({
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        80: "HTTP", 443: "HTTPS", 110: "POP", 3389: "RDP"
    })

    return port_labels

#CREDITS TO BIZSPLOIT
