#!/usr/bin/env bash

set -u

prefix="[SAPstract]"
log()      { printf '%s %s\n' "$prefix" "$*"; }
warn()     { printf '%s [!] %s\n' "$prefix" "$*" >&2; }
found()    { printf '%s [FOUND] %s\n' "$prefix" "$*"; }
pmatch()   { printf '%s [PORT] %s\n' "$prefix" "$*"; }

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  warn "Not running as root; run elevated if possible"
fi

skip_fstypes='^(proc|sysfs|devtmpfs|devpts|tmpfs|squashfs|overlay|cgroup|cgroup2|pstore|debugfs|tracefs|aufs|ramfs|bpf|nsfs|fusectl|mqueue|configfs|securityfs|hugetlbfs)$'

declare -a mounts=()
declare -A seen=()

mounts+=("/")
seen[/]=1

if [ -r /proc/mounts ]; then
  while read -r _ mp fstype _; do
    [ -n "$mp" ] && [ -d "$mp" ] || continue
    fstype_base="${fstype%%,*}"
    [[ "$fstype_base" =~ $skip_fstypes ]] && continue
    if [ -z "${seen["$mp"]+x}" ]; then mounts+=("$mp"); seen["$mp"]=1; fi
  done < /proc/mounts
else
  while read -r mp; do
    [ -d "$mp" ] || continue
    if [ -z "${seen["$mp"]+x}" ]; then mounts+=("$mp"); seen["$mp"]=1; fi
  done < <(df -P | awk 'NR>1 {print $6}')
fi

if [ "${#mounts[@]}" -eq 0 ]; then
  warn "No mount points found."
fi

log "[*] Probing mount roots for placeholder directory: /usr/sap"
for mp in "${mounts[@]}"; do
  cand="$(printf '%s\n' "$mp/usr/sap" | sed -e 's://*:/:g')"
  if [ -d "$cand" ]; then
    found "$cand"
  fi
done
log "[*] Directory probe complete."

label_for_port() {
  case "$1" in
    # NetWeaver ABAP + ICM
    80[0-9][0-9])   echo "NW ABAP/ICM HTTP 80NN" ;;
    443[0-9][0-9])  echo "NW ABAP/ICM HTTPS 443NN" ;;
    81[0-9][0-9])   echo "NW ABAP/ICM HTTP 81NN" ;;
    444[0-9][0-9])  echo "NW ABAP/ICM HTTPS 444NN" ;;
    32[0-9][0-9])   echo "NW Dispatcher 32NN" ;;
    33[0-9][0-9])   echo "NW Gateway 33NN" ;;
    48[0-9][0-9])   echo "NW Secure GW 48NN" ;;
    36[0-9][0-9])   echo "NW Msg Server 36NN" ;;

    # NetWeaver JAVA
    5[0-9][0-9]00)  echo "NW JAVA HTTP 5NN00" ;;
    5[0-9][0-9]01)  echo "NW JAVA HTTPS 5NN01" ;;
    5[0-9][0-9]05)  echo "NW JAVA P4/HTTP 5NN05" ;;
    5[0-9][0-9]06)  echo "NW JAVA P4/HTTPS 5NN06" ;;
    5[0-9][0-9]02)  echo "NW JAVA IIOP Init 5NN02" ;;
    5[0-9][0-9]03)  echo "NW JAVA IIOP SSL 5NN03" ;;
    5[0-9][0-9]04)  echo "NW JAVA P4 Remoting 5NN04" ;;
    5[0-9][0-9]07)  echo "NW JAVA IIOP 5NN07" ;;
    5[0-9][0-9]08)  echo "NW JAVA Telnet 5NN08" ;;
    5[0-9][0-9]10)  echo "NW JAVA JMS 5NN10" ;;

    # Admin Services
    1128)           echo "SAPHostControl 1128" ;;
    1129)           echo "SAPHostControlS 1129" ;;
    5[0-9][0-9]13)  echo "SAP Start Service 5NN13" ;;
    5[0-9][0-9]14)  echo "SAP Start Service 5NN14" ;;

    # SAP IGS
    4[0-9][0-9]80)  echo "IGS HTTP 4NN80" ;;
    4[0-9][0-9]00)  echo "IGS Multiplexer 4NN00" ;;
    4[0-9][0-9]01)  echo "IGS Portwatcher 4NN01" ;;
    4[0-9][0-9]02)  echo "IGS Portwatcher 4NN02" ;;

    # Install Tools
    5[0-9][0-9]19)  echo "SDM HTTP 5NN19" ;;
    5[0-9][0-9]17)  echo "SDM Admin 5NN17" ;;
    5[0-9][0-9]18)  echo "SDM GUI 5NN18" ;;
    21212)          echo "SAPinst HTTP UI 21212" ;;
    21213)          echo "SAPinst HTTP UI 21213" ;;
    59975)          echo "SAPinst AS400 59975" ;;
    59976)          echo "SAPinst AS400 59976" ;;
    4238)           echo "Upgrade Monitor 4238" ;;
    4239)           echo "Upgrade UA HTTP 4239" ;;
    4240)           echo "Upgrade R3up 4240" ;;
    4241)           echo "Upgrade UA 4241" ;;

    # Utilities
    3299)           echo "SAProuter 3299" ;;
    3298)           echo "SAP niping 3298" ;;
    515)            echo "SAPlpd 515" ;;

    # ITS
    3950|3951|3954|3964) echo "ITS HTTP $1" ;;

    # Databases
    1433)           echo "MSSQL 1433" ;;
    1527)           echo "Oracle 1527" ;;
    50000)          echo "DB6 50000" ;;
    4402)           echo "DB2 4402" ;;
    7200|7210|7269|7270|7275) echo "MaxDB $1" ;;

    # Common Internet
    80)             echo "HTTP 80" ;;
    443)            echo "HTTPS 443" ;;
    21)             echo "FTP 21" ;;
    22)             echo "SSH 22" ;;
    23)             echo "Telnet 23" ;;
    25)             echo "SMTP 25" ;;
    110)            echo "POP 110" ;;
    3389)           echo "RDP 3389" ;;
    *)              return 1 ;;
  esac
  return 0
}

fmt_line() { printf '%-24s %-4s %-39s %-39s %s\n' "$1" "$2" "$3" "$4" "$5"; }

emit_match() {
  local proto="$1" local_ep="$2" remote_ep="$3" pid="${4:-}" comm="${5:-}"

  local lclean rclean lport rport
  lclean="${local_ep#[}"; lclean="${lclean%]}"
  rclean="${remote_ep#[}"; rclean="${rclean%]}"
  lport="${lclean##*:}"
  rport="${rclean##*:}"

  local label=""
  if label_for_port "$lport" >/dev/null; then label="$(label_for_port "$lport")"
  elif label_for_port "$rport" >/dev/null; then label="$(label_for_port "$rport")"
  fi
  [ -n "$label" ] || return 0

  local extra=""
  if [ -n "${comm:-}" ]; then
    if [ -n "${pid:-}" ]; then extra="proc=${comm}(${pid})"; else extra="proc=${comm}"; fi
  fi

  pmatch "$(fmt_line "$label" "$proto" "$local_ep" "$remote_ep" "$extra")"
}

pmatch "$(fmt_line 'LABEL' 'PROT' 'LOCAL' 'REMOTE' 'EXTRA')"

if command -v ss >/dev/null 2>&1; then
  if ss -H -tunap 1>/dev/null 2>&1; then
    ss -H -tunap 2>/dev/null | awk '
      {
        proto=toupper($1); local=$5; remote=$6; users=$0; pid=""; comm="";
        # Heuristics for fields shifting
        if (local !~ /:[0-9]+$/)  local=$(NF-2);
        if (remote !~ /(:[0-9]+$|\*:.*)/) remote=$(NF-1);
        if (match(users, /users:\(\("([^"]+)",pid=([0-9]+)/, m)) { comm=m[1]; pid=m[2]; }
        printf("%s\t%s\t%s\t%s\t%s\n", proto, local, remote, pid, comm);
      }' | while IFS=$'\t' read -r PROTO LOCAL REMOTE PID COMM; do
            emit_match "$PROTO" "$LOCAL" "$REMOTE" "$PID" "$COMM"
         done
  else
    ss -H -tuna 2>/dev/null | awk '
      { proto=toupper($1); local=$5; remote=$6;
        if (local !~ /:[0-9]+$/)  local=$(NF-2);
        if (remote !~ /(:[0-9]+$|\*:.*)/) remote=$(NF-1);
        printf("%s\t%s\t%s\n", proto, local, remote);
      }' | while IFS=$'\t' read -r PROTO LOCAL REMOTE; do
            emit_match "$PROTO" "$LOCAL" "$REMOTE" "" ""
         done
  fi

elif command -v netstat >/dev/null 2>&1; then
  if netstat -anp 1>/dev/null 2>&1; then
    netstat -anp 2>/dev/null | awk '
      tolower($1) ~ /^(tcp|udp)/ && NF>=4 {
        proto=toupper($1); local=$4; remote=$5; pidcomm=$0; pid=""; comm="";
        if (match(pidcomm, / ([0-9]+)\/([[:alnum:]_\-\.]+)/, m)) { pid=m[1]; comm=m[2]; }
        printf("%s\t%s\t%s\t%s\t%s\n", proto, local, remote, pid, comm);
      }' | while IFS=$'\t' read -r PROTO LOCAL REMOTE PID COMM; do
            emit_match "$PROTO" "$LOCAL" "$REMOTE" "$PID" "$COMM"
         done
  else
    netstat -an 2>/dev/null | awk '
      tolower($1) ~ /^(tcp|udp)/ && NF>=4 {
        proto=toupper($1); local=$4; remote=$5;
        printf("%s\t%s\t%s\n", proto, local, remote);
      }' | while IFS=$'\t' read -r PROTO LOCAL REMOTE; do
            emit_match "$PROTO" "$LOCAL" "$REMOTE" "" ""
         done
  fi

elif command -v lsof >/dev/null 2>&1; then
  lsof -nP -iTCP -iUDP 2>/dev/null | awk '
    NR>1 {
      cmd=$1; pid=$2; name=$NF;
      split(name, a, "->"); local=a[1]; remote=(a[2] ? a[2] : "*:*");
      proto="TCP"; if (index($0," UDP ")>0) proto="UDP";
      printf("%s\t%s\t%s\t%s\t%s\n", proto, local, remote, pid, cmd);
    }' | while IFS=$'\t' read -r PROTO LOCAL REMOTE PID COMM; do
          emit_match "$PROTO" "$LOCAL" "$REMOTE" "$PID" "$COMM"
       done

else
  warn "No suitable socket tool found (need one of: ss | netstat | lsof)."
  exit 1
fi

log "[*] Done."

