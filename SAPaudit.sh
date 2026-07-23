#!/usr/bin/env bash
#
# SAPstract - read-only, host-local SAP footprint and posture audit
# Schema: sapstract-audit/v2
#
# This collector does not connect to remote services, decrypt secure stores,
# invoke SAP administration functions, or change the audited host.

set -uo pipefail
shopt -s extglob nullglob

VERSION="2.2.0"
SCHEMA="sapstract-audit/v2"
OUTPUT_DIR=""
REPORT_PATH=""
JSON_PATH=""
ROOT_PATH="/"
HOST_LABEL=""
REPORT_NOTE=""
MAX_FILES=6000
QUIET=0
NO_COLOR=0

usage() {
  cat <<'EOF'
SAPstract host-local SAP posture audit

Usage:
  ./SAPaudit.sh [options]

Options:
  --output-dir DIR       Directory for generated reports (default: current dir)
  --report FILE          HTML report path
  --json FILE            JSON evidence report path
  --root DIR             Alternate filesystem root for offline audits
  --host-label NAME      Override the report hostname (useful for offline images)
  --report-note TEXT     Add a scope/context note to HTML and JSON
  --max-files N          Maximum discovered files per broad scan (default: 6000)
  --quiet                Only print warnings and final paths
  --no-color             Disable terminal colors
  -h, --help             Show this help

The audit is passive and local. It never probes a remote endpoint and never
prints SSFS values, key bytes, passwords, tokens, or private-key contents.
EOF
}

while (($#)); do
  case "$1" in
    --output-dir) [[ $# -ge 2 ]] || { printf '%s\n' "Missing value for $1" >&2; exit 2; }; OUTPUT_DIR=$2; shift 2 ;;
    --report) [[ $# -ge 2 ]] || { printf '%s\n' "Missing value for $1" >&2; exit 2; }; REPORT_PATH=$2; shift 2 ;;
    --json) [[ $# -ge 2 ]] || { printf '%s\n' "Missing value for $1" >&2; exit 2; }; JSON_PATH=$2; shift 2 ;;
    --root) [[ $# -ge 2 ]] || { printf '%s\n' "Missing value for $1" >&2; exit 2; }; ROOT_PATH=$2; shift 2 ;;
    --host-label) [[ $# -ge 2 ]] || { printf '%s\n' "Missing value for $1" >&2; exit 2; }; HOST_LABEL=$2; shift 2 ;;
    --report-note) [[ $# -ge 2 ]] || { printf '%s\n' "Missing value for $1" >&2; exit 2; }; REPORT_NOTE=$2; shift 2 ;;
    --max-files) [[ $# -ge 2 ]] || { printf '%s\n' "Missing value for $1" >&2; exit 2; }; MAX_FILES=$2; shift 2 ;;
    --quiet) QUIET=1; shift ;;
    --no-color) NO_COLOR=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "$MAX_FILES" =~ ^[1-9][0-9]*$ ]] || { printf '%s\n' "--max-files must be a positive integer" >&2; exit 2; }
[[ -d "$ROOT_PATH" ]] || { printf 'Audit root does not exist: %s\n' "$ROOT_PATH" >&2; exit 2; }
ROOT_PATH=${ROOT_PATH%/}
[[ -n "$ROOT_PATH" ]] || ROOT_PATH="/"

if [[ -t 1 && "$NO_COLOR" -eq 0 ]]; then
  C_BLUE=$'\033[36m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RESET=$'\033[0m'
else
  C_BLUE=""; C_GREEN=""; C_YELLOW=""; C_RESET=""
fi
log() { ((QUIET)) || printf '%s[SAPstract]%s %s\n' "$C_BLUE" "$C_RESET" "$*"; }
ok() { ((QUIET)) || printf '%s[SAPstract] [OK]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s[SAPstract] [!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }

show_banner() {
  ((QUIET)) && return
  local blue="" white="" reset=""
  if [[ -t 1 && "$NO_COLOR" -eq 0 ]]; then
    blue=$'\033[94m'; white=$'\033[97m'; reset=$'\033[0m'
  fi
  printf '%s\n' "$blue"
  printf '%s%s%s%s\n' "$blue" '     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@' "$white" '.dBBBBP dBBBBBBP dBBBBBb dBBBBBb     dBBBP dBBBBBBP'
  printf '%s%s%s%s\n' "$blue" '     @@@@#+-     .=+*%@@@@@*:::::=@@@@@*:::::::-==+*%@@@@@@@@@@@@@@@@ ' "$white" '.BP                   dBP      BB'
  printf '%s%s%s%s\n' "$blue" '     @@+              *@@@%       =@@@@+              +@@@@@@@@@@@@   ' "$white" '`BBBBb   dBP     dBBBBK   dBP BB   dBP      dBP'
  printf '%s%s%s%s\n' "$blue" '     @=      .::     %@@@@         +@@@+               :@@@@@@@@@@       ' "$white" 'dBP  dBP     dBP  BB  dBP  BB  dBP      dBP'
  printf '%s%s%s%s\n' "$blue" '     @      @@@@@@@@@@@@@-          %@@+     +@@@%-     +@@@@@@     ' "$white" "dBBBBP'  dBP     dBP  dB' dBBBBBBB dBBBBP   dBP"
  printf '%s%s%s%s\n' "$blue" '     @.       :*%@@@@@@@+     =     =@@+     +@@@@=     +@@@@      ' "$white" '-----------------------------------------------------'
  printf '%s%s%s%s\n' "$blue" '     @%:           =*@@#     -%=     +@+     :+++:      %@@@        ' "$white" 'Tool: SAPstract  — SAP enumeration & fuzzing toolkit'
  printf '%s%s%s%s\n' "$blue" '     @@@#+           :*:     *@@      #+               #@@          ' "$white" 'By:   @A3-N      — github.com/A3-N/SAPstract'
  printf '%s%s%s%s\n' "$blue" '     @@@@@@@%#+.             +#*:     -+            =#@@            ' "$white" 'Cred: Bizsploit  — Mariano Nuñez Di Croce'
  printf '%s%s%s%s\n' "$blue" '     @@%*@@@@@@@-                      .     +@@@@@@@@                    ' "$white" 'Metasploit — rapid7'
  printf '%s%s%s%s\n' "$blue" '     @%.                                     +@@@@@@                      ' "$white" 'pysap      — OWASP'
  printf '%s\n' "${blue}     @-                   -@@%%%@@+          +@@@@"
  printf '%s\n' "${blue}     @@@#+=-. .-=@@@@@@@@@@@@@@@@@+=@@@#@@@@@@@@"
  printf '%s%s%s%s\n' "$blue" '     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                          ' "$white" 'Read-only host-local SAP posture assessment'
  printf '%s\n\n' "$reset"
}

trim() {
  local value=$1
  value="${value##+([[:space:]])}"
  value="${value%%+([[:space:]])}"
  printf '%s' "$value"
}

clean_field() {
  local value=${1-}
  value=${value//$'\t'/ }
  value=${value//$'\r'/ }
  value=${value//$'\n'/ }
  value=${value//|/¦}
  printf '%s' "$value"
}

physical_path() {
  local logical=$1
  if [[ "$ROOT_PATH" == "/" ]]; then
    printf '%s' "$logical"
  else
    printf '%s%s' "$ROOT_PATH" "$logical"
  fi
}

logical_path() {
  local physical=$1
  if [[ "$ROOT_PATH" != "/" && "$physical" == "$ROOT_PATH"* ]]; then
    physical=${physical#"$ROOT_PATH"}
    [[ -n "$physical" ]] || physical="/"
  fi
  printf '%s' "$physical"
}

HOST_NAME=$(hostname -f 2>/dev/null || hostname 2>/dev/null || printf unknown)
[[ -z "$HOST_LABEL" ]] || HOST_NAME=$HOST_LABEL
COLLECTED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
STAMP=$(date -u '+%Y%m%d-%H%M%S')
SAFE_HOST=${HOST_NAME//[^A-Za-z0-9_.-]/_}
[[ -n "$OUTPUT_DIR" ]] || OUTPUT_DIR="$PWD"
mkdir -p -- "$OUTPUT_DIR" || { printf 'Cannot create output directory: %s\n' "$OUTPUT_DIR" >&2; exit 1; }
[[ -n "$REPORT_PATH" ]] || REPORT_PATH="$OUTPUT_DIR/sapstract-$SAFE_HOST-$STAMP.html"
[[ -n "$JSON_PATH" ]] || JSON_PATH="$OUTPUT_DIR/sapstract-$SAFE_HOST-$STAMP.json"
mkdir -p -- "$(dirname -- "$REPORT_PATH")" "$(dirname -- "$JSON_PATH")" ||
  { printf '%s\n' "Cannot create report parent directory" >&2; exit 1; }

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sapstract.XXXXXXXX") ||
  { printf '%s\n' "Unable to create temporary workspace" >&2; exit 1; }
cleanup() { rm -rf -- "$WORK_DIR"; }
trap cleanup EXIT HUP INT TERM

FINDINGS="$WORK_DIR/findings.tsv"
SYSTEMS="$WORK_DIR/systems.tsv"
SERVICES="$WORK_DIR/services.tsv"
PROCESSES="$WORK_DIR/processes.tsv"
SOCKETS="$WORK_DIR/sockets.tsv"
PATHS="$WORK_DIR/paths.tsv"
SSFS="$WORK_DIR/ssfs.tsv"
TOOLS="$WORK_DIR/tools.tsv"
PROFILES="$WORK_DIR/profiles.tsv"
COVERAGE="$WORK_DIR/coverage.tsv"
ASSESSMENT="$WORK_DIR/assessment.tsv"
SECTION_SCORES="$WORK_DIR/section_scores.tsv"
SERVICE_MAP="$WORK_DIR/service_map.tsv"
CAPABILITIES="$WORK_DIR/capabilities.tsv"
DATABASES="$WORK_DIR/databases.tsv"
TOPOLOGY_NODES="$WORK_DIR/topology_nodes.tsv"
TOPOLOGY_EDGES="$WORK_DIR/topology_edges.tsv"
for table in "$FINDINGS" "$SYSTEMS" "$SERVICES" "$PROCESSES" "$SOCKETS" "$PATHS" "$SSFS" "$TOOLS" "$PROFILES" "$COVERAGE" "$ASSESSMENT" "$SECTION_SCORES" "$SERVICE_MAP" "$CAPABILITIES" "$DATABASES" "$TOPOLOGY_NODES" "$TOPOLOGY_EDGES"; do
  : > "$table"
done

declare -A SEEN_FINDING=()
declare -A SEEN_PATH=()
declare -A SEEN_SSFS=()
declare -A SEEN_TOOL=()
declare -A SEEN_SYSTEM=()
declare -A SSFS_DATA_PATHS=()
declare -A SSFS_KEY_PATHS=()
declare -A SSFS_FAMILY_BY_STEM=()
declare -A SAP_PIDS=()
declare -A SAP_PROCESS_BY_PID=()
declare -A SEEN_SERVICE_MAP=()
declare -A SEEN_DATABASE=()
declare -A SEEN_TOPOLOGY_NODE=()
declare -A SEEN_TOPOLOGY_EDGE=()
declare -A SEEN_CAPABILITY=()
declare -a CONFIGURED_SSFS_PATHS=()
RISK_SCORE=0
SAP_EVIDENCE_COUNT=0
TRUNCATED_SCANS=0
DATABASE_POSTURE_STATUS="undetermined"
DATABASE_POSTURE_SUMMARY="No database placement evidence was observed."
DATABASE_POSTURE_CONFIDENCE="low"

append_row() {
  local file=$1
  shift
  local first=1 field
  for field in "$@"; do
    ((first)) || printf '\t' >> "$file"
    clean_field "$field" >> "$file"
    first=0
  done
  printf '\n' >> "$file"
}

severity_weight() {
  case "$1" in
    Critical) printf 30 ;;
    High) printf 18 ;;
    Medium) printf 8 ;;
    Low) printf 3 ;;
    *) printf 0 ;;
  esac
}

add_finding() {
  local id=$1 severity=$2 title=$3 asset=$4 evidence=$5 recommendation=$6 reference=${7-}
  local key="$id|$asset"
  [[ -z "${SEEN_FINDING[$key]+x}" ]] || return 0
  SEEN_FINDING[$key]=1
  local weight
  weight=$(severity_weight "$severity")
  RISK_SCORE=$((RISK_SCORE + weight))
  ((RISK_SCORE > 100)) && RISK_SCORE=100
  append_row "$FINDINGS" "$id" "$severity" "$weight" "$title" "$asset" "$evidence" "$recommendation" "$reference"
}

add_coverage() {
  append_row "$COVERAGE" "$1" "$2" "$3"
}

add_assessment() {
  append_row "$ASSESSMENT" "$1" "$2" "$3" "$4" "$5"
}

stat_fields() {
  local path=$1
  STAT_MODE=""; STAT_OWNER=""; STAT_GROUP=""; STAT_SIZE=""; STAT_TYPE=""; STAT_MTIME=""
  if stat -c '%a|%U|%G|%s|%F|%y' -- "$path" >/dev/null 2>&1; then
    IFS='|' read -r STAT_MODE STAT_OWNER STAT_GROUP STAT_SIZE STAT_TYPE STAT_MTIME < <(stat -c '%a|%U|%G|%s|%F|%y' -- "$path" 2>/dev/null)
  elif stat -f '%Lp|%Su|%Sg|%z|%HT|%Sm' -- "$path" >/dev/null 2>&1; then
    IFS='|' read -r STAT_MODE STAT_OWNER STAT_GROUP STAT_SIZE STAT_TYPE STAT_MTIME < <(stat -f '%Lp|%Su|%Sg|%z|%HT|%Sm' -- "$path" 2>/dev/null)
  else
    return 1
  fi
  STAT_MTIME=${STAT_MTIME%%.*}
  return 0
}

permission_bits() {
  local mode=${1##+(0)}
  [[ -n "$mode" ]] || mode=0
  while ((${#mode} < 3)); do mode="0$mode"; done
  local triad=${mode: -3}
  PERM_GROUP=${triad:1:1}
  PERM_OTHER=${triad:2:1}
}

has_bit() {
  local digit=$1 bit=$2
  [[ "$digit" =~ ^[0-7]$ ]] && (((8#$digit & bit) != 0))
}

audit_permission_risk() {
  local logical=$1 category=$2 mode=$3 type=$4
  permission_bits "$mode"
  local is_dir=0
  [[ "$type" == *directory* || "$type" == "Directory" ]] && is_dir=1

  if has_bit "$PERM_OTHER" 2; then
    if [[ "$category" == "SSFS key" || "$category" == "SSFS local protection" ]]; then
      add_finding "SSFS-001" "Critical" "SSFS key material is writable by everyone" "$logical" \
        "Mode $mode permits other users to alter master-key or local-protection material." \
        "Restrict the file and its parent path to the SAP service owner and only the explicitly required administration group; validate with SAP tooling after correcting ownership." \
        "SAP SSFS least-privilege guidance"
    elif [[ "$category" == "Executable" ]]; then
      add_finding "FILE-001" "Critical" "SAP executable is writable by everyone" "$logical" \
        "Mode $mode permits arbitrary local users to replace or modify executable code." \
        "Remove other-write permission, restore the vendor binary from trusted media if integrity is uncertain, and verify ownership and patch level." \
        "OWASP CBAS: OS command execution and code integrity"
    else
      add_finding "FILE-002" "High" "SAP security-relevant path is writable by everyone" "$logical" \
        "Mode $mode permits arbitrary local modification of this $category." \
        "Remove other-write permission and grant changes only to the SAP service owner or an explicitly managed administrator group." \
        "OWASP CBAS: filesystem write attack paths"
    fi
  fi

  if has_bit "$PERM_GROUP" 2; then
    case "$category" in
      "SSFS key"|"SSFS local protection")
        add_finding "SSFS-002" "High" "SSFS key material is group-writable" "$logical" \
          "Mode $mode allows members of group $STAT_GROUP to replace key material." \
          "Confirm the group is operationally required and tightly controlled; otherwise remove group-write and keep matched SSFS data/key backups." \
          "SAP SSFS least-privilege guidance"
        ;;
      Executable)
        add_finding "FILE-003" "High" "SAP executable is group-writable" "$logical" \
          "Mode $mode allows group $STAT_GROUP to modify executable code." \
          "Restrict write access to the software owner and trusted patching workflow; investigate the binary if group membership is broad." \
          "OWASP CBAS: code integrity"
        ;;
      Profile|ACL|Credential|"SSFS data")
        add_finding "FILE-004" "Medium" "Sensitive SAP file is group-writable" "$logical" \
          "Mode $mode allows group $STAT_GROUP to modify this $category." \
          "Validate that every group member requires write access and remove it otherwise; use a dedicated SAP administration group." \
          "SAP security configuration hardening"
        ;;
    esac
  fi

  if [[ "$category" == "SSFS key" || "$category" == "SSFS local protection" ]]; then
    if has_bit "$PERM_OTHER" 4; then
      add_finding "SSFS-003" "Critical" "SSFS key material is readable by everyone" "$logical" \
        "Mode $mode exposes master-key or key-protection material to arbitrary local users." \
        "Remove all access for other users immediately, review access logs and local accounts, and rotate/re-encrypt the secure store if disclosure cannot be excluded." \
        "SAP SSFS least-privilege guidance"
    fi
    if has_bit "$PERM_GROUP" 4; then
      add_finding "SSFS-004" "Medium" "SSFS key material is group-readable" "$logical" \
        "Mode $mode exposes key material to every member of group $STAT_GROUP." \
        "Confirm all group members require access. Prefer owner-only read access where the SAP deployment permits it." \
        "SAP SSFS least-privilege guidance"
    fi
  elif [[ "$category" == "SSFS data" || "$category" == "Credential" ]]; then
    if has_bit "$PERM_OTHER" 4; then
      add_finding "FILE-005" "High" "Secret-bearing SAP data is readable by everyone" "$logical" \
        "Mode $mode allows arbitrary local users to copy encrypted or credential-bearing material for offline analysis." \
        "Remove other-read access, restrict parent-directory traversal, and review whether the matching keys or credentials were also exposed." \
        "OWASP CBAS: filesystem read attack paths"
    fi
  fi

  if ((is_dir)) && has_bit "$PERM_OTHER" 2; then
    add_finding "FILE-006" "High" "SAP directory is writable by everyone" "$logical" \
      "Directory mode $mode permits arbitrary local users to add, replace, or rename SAP files." \
      "Remove other-write; if a shared drop location is intentional, isolate it from executable, profile, transport, and secure-store paths and apply sticky/ACL controls." \
      "OWASP CBAS: filesystem write and transport paths"
  fi
}

record_path() {
  local physical=$1 category=$2 note=${3-}
  [[ -e "$physical" || -L "$physical" ]] || return 0
  local logical
  logical=$(logical_path "$physical")
  [[ -z "${SEEN_PATH[$logical]+x}" ]] || return 0
  SEEN_PATH[$logical]=1
  if stat_fields "$physical"; then
    append_row "$PATHS" "$category" "$logical" "$STAT_TYPE" "$STAT_OWNER" "$STAT_GROUP" "$STAT_MODE" "$STAT_SIZE" "$STAT_MTIME" "$note"
    audit_permission_risk "$logical" "$category" "$STAT_MODE" "$STAT_TYPE"
  else
    append_row "$PATHS" "$category" "$logical" "unknown" "unknown" "unknown" "unknown" "unknown" "unknown" "$note"
  fi
  SAP_EVIDENCE_COUNT=$((SAP_EVIDENCE_COUNT + 1))
}

is_sap_process() {
  local text=${1,,}
  [[ "$text" =~ (^|[[:space:]/\\])(disp\+work|dw\.sap|gwrd|ms\.sap|enserver|enrepserver|icman|igswd_mt|igsmux|sapstartsrv(\.exe)?|saphostexec(\.exe)?|saphostctrl(\.exe)?|saposcol(\.exe)?|saprouter(\.exe)?|sapwebdisp(\.exe)?|jstart(\.exe)?|jlaunch(\.exe)?|hdbdaemon|hdbnameserver|hdbindexserver|hdbcompileserver|hdbpreprocessor|hdbxsengine|hdbscriptserver|hdbwebdispatcher|hdbesserver|hdbdocstore|hdbdpserver|hdbdiserver|dataserver|backupserver|bcksrvr(\.exe)?|oracle|ora_[a-z0-9_]+|tnslsnr|db2sysc|db2wdog|sqlservr(\.exe)?|dbmsrv|x_server|sapinst|sapup|r3trans(\.exe)?|tp(\.exe)?|scc_daemon|cloud.?connector)([[:space:]/\\]|$) ]] ||
    [[ "$text" == *"/usr/sap/"* || "$text" == *"\\usr\\sap\\"* || "$text" == *"/sapmnt/"* || "$text" == *"\\sap\\hostctrl\\"* || "$text" == *"/oracle/"* || "$text" == *"/db2/"* || "$text" == *"/sapdb/"* || "$text" == *"/maxdb/"* ]]
}

component_for_process() {
  local text=${1,,}
  case "$text" in
    *hdb*) printf "SAP HANA" ;;
    *dataserver*|*backupserver*|*bcksrvr*) printf "SAP ASE" ;;
    *ora_pmon*|*tnslsnr*|*/oracle/*|*\\oracle\\*|*" oracle "*) printf "Oracle Database" ;;
    *db2sysc*|*db2wdog*|*/db2/*|*\\db2\\*) printf "IBM Db2" ;;
    *sqlservr*) printf "Microsoft SQL Server" ;;
    *dbmsrv*|*x_server*|*/sapdb/*|*/maxdb/*|*\\sapdb\\*|*\\maxdb\\*) printf "SAP MaxDB" ;;
    *saprouter*) printf "SAProuter" ;;
    *sapwebdisp*) printf "SAP Web Dispatcher" ;;
    *saphost*) printf "SAP Host Agent" ;;
    *sapstartsrv*) printf "SAP Start Service" ;;
    *enserver*|*enrepserver*) printf "SAP Enqueue Server" ;;
    *gwrd*) printf "SAP RFC Gateway" ;;
    *ms.sap*) printf "SAP Message Server" ;;
    *disp+work*|*dw.sap*) printf "SAP Dispatcher/Work Process" ;;
    *icman*) printf "SAP ICM" ;;
    *igs*) printf "SAP IGS" ;;
    *jstart*|*jlaunch*) printf "SAP NetWeaver Java" ;;
    *cloud*connector*|*scc_daemon*) printf "SAP Cloud Connector" ;;
    *sapinst*) printf "SAP Software Provisioning Manager" ;;
    *sapup*) printf "SAP Software Update Manager" ;;
    *) printf "SAP component" ;;
  esac
}

audit_process_command() {
  local name=${1-} command=${2-}
  if [[ "${name,,} ${command,,}" == *saprouter* ]] &&
     [[ "$command" =~ (^|[[:space:]])-X([[:space:]]|$) ]]; then
    add_finding "ROUTER-001" "High" "SAProuter remote administration loopback is enabled" "$name" \
      "The observed SAProuter command line includes -X, which explicitly permits routes from SAProuter back to itself and exposes administrative operations when network and route controls permit access." \
      "Remove -X unless a documented, tightly controlled dependency requires it; restrict port 3299, use a least-privilege saprouttab, and verify SAP Note 3158375 and the current kernel patch level." \
      "SAP Note 1853140; SEC Consult CVE-2022-27668; HackTricks SAProuter references"
  fi
}

collect_processes() {
  log "Collecting SAP processes"
  if ! command -v ps >/dev/null 2>&1; then
    add_coverage "Processes" "unavailable" "ps command not found"
    return
  fi
  local pid user group name args executable component
  while read -r pid user group name args; do
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    is_sap_process "$name $args" || continue
    executable=""
    [[ -e "/proc/$pid/exe" ]] && executable=$(readlink "/proc/$pid/exe" 2>/dev/null || true)
    component=$(component_for_process "$name $executable $args")
    append_row "$PROCESSES" "$pid" "$user" "$group" "$name" "$executable" "$args" "$component"
    SAP_PIDS[$pid]=1; SAP_PROCESS_BY_PID[$pid]=$name
    SAP_EVIDENCE_COUNT=$((SAP_EVIDENCE_COUNT + 1))
    audit_process_command "$name" "$args"
    if [[ -n "$executable" ]]; then
      record_path "$executable" "Executable" "Running $component binary"
    fi
  done < <(ps -eo pid=,user=,group=,comm=,args= 2>/dev/null)
  add_coverage "Processes" "complete" "Local process table inspected; command lines may be permission-limited"
}

collect_services() {
  log "Collecting SAP services"
  local found_any=0
  if command -v systemctl >/dev/null 2>&1; then
    local unit _load active sub description
    while read -r unit _load active sub description; do
      [[ -n "$unit" ]] || continue
      if [[ "${unit,,} ${description,,}" =~ (sap|hana|hdb|sybase|cloud.?connector|scc) ]]; then
        local fragment=""
        fragment=$(systemctl show "$unit" -p FragmentPath --value 2>/dev/null || true)
        append_row "$SERVICES" "$unit" "$active/$sub" "systemd" "" "$fragment" "$description"
        found_any=1
        [[ -n "$fragment" ]] && record_path "$fragment" "Service definition" "Unit $unit"
      fi
    done < <(systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null)
  fi

  local init_dir
  init_dir=$(physical_path "/etc/init.d")
  if [[ -d "$init_dir" ]]; then
    local init
    for init in "$init_dir"/*; do
      [[ -f "$init" ]] || continue
      [[ "${init##*/}" =~ [Ss][Aa][Pp]|[Hh][Dd][Bb]|[Ss][Cc][Cc] ]] || continue
      append_row "$SERVICES" "${init##*/}" "installed/unknown" "init" "" "$(logical_path "$init")" "Legacy service definition"
      record_path "$init" "Service definition" "Legacy init script"
      found_any=1
    done
  fi
  if ((found_any)); then
    add_coverage "Services" "complete" "Local service manager and init definitions inspected"
  else
    add_coverage "Services" "complete" "No SAP-named local service definitions observed"
  fi
}

endpoint_parts() {
  local endpoint=${1-}
  EP_PORT=""; EP_ADDR="$endpoint"
  endpoint=${endpoint%%,*}
  if [[ "$endpoint" =~ ^\[(.*)\]:([0-9]+)$ ]]; then
    EP_ADDR=${BASH_REMATCH[1]}; EP_PORT=${BASH_REMATCH[2]}
  elif [[ "$endpoint" =~ ^(.*):([0-9]+)$ ]]; then
    EP_ADDR=${BASH_REMATCH[1]}; EP_PORT=${BASH_REMATCH[2]}
  fi
  EP_ADDR=${EP_ADDR#[}; EP_ADDR=${EP_ADDR%]}
}

classify_port() {
  local port=${1-}
  PORT_CLASS=""; PORT_TRANSPORT=""; PORT_SENSITIVITY="normal"
  [[ "$port" =~ ^[0-9]+$ ]] || return 1
  case "$port" in
    3298) PORT_CLASS="SAP NI ping"; PORT_TRANSPORT="NI"; PORT_SENSITIVITY="business" ;;
    3299) PORT_CLASS="SAProuter"; PORT_TRANSPORT="NI/Router"; PORT_SENSITIVITY="gateway" ;;
    32[0-9][0-9]) PORT_CLASS="SAP Dispatcher / SAP DIAG or Enqueue"; PORT_TRANSPORT="NI/DIAG"; PORT_SENSITIVITY="business" ;;
    33[0-9][0-9]) PORT_CLASS="SAP RFC Gateway"; PORT_TRANSPORT="RFC/NI (typically unencrypted)"; PORT_SENSITIVITY="admin" ;;
    48[0-9][0-9]) PORT_CLASS="SAP RFC Gateway with SNC"; PORT_TRANSPORT="RFC/NI/SNC"; PORT_SENSITIVITY="admin" ;;
    36[0-9][0-9]) PORT_CLASS="SAP Message Server external"; PORT_TRANSPORT="SAP MS"; PORT_SENSITIVITY="business" ;;
    39[0-9][0-9]) PORT_CLASS="SAP Message Server internal"; PORT_TRANSPORT="SAP MS"; PORT_SENSITIVITY="critical-internal" ;;
    80[0-9][0-9]) PORT_CLASS="SAP ICM HTTP"; PORT_TRANSPORT="HTTP"; PORT_SENSITIVITY="cleartext" ;;
    443[0-9][0-9]) PORT_CLASS="SAP ICM HTTPS"; PORT_TRANSPORT="HTTPS"; PORT_SENSITIVITY="business" ;;
    81[0-9][0-9]) PORT_CLASS="SAP Message Server HTTP"; PORT_TRANSPORT="HTTP"; PORT_SENSITIVITY="cleartext" ;;
    444[0-9][0-9]) PORT_CLASS="SAP Message Server HTTPS"; PORT_TRANSPORT="HTTPS"; PORT_SENSITIVITY="business" ;;
    5[0-9][0-9]00) PORT_CLASS="SAP NetWeaver Java HTTP"; PORT_TRANSPORT="HTTP"; PORT_SENSITIVITY="cleartext" ;;
    5[0-9][0-9]01) PORT_CLASS="SAP NetWeaver Java HTTPS"; PORT_TRANSPORT="HTTPS"; PORT_SENSITIVITY="business" ;;
    5[0-9][0-9]02) PORT_CLASS="SAP NetWeaver Java IIOP initial"; PORT_TRANSPORT="IIOP"; PORT_SENSITIVITY="business" ;;
    5[0-9][0-9]03) PORT_CLASS="SAP NetWeaver Java IIOP over TLS"; PORT_TRANSPORT="IIOP/TLS"; PORT_SENSITIVITY="business" ;;
    5[0-9][0-9]04) PORT_CLASS="SAP NetWeaver Java P4"; PORT_TRANSPORT="P4"; PORT_SENSITIVITY="admin" ;;
    5[0-9][0-9]05) PORT_CLASS="SAP NetWeaver Java P4 over HTTP"; PORT_TRANSPORT="P4/HTTP"; PORT_SENSITIVITY="admin" ;;
    5[0-9][0-9]06) PORT_CLASS="SAP NetWeaver Java P4 over TLS"; PORT_TRANSPORT="P4/TLS"; PORT_SENSITIVITY="admin" ;;
    5[0-9][0-9]07) PORT_CLASS="SAP NetWeaver Java IIOP"; PORT_TRANSPORT="IIOP"; PORT_SENSITIVITY="business" ;;
    5[0-9][0-9]08) PORT_CLASS="SAP NetWeaver Java shell/telnet"; PORT_TRANSPORT="Telnet"; PORT_SENSITIVITY="critical-admin" ;;
    5[0-9][0-9]10) PORT_CLASS="SAP NetWeaver Java JMS"; PORT_TRANSPORT="JMS"; PORT_SENSITIVITY="business" ;;
    5[0-9][0-9]13) PORT_CLASS="SAP Start Service HTTP"; PORT_TRANSPORT="HTTP/SOAP"; PORT_SENSITIVITY="admin-cleartext" ;;
    5[0-9][0-9]14) PORT_CLASS="SAP Start Service HTTPS"; PORT_TRANSPORT="HTTPS/SOAP"; PORT_SENSITIVITY="admin" ;;
    5[0-9][0-9]17) PORT_CLASS="SAP Java SDM administration"; PORT_TRANSPORT="proprietary"; PORT_SENSITIVITY="critical-admin" ;;
    5[0-9][0-9]18) PORT_CLASS="SAP Java SDM GUI"; PORT_TRANSPORT="proprietary"; PORT_SENSITIVITY="critical-admin" ;;
    5[0-9][0-9]19) PORT_CLASS="SAP Java SDM HTTP"; PORT_TRANSPORT="HTTP"; PORT_SENSITIVITY="critical-admin" ;;
    4901) PORT_CLASS="SAP ASE Data Server"; PORT_TRANSPORT="TDS/ASE"; PORT_SENSITIVITY="database" ;;
    4902) PORT_CLASS="SAP ASE Backup Server"; PORT_TRANSPORT="TDS/ASE backup"; PORT_SENSITIVITY="database" ;;
    4903) PORT_CLASS="SAP ASE Job Scheduler"; PORT_TRANSPORT="ASE internal"; PORT_SENSITIVITY="critical-internal" ;;
    49[0-9][0-9]) PORT_CLASS="SAP ASE configurable service"; PORT_TRANSPORT="TDS/ASE"; PORT_SENSITIVITY="database" ;;
    4[0-9][0-9]00) PORT_CLASS="SAP IGS multiplexer"; PORT_TRANSPORT="IGS"; PORT_SENSITIVITY="business" ;;
    4[0-9][0-9]0[1-9]|4[0-9][0-9][1-7][0-9]) PORT_CLASS="SAP IGS portwatcher"; PORT_TRANSPORT="IGS"; PORT_SENSITIVITY="business" ;;
    4[0-9][0-9]8[0-9]|4[0-9][0-9]9[0-9]) PORT_CLASS="SAP IGS HTTP"; PORT_TRANSPORT="HTTP"; PORT_SENSITIVITY="admin-cleartext" ;;
    3[0-9][0-9]00) PORT_CLASS="SAP HANA daemon"; PORT_TRANSPORT="HANA internal"; PORT_SENSITIVITY="critical-internal" ;;
    3[0-9][0-9]01) PORT_CLASS="SAP HANA nameserver internal"; PORT_TRANSPORT="HANA internal"; PORT_SENSITIVITY="critical-internal" ;;
    3[0-9][0-9]02) PORT_CLASS="SAP HANA preprocessor internal"; PORT_TRANSPORT="HANA internal"; PORT_SENSITIVITY="critical-internal" ;;
    3[0-9][0-9]03) PORT_CLASS="SAP HANA indexserver internal"; PORT_TRANSPORT="HANA internal"; PORT_SENSITIVITY="critical-internal" ;;
    3[0-9][0-9]04) PORT_CLASS="SAP HANA scriptserver internal"; PORT_TRANSPORT="HANA internal"; PORT_SENSITIVITY="critical-internal" ;;
    3[0-9][0-9]05) PORT_CLASS="SAP HANA statisticsserver internal"; PORT_TRANSPORT="HANA internal"; PORT_SENSITIVITY="critical-internal" ;;
    3[0-9][0-9]13) PORT_CLASS="SAP HANA SystemDB SQL/MDX"; PORT_TRANSPORT="HDB"; PORT_SENSITIVITY="database" ;;
    3[0-9][0-9]15) PORT_CLASS="SAP HANA first tenant SQL/MDX"; PORT_TRANSPORT="HDB"; PORT_SENSITIVITY="database" ;;
    3[0-9][0-9]17) PORT_CLASS="SAP HANA internal SQL"; PORT_TRANSPORT="HDB"; PORT_SENSITIVITY="critical-internal" ;;
    3[0-9][0-9]2[6-9]) PORT_CLASS="SAP HANA optional service"; PORT_TRANSPORT="HANA"; PORT_SENSITIVITY="business" ;;
    3[0-9][0-9][4-9][0-9]) PORT_CLASS="SAP HANA tenant/internal dynamic service"; PORT_TRANSPORT="HANA"; PORT_SENSITIVITY="database" ;;
    1128) PORT_CLASS="SAP Host Agent HTTP"; PORT_TRANSPORT="HTTP/SOAP"; PORT_SENSITIVITY="admin-cleartext" ;;
    1129) PORT_CLASS="SAP Host Agent HTTPS"; PORT_TRANSPORT="HTTPS/SOAP"; PORT_SENSITIVITY="admin" ;;
    21212) PORT_CLASS="SAPinst web interface HTTP"; PORT_TRANSPORT="HTTP"; PORT_SENSITIVITY="critical-admin" ;;
    21213) PORT_CLASS="SAPinst web interface HTTPS"; PORT_TRANSPORT="HTTPS"; PORT_SENSITIVITY="critical-admin" ;;
    4238|4239|4240|4241) PORT_CLASS="SAP update/upgrade administration"; PORT_TRANSPORT="administration"; PORT_SENSITIVITY="critical-admin" ;;
    59975|59976) PORT_CLASS="SAPinst platform service"; PORT_TRANSPORT="administration"; PORT_SENSITIVITY="critical-admin" ;;
    *) return 1 ;;
  esac
  return 0
}

is_loopback() {
  local addr=${1,,}
  addr=${addr%%%*}
  [[ "$addr" == "localhost" || "$addr" == "::1" || "$addr" == 127.* ]]
}

is_wildcard() {
  local addr=${1,,}
  [[ -z "$addr" || "$addr" == "*" || "$addr" == "0.0.0.0" || "$addr" == "::" || "$addr" == "0:0:0:0:0:0:0:0" ]]
}

is_collected_sap_pid() {
  local pid=${1-}
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  [[ -n "${SAP_PIDS[$pid]+x}" ]]
}

record_socket() {
  local protocol=$1 state=$2 local_ep=$3 remote_ep=$4 pid=${5-} process=${6-} service=${7-}
  endpoint_parts "$local_ep"; local local_addr=$EP_ADDR local_port=$EP_PORT
  endpoint_parts "$remote_ep"; local remote_port=$EP_PORT
  local classification="" transport="" sensitivity=""
  if [[ "${state^^}" =~ ^(LISTEN|LISTENING|UNCONN|UDP|BOUND)$ ]]; then
    if classify_port "$local_port"; then
      classification=$PORT_CLASS; transport=$PORT_TRANSPORT; sensitivity=$PORT_SENSITIVITY
    elif classify_port "$remote_port"; then
      classification=$PORT_CLASS; transport=$PORT_TRANSPORT; sensitivity=$PORT_SENSITIVITY
    fi
  else
    # Connected sockets normally use an ephemeral local port. Prefer the peer
    # port so an ephemeral value such as 53000 is not misread as Java HTTP.
    if classify_port "$remote_port"; then
      classification=$PORT_CLASS; transport=$PORT_TRANSPORT; sensitivity=$PORT_SENSITIVITY
    elif classify_port "$local_port"; then
      classification=$PORT_CLASS; transport=$PORT_TRANSPORT; sensitivity=$PORT_SENSITIVITY
    fi
  fi
  if [[ -z "$classification" ]]; then
    if is_collected_sap_pid "$pid" || is_sap_process "$process $service"; then
      classification=$(component_for_process "$process $service")
      transport="unclassified"
      sensitivity="unknown"
      [[ "$classification" == "SAP Cloud Connector" ]] && sensitivity="admin"
    else
      return 0
    fi
  fi

  local exposure="connected"
  case "${state^^}" in
    LISTEN|LISTENING|UNCONN|UDP)
      if is_loopback "$local_addr"; then exposure="loopback"
      elif is_wildcard "$local_addr"; then exposure="all-interfaces"
      else exposure="network-interface"
      fi
      ;;
  esac

  if [[ -z "$process" ]] && is_collected_sap_pid "$pid"; then
    process=${SAP_PROCESS_BY_PID[$pid]-}
  fi
  if [[ "${process,,} ${service,,}" =~ (^|[[:space:]/\\])(enserver|enrepserver)([[:space:]/\\]|$) ]]; then
    classification="SAP Enqueue Server"
    transport="SAP Enqueue/NI"
    sensitivity="critical-internal"
  fi
  append_row "$SOCKETS" "$classification" "$transport" "$protocol" "$state" "$local_ep" "$remote_ep" "$exposure" "$pid" "$process" "$service"
  SAP_EVIDENCE_COUNT=$((SAP_EVIDENCE_COUNT + 1))

  if [[ "$exposure" == "all-interfaces" || "$exposure" == "network-interface" ]]; then
    case "$sensitivity" in
      critical-admin)
        add_finding "NET-001" "High" "High-impact SAP administration service is network-reachable" "$classification at $local_ep" \
          "A listening $transport endpoint is bound to $local_addr. Exposure is evidence of reachability, not proof of an exploitable service." \
          "Bind the service to a dedicated administration interface or loopback where supported, restrict it with host/network firewalls, require strong authentication, and confirm the component is patched." \
          "OWASP SAP Pentest Playbook service exposure"
        ;;
      critical-internal)
        add_finding "NET-002" "High" "Internal SAP service is bound beyond loopback" "$classification at $local_ep" \
          "The internal service is listening on $local_addr; these protocols normally require strict network isolation." \
          "Restrict the binding and firewall path to explicitly required SAP cluster hosts. For HANA, use network separation and encrypted internal communication where supported." \
          "SAP internal-service network separation guidance"
        ;;
      admin-cleartext)
        add_finding "NET-003" "High" "Cleartext SAP management endpoint is network-reachable" "$classification at $local_ep" \
          "The HTTP/administration endpoint is listening on $local_addr without transport encryption." \
          "Prefer the TLS endpoint, bind cleartext management to loopback when SAP requires it locally, and restrict remote access with host/network controls." \
          "SAP Host Agent and SAP Start Service security guidance"
        ;;
      cleartext)
        add_finding "NET-004" "Medium" "SAP HTTP endpoint is network-reachable" "$classification at $local_ep" \
          "The endpoint uses cleartext HTTP on a non-loopback binding." \
          "Confirm the endpoint contains no authenticated or sensitive workflow; redirect to HTTPS, disable unnecessary HTTP ports, and enforce TLS at ICM/Web Dispatcher." \
          "OWASP SAP ICM attack-surface guidance"
        ;;
      gateway)
        add_finding "NET-005" "Medium" "SAProuter is network-reachable" "$classification at $local_ep" \
          "SAProuter is expected to be a boundary component, but its reachability makes route-table scope and patching security-critical." \
          "Review saprouttab for least-privilege routes, require SNC where appropriate, restrict management access, and keep SAProuter patched." \
          "OWASP SAP Pentest Playbook: SAProuter"
        ;;
      admin)
        add_finding "NET-006" "Medium" "SAP administration endpoint is network-reachable" "$classification at $local_ep" \
          "An SAP administrative service is listening beyond loopback. Encryption alone does not provide network isolation or strong administrative authorization." \
          "Restrict the listener and firewall path to approved administration networks, require strong authentication, and review TLS certificate trust and patch level." \
          "SAP component security guidance; OWASP CBAS attack-surface research"
        ;;
      database)
        add_finding "NET-007" "Medium" "SAP database endpoint is network-reachable" "$classification at $local_ep" \
          "A database client endpoint is listening beyond loopback. This proves a local bind, not reachability from an untrusted zone or weak authentication." \
          "Restrict the host/network path to approved application and administration systems, require product-supported TLS with certificate and hostname validation, and review database authentication and audit policy." \
          "SecuritySilverbacks SAP HANA/ASE service discovery; PySAP HDB documentation"
        ;;
    esac
    if [[ "$classification" == "SAP NetWeaver Java shell/telnet" ]]; then
      add_finding "JAVA-001" "High" "SAP Java shell/telnet is exposed beyond loopback" "$local_ep" \
        "The administrative shell port is listening on a non-loopback interface." \
        "Bind the TELNET listener to localhost as shown in SAP profile examples, limit the telnet_login role, or disable the service if it is not operationally required." \
        "SAP AS Java shell console guidance"
    fi
    if [[ "$classification" == "SAP Message Server internal" ]]; then
      add_finding "MS-001" "High" "SAP Message Server internal port is broadly bound" "$local_ep" \
        "The 39NN internal cluster-management port is reachable on a non-loopback interface and must be network-isolated." \
        "Permit only required application-server hosts at host/network firewalls and validate message-server ACL configuration." \
        "OWASP SAP Pentest Playbook: Message Server internal port"
    fi
    if [[ "$classification" == "SAP Dispatcher / SAP DIAG or Enqueue" ]]; then
      add_finding "DIAG-001" "Medium" "SAP Dispatcher/DIAG endpoint requires SNC and boundary validation" "$local_ep" \
        "The 32NN endpoint is listening beyond loopback; classic DIAG does not provide confidentiality unless SNC is negotiated." \
        "Restrict network paths to approved clients, require SNC with privacy where feasible, and validate enforcement from an authorized client." \
        "OWASP SAP Pentest Playbook: Dispatcher; OWASP sncscan"
    fi
    if [[ "$classification" == "SAP Message Server external" ]]; then
      add_finding "MS-003" "Medium" "SAP Message Server external endpoint is network-reachable" "$local_ep" \
        "The 36NN service is listening beyond loopback and can expose landscape/service metadata if network boundaries or ACLs are weak." \
        "Limit access to required SAP clients/servers, maintain message-server ACLs, and separately validate external reachability." \
        "OWASP SAP Pentest Playbook: Message Server"
    fi
    if [[ "$classification" == "SAP Enqueue Server" ]]; then
      add_finding "ENQ-001" "High" "SAP Enqueue service is bound beyond loopback" "$local_ep" \
        "The Enqueue or Enqueue Replication listener is reachable on a non-loopback interface and exposes a high-impact internal coordination service." \
        "Permit only explicitly required SAP cluster peers at host and network firewalls, restrict monitor/administrative access, and verify the current kernel and Enqueue patch posture." \
        "OWASP PySAP Enqueue documentation; SAP Pentest Playbook internal-service isolation"
    fi
  fi

  if [[ "$classification" == "SAP RFC Gateway" && "$exposure" != "loopback" ]]; then
    add_finding "GW-001" "Medium" "Unencrypted RFC Gateway endpoint is reachable" "$local_ep" \
      "Port family 33NN is normally RFC/NI without SNC. This does not prove that individual RFC sessions lack application controls." \
      "Use SNC for sensitive RFC paths, restrict gateway reachability, and enforce restrictive secinfo/reginfo rules." \
      "OWASP SAP Pentest Playbook: RFC Gateway"
  fi
}

collect_sockets() {
  log "Collecting listening and connected SAP sockets"
  if command -v ss >/dev/null 2>&1; then
    local protocol state _recvq _sendq local_ep remote_ep rest pid process
    while read -r protocol state _recvq _sendq local_ep remote_ep rest; do
      [[ -n "$protocol" && -n "$local_ep" ]] || continue
      pid=""; process=""
      if [[ "$rest" =~ \"([^\"]+)\".*pid=([0-9]+) ]]; then
        process=${BASH_REMATCH[1]}; pid=${BASH_REMATCH[2]}
      fi
      record_socket "${protocol^^}" "$state" "$local_ep" "$remote_ep" "$pid" "$process" ""
    done < <(ss -H -tunap 2>/dev/null)
    add_coverage "Sockets" "complete" "ss -tunap; process attribution depends on privileges"
  elif command -v netstat >/dev/null 2>&1; then
    local protocol _recvq _sendq local_ep remote_ep state pidprogram pid process
    while read -r protocol _recvq _sendq local_ep remote_ep state pidprogram; do
      [[ "${protocol,,}" =~ ^(tcp|udp) ]] || continue
      pid=""; process=""
      if [[ "$pidprogram" =~ ^([0-9]+)/(.+)$ ]]; then pid=${BASH_REMATCH[1]}; process=${BASH_REMATCH[2]}; fi
      [[ "${protocol,,}" == udp* ]] && state="UDP"
      record_socket "${protocol^^}" "$state" "$local_ep" "$remote_ep" "$pid" "$process" ""
    done < <(netstat -tunap 2>/dev/null)
    add_coverage "Sockets" "partial" "netstat fallback; process attribution depends on privileges"
  elif command -v lsof >/dev/null 2>&1; then
    local command pid user _fd type _device _size node name local_ep remote_ep state
    while read -r command pid user _fd type _device _size node name; do
      [[ "$node" == TCP || "$node" == UDP ]] || continue
      local_ep=${name%%->*}; remote_ep="*:*"; state="UDP"
      if [[ "$name" == *"->"* ]]; then remote_ep=${name#*->}; state="ESTABLISHED"
      elif [[ "$name" == *"(LISTEN)"* ]]; then local_ep=${name%% *}; state="LISTEN"
      fi
      record_socket "$node" "$state" "$local_ep" "$remote_ep" "$pid" "$command" ""
    done < <(lsof -nP -iTCP -iUDP 2>/dev/null)
    add_coverage "Sockets" "partial" "lsof fallback"
  else
    add_coverage "Sockets" "unavailable" "No ss, netstat, or lsof command found"
    warn "No socket inventory command found; report will note the coverage gap"
  fi
}

discover_systems() {
  log "Discovering SAP systems and instances"
  local logical_root physical sid_dir sid sid_u stack instances instance name key
  for logical_root in /usr/sap /sapmnt; do
    physical=$(physical_path "$logical_root")
    [[ -d "$physical" ]] || continue
    record_path "$physical" "SAP root" "Standard SAP installation root"
    for sid_dir in "$physical"/*; do
      [[ -d "$sid_dir" ]] || continue
      sid=${sid_dir##*/}; sid_u=${sid^^}
      [[ "$sid_u" =~ ^[A-Z][A-Z0-9]{2}$ ]] || continue
      [[ "$sid_u" =~ ^(SYS|SUM)$ ]] && continue
      stack="Unknown"
      [[ -d "$sid_dir/SYS/global/hdb" ]] && stack="SAP HANA"
      [[ -d "$sid_dir/SYS/profile" ]] && stack=$([[ "$stack" == "SAP HANA" ]] && printf "SAP HANA / NetWeaver" || printf "SAP NetWeaver")
      instances=""
      for instance in "$sid_dir"/*; do
        [[ -d "$instance" ]] || continue
        name=${instance##*/}
        if [[ "$name" =~ ^(D|J|DVEBMGS|ASCS|SCS|ERS|HDB|PAS|AAS|SMDA|W)[0-9]{2}$ ]]; then
          [[ -z "$instances" ]] || instances+=", "
          instances+="$name"
          record_path "$instance" "SAP instance" "SID $sid_u instance $name"
        fi
      done
      key="$sid_u|$(logical_path "$sid_dir")"
      if [[ -z "${SEEN_SYSTEM[$key]+x}" ]]; then
        SEEN_SYSTEM[$key]=1
        append_row "$SYSTEMS" "$sid_u" "$stack" "$instances" "$(logical_path "$sid_dir")" "$logical_root directory"
        SAP_EVIDENCE_COUNT=$((SAP_EVIDENCE_COUNT + 1))
      fi
      record_path "$sid_dir" "SAP system" "SID $sid_u"
    done
  done

  local sapservices
  sapservices=$(physical_path "/usr/sap/sapservices")
  if [[ -f "$sapservices" ]]; then
    record_path "$sapservices" "Service definition" "SAP instance startup registry"
    while IFS= read -r line; do
      [[ "$line" == *pf=* ]] || continue
      if [[ "$line" =~ /usr/sap/([A-Za-z][A-Za-z0-9]{2})/ ]]; then
        sid_u=${BASH_REMATCH[1]^^}
        key="$sid_u|sapservices"
        if [[ -z "${SEEN_SYSTEM[$key]+x}" ]]; then
          SEEN_SYSTEM[$key]=1
          append_row "$SYSTEMS" "$sid_u" "SAP (from sapservices)" "" "/usr/sap/$sid_u" "/usr/sap/sapservices"
        fi
      fi
    done < "$sapservices"
  fi
  add_coverage "SAP systems" "complete" "Standard /usr/sap and /sapmnt layouts plus sapservices inspected"
}

scan_known_paths() {
  log "Inventorying standard SAP paths"
  local logical physical category
  while IFS='|' read -r logical category; do
    physical=$(physical_path "$logical")
    [[ -e "$physical" ]] && record_path "$physical" "$category" "Known SAP path"
  done <<'EOF'
/usr/sap|SAP root
/sapmnt|SAP root
/hana/shared|SAP HANA shared
/hana/data|SAP HANA data
/hana/log|SAP HANA log
/usr/sap/hostctrl|SAP Host Agent
/usr/sap/trans|SAP transport
/usr/sap/sapinst_instdir|SAP installer
/var/tmp/sapinst_exe|SAP installer
/opt/sap|SAP product
/var/lib/sap|SAP product
/var/log/sap|SAP log
/sybase|SAP ASE
/opt/sybase|SAP ASE
/oracle|Oracle for SAP
/sapdb|SAP MaxDB
/opt/sapdb|SAP MaxDB
/var/opt/sapdb|SAP MaxDB
/db2|IBM Db2 for SAP
/usr/sap/SAPBusinessObjects|SAP BusinessObjects
EOF
}

scan_security_artifacts() {
  log "Inventorying SAP security, audit, transport, and client artifacts"
  local roots=() logical physical root file base lower category note count=0
  for logical in /usr/sap /sapmnt /hana/shared /opt/sap /var/lib/sap /home /root; do
    physical=$(physical_path "$logical")
    [[ -d "$physical" ]] && roots+=("$physical")
  done

  for root in "${roots[@]}"; do
    while IFS= read -r -d '' file; do
      count=$((count + 1))
      if ((count > MAX_FILES)); then
        TRUNCATED_SCANS=$((TRUNCATED_SCANS + 1))
        break 2
      fi
      base=${file##*/}
      lower=${base,,}
      category="SAP security artifact"
      note="Metadata only; content not collected"
      case "$lower" in
        *webgui*)
          category="SAP WebGUI artifact"
          note="Host-side WebGUI-named artifact; active SICF service still requires authenticated confirmation"
          ;;
        *.pse|cred_v2|cred_v2.*|*.cred|secstore.properties|secstore.key|dlmanager.conf)
          category="Credential"
          note="PSE, Java secure-store, Download Manager, or credential container; content and private keys not read"
          ;;
        *.jks|*.keystore|cacerts|keystore.xml)
          category="Credential"
          note="Java/SCC key store; content, aliases, and passwords not read"
          ;;
        audit*|*audit*.log|sal*.log)
          category="Audit log"
          note="Security/audit log presence and metadata only"
          ;;
        dev_w*|dev_disp|dev_ms|dev_rd|dev_icm|dev_jstart|dev_server*|std_server*)
          category="SAP trace"
          note="Runtime trace presence and metadata only"
          ;;
        saprouttab|secinfo|reginfo|prxyinfo|ms_acl_info|*.acl)
          category="ACL"
          note="SAP access-control artifact"
          ;;
        cofiles|data|buffer)
          category="SAP transport"
          note="Transport directory/file metadata"
          ;;
        *.sar|*.car|*.sca|*.sda)
          category="SAP archive"
          note="Deployable or transportable SAP archive"
          ;;
        saphistory*.db|history)
          category="SAP GUI history"
          note="Client-side user-input history; content not read"
          add_finding "GUI-001" "High" "SAP GUI input-history data is present" "$(logical_path "$file")" \
            "SAP GUI history can contain business data, identifiers, table names, and other clear-text field input. Older Java clients stored it unencrypted and older Windows clients used reversible XOR-based protection." \
            "Confirm the SAP GUI edition and patch level. Apply the relevant SAP security notes, disable history where the business risk requires it, exclude sensitive fields, and remove old history through an approved user-data procedure." \
            "OWASP CBAS research: CVE-2025-0055/CVE-2025-0056"
          ;;
      esac
      record_path "$file" "$category" "$note"
    done < <(find "$root" -xdev -maxdepth 12 \
      \( -type f \( -iname '*.pse' -o -iname 'cred_v2*' -o -iname '*.cred' -o -iname 'SecStore.properties' \
         -o -iname 'SecStore.key' -o -iname 'dlmanager.conf' -o -iname '*.jks' \
         -o -iname '*.keystore' -o -iname 'cacerts' -o -iname 'keystore.xml' -o -iname 'audit*' \
         -o -iname '*audit*.log' -o -iname 'sal*.log' -o -iname 'dev_w*' -o -iname 'dev_disp' \
         -o -iname 'dev_ms' -o -iname 'dev_rd' -o -iname 'dev_icm' -o -iname 'dev_webdisp' \
         -o -iname 'dev_jstart' -o -iname 'dev_server*' -o -iname 'std_server*' -o -iname 'prxyinfo' \
         -o -iname 'ms_acl_info' -o -iname '*.acl' -o -iname '*.sar' -o -iname '*.car' \
         -o -iname '*.sca' -o -iname '*.sda' -o -iname 'SAPHistory*.db' -o -iname '*webgui*' \) \
         -o -type d \( -iname 'cofiles' -o -iname 'data' -o -iname 'buffer' -o -iname 'History' -o -iname '*webgui*' \) \) \
      -print0 2>/dev/null)
  done
  if ((count > MAX_FILES)); then
    add_coverage "Security artifacts" "partial" "Stopped at --max-files=$MAX_FILES"
  else
    add_coverage "Security artifacts" "complete" "PSE/credential, Java SecStore, Download Manager, audit/trace, transport/archive, ACL, SAP GUI history, and WebGUI-named artifact patterns inspected without reading protected content"
  fi
}

ssfs_hex_prefix() {
  local path=$1 count=${2:-12}
  od -An -tx1 -N "$count" -- "$path" 2>/dev/null | tr -d ' \n'
}

ssfs_data_shape() {
  local path=$1 size=$2 offset=0 count=0 status="recognized"
  local prefix bytes b0 b1 b2 b3 le be length remaining
  while ((offset + 176 <= size && count < 10000)); do
    prefix=$(dd if="$path" bs=1 skip="$offset" count=12 2>/dev/null | od -An -tx1 | tr -d ' \n')
    [[ "$prefix" == "525365635353467344617461" ]] || { status="trailing or unrecognized bytes at offset $offset"; break; }
    bytes=$(od -An -tu1 -j $((offset + 12)) -N 4 -- "$path" 2>/dev/null)
    read -r b0 b1 b2 b3 <<< "$bytes"
    [[ "$b0" =~ ^[0-9]+$ && "$b1" =~ ^[0-9]+$ && "$b2" =~ ^[0-9]+$ && "$b3" =~ ^[0-9]+$ ]] ||
      { status="unreadable record length at offset $offset"; break; }
    le=$((b0 + b1*256 + b2*65536 + b3*16777216))
    be=$((b3 + b2*256 + b1*65536 + b0*16777216))
    remaining=$((size - offset))
    length=0
    if ((le >= 176 && le <= remaining)); then length=$le
    elif ((be >= 176 && be <= remaining)); then length=$be
    else status="invalid record length at offset $offset"; break
    fi
    offset=$((offset + length))
    count=$((count + 1))
  done
  if ((offset == size)); then status="recognized structure"
  elif ((count == 0)) && [[ "$status" == "recognized" ]]; then status="empty or unrecognized data file"
  fi
  SSFS_RECORD_COUNT=$count
  SSFS_SHAPE=$status
}

classify_ssfs_file() {
  local logical=$1 basename_u=$2
  SSFS_FAMILY="Generic SAP SSFS"; SSFS_ROLE="SSFS artifact"; SSFS_SID=""; SSFS_DETAIL=""
  if [[ "$logical" == *"/scc_config/"* || "$basename_u" == SSFS_SCC.* ]]; then
    SSFS_FAMILY="SAP Cloud Connector SSFS"
  elif [[ "$logical" == *"/.hdb/"* || "$basename_u" == SSFS_HDB.* && "$logical" == *"/home/"* ]]; then
    SSFS_FAMILY="SAP HANA client user store"
  elif [[ "$logical" == *"/global/hdb/security/ssfs/"* ]]; then
    SSFS_FAMILY="SAP HANA instance SSFS"
  elif [[ "$logical" == *"/global/security/rsecssfs/"* ]]; then
    SSFS_FAMILY="ABAP / HANA System-PKI RSEC SSFS"
  elif [[ "$logical" == *"/rsecssfs/"* ]]; then
    SSFS_FAMILY="RSEC SSFS"
  fi

  if [[ "$basename_u" =~ ^SSFS_([A-Z0-9]{3})\.(DAT|DA_|KEY|KE_|LCK|LKY)$ ]]; then
    SSFS_SID=${BASH_REMATCH[1]}
  elif [[ "$basename_u" =~ ^SSFS_([^.]*)\. ]]; then
    SSFS_SID=${BASH_REMATCH[1]}
  fi
  case "$basename_u" in
    *.DAT) SSFS_ROLE="SSFS data"; SSFS_DETAIL="Active secure-store data" ;;
    *.DA_) SSFS_ROLE="SSFS data backup"; SSFS_DETAIL="Recovery copy created before non-trivial data changes" ;;
    *.KEY) SSFS_ROLE="SSFS key"; SSFS_DETAIL="Individual master-key material" ;;
    *.KE_) SSFS_ROLE="SSFS key backup"; SSFS_DETAIL="Recovery copy of individual master-key material" ;;
    *.LCK) SSFS_ROLE="SSFS lock"; SSFS_DETAIL="Store lock metadata" ;;
    *.LKY) SSFS_ROLE="SSFS local protection"; SSFS_DETAIL="Enhanced/key-protection local key material" ;;
  esac
}

record_ssfs_file() {
  local physical=$1
  [[ -f "$physical" ]] || return 0
  local logical basename basename_u stem header detail category
  logical=$(logical_path "$physical")
  [[ -z "${SEEN_SSFS[$logical]+x}" ]] || return 0
  SEEN_SSFS[$logical]=1
  basename=${physical##*/}; basename_u=${basename^^}; stem=${basename_u%.*}
  classify_ssfs_file "$logical" "$basename_u"
  stat_fields "$physical" || return 0
  header=$(ssfs_hex_prefix "$physical" 12)
  detail=$SSFS_DETAIL
  case "$SSFS_ROLE" in
    "SSFS data"|"SSFS data backup")
      ssfs_data_shape "$physical" "${STAT_SIZE:-0}"
      detail+="; $SSFS_RECORD_COUNT record(s); $SSFS_SHAPE; values not read"
      SSFS_DATA_PATHS[$stem]="${SSFS_DATA_PATHS[$stem]-}${SSFS_DATA_PATHS[$stem]:+; }$logical"
      SSFS_FAMILY_BY_STEM[$stem]=$SSFS_FAMILY
      ;;
    "SSFS key"|"SSFS key backup")
      local type_byte=""
      type_byte=$(od -An -tu1 -j 11 -N 1 -- "$physical" 2>/dev/null | tr -d ' ')
      if [[ "$header" == 52536563535346734b6579* ]]; then
        detail+="; recognized RSecSSFsKey; type ${type_byte:-unknown}; ${STAT_SIZE} bytes; key bytes not read"
      else
        detail+="; header not recognized; key bytes not read"
      fi
      SSFS_KEY_PATHS[$stem]="${SSFS_KEY_PATHS[$stem]-}${SSFS_KEY_PATHS[$stem]:+; }$logical"
      ;;
    "SSFS local protection")
      [[ "$header" == 52536563535346734c4b59* ]] && detail+="; recognized RSecSSFsLKY preamble"
      ;;
    "SSFS lock")
      [[ "$header" == 52536563535346734c6f636b ]] && detail+="; recognized RSecSSFsLock preamble"
      ;;
  esac
  append_row "$SSFS" "$SSFS_FAMILY" "$SSFS_SID" "$SSFS_ROLE" "$logical" "$STAT_SIZE" "$STAT_OWNER" "$STAT_GROUP" "$STAT_MODE" "$detail"
  category=$SSFS_ROLE
  case "$SSFS_ROLE" in
    "SSFS key backup") category="SSFS key" ;;
    "SSFS data backup") category="SSFS data" ;;
  esac
  record_path "$physical" "$category" "$SSFS_FAMILY; secret-bearing metadata only"
  SAP_EVIDENCE_COUNT=$((SAP_EVIDENCE_COUNT + 1))
}

scan_ssfs() {
  log "Discovering all recognized SAP SSFS families"
  local roots=() logical physical configured candidate count=0
  for logical in /usr/sap /sapmnt /opt/sap /var/lib/sap /home /root; do
    physical=$(physical_path "$logical")
    [[ -d "$physical" ]] && roots+=("$physical")
  done
  for configured in "${RSEC_SSFS_DATAPATH-}" "${RSEC_SSFS_KEYPATH-}" "${RSEC_SSFS_LKYPATH-}" "${CONFIGURED_SSFS_PATHS[@]-}"; do
    [[ -n "$configured" && "$configured" == /* ]] || continue
    if [[ "$ROOT_PATH" == "/" ]]; then candidate=$configured; else candidate="$ROOT_PATH$configured"; fi
    [[ -d "$candidate" ]] && roots+=("$candidate")
  done
  local root
  for root in "${roots[@]}"; do
    while IFS= read -r -d '' candidate; do
      record_ssfs_file "$candidate"
      count=$((count + 1))
      if ((count >= MAX_FILES)); then TRUNCATED_SCANS=$((TRUNCATED_SCANS + 1)); break 2; fi
    done < <(find "$root" -xdev -maxdepth 12 -type f \
      \( -iname 'SSFS_*.DAT' -o -iname 'SSFS_*.DA_' -o -iname 'SSFS_*.KEY' -o -iname 'SSFS_*.KE_' -o -iname 'SSFS_*.LCK' -o -iname 'SSFS_*.LKY' \) \
      -print0 2>/dev/null)
  done

  local stem family data key
  for stem in "${!SSFS_DATA_PATHS[@]}"; do
    [[ "$stem" == *.DAT || "$stem" == *.DA_ ]] && true
    data=${SSFS_DATA_PATHS[$stem]}
    key=${SSFS_KEY_PATHS[$stem]-}
    family=${SSFS_FAMILY_BY_STEM[$stem]-Generic SAP SSFS}
    if [[ -z "$key" ]]; then
      if [[ "$family" == "SAP Cloud Connector SSFS" ]]; then
        add_finding "SSFS-005" "High" "Cloud Connector SSFS has no individual key file in audited paths" "$data" \
          "A Cloud Connector SSFS data file was observed without a matching .KEY. This can be the product's compatibility/default-key mode, which provides obfuscation rather than independent key confidentiality; a separately configured key path is also possible." \
          "Confirm the deployed SCC version and supported key-management mode with SAP. Restrict the scc_config path, protect the Java keystore consistently, and use an individual key only through an SAP-supported lifecycle procedure." \
          "SAP SSFS key-management guidance; SCC context must be validated"
      elif [[ "$family" == "SAP HANA client user store" ]]; then
        add_finding "SSFS-006" "High" "HANA user-store data has no matching host key" "$data" \
          "SSFS_HDB.DAT was found without SSFS_HDB.KEY in the audited paths; the pair is normally host/user bound." \
          "Run hdbuserstore as the owning account to validate the store, restore the matched host-bound key if appropriate, and recreate entries rather than copying unrelated keys." \
          "SAP HANA secure user store guidance"
      else
        add_finding "SSFS-007" "High" "SSFS data has no matching individual key in audited paths" "$data" \
          "No matching $stem.KEY was observed. For ABAP SSFS, absence can mean use of the built-in default key; it can also mean the configured key path was outside collection scope." \
          "Use official rsecssfx info/list with the instance profile to confirm key mode and readability. SAP recommends an individual key; do not copy or replace key files ad hoc." \
          "SAP SSFS key-management guidance"
      fi
    fi
  done
  for stem in "${!SSFS_KEY_PATHS[@]}"; do
    [[ -n "${SSFS_DATA_PATHS[$stem]-}" ]] && continue
    add_finding "SSFS-008" "Medium" "SSFS key has no matching data file in audited paths" "${SSFS_KEY_PATHS[$stem]}" \
      "A key artifact was observed without the matching data file. The data path may be separately configured or the artifact may be an orphan/backup." \
      "Resolve the configured data path from the SAP instance profile and validate the pair with official tooling. Preserve recovery copies before cleanup; never substitute an unrelated key." \
      "SAP SSFS recovery guidance"
  done

  if ((count >= MAX_FILES)); then
    add_coverage "SSFS" "partial" "Stopped at --max-files=$MAX_FILES"
  else
    add_coverage "SSFS" "complete" "ABAP/RSEC, HANA instance, HANA System-PKI, hdbuserstore, enhanced LKY, and SCC naming/layouts inspected; values and key bytes were not read"
  fi
}

is_sensitive_parameter() {
  local name=${1,,}
  [[ "$name" =~ (password|passwd|pwd|secret|token|credential|cryptkey|private.?key|signing.?key) ]]
}

profile_value_for_report() {
  local name=$1 value=$2
  if is_sensitive_parameter "$name"; then
    [[ -n "$value" ]] && printf '[REDACTED: non-empty]' || printf '[empty]'
  else
    printf '%s' "$value"
  fi
}

evaluate_profile_parameter() {
  local file=$1 name=$2 value=$3
  local lower=${name,,} compact=${value//[[:space:]]/} normalized=${value^^}
  case "$lower" in
    auth/rfc_authority_check)
      if [[ "$compact" == "0" ]]; then
        add_finding "AUTH-001" "High" "RFC authorization checks are disabled" "$file" \
          "auth/rfc_authority_check=0 disables the S_RFC authorization check for incoming RFC function calls." \
          "Set a supported non-zero value after tracing and correcting S_RFC roles; evaluate value 9 for function-module-level checks and validate every technical destination." \
          "SAP Help: Secure RFCs with Authorizations; SAP Note 931252"
      fi
      ;;
    login/no_automatic_user_sapstar)
      if [[ "$compact" == "0" ]]; then
        add_finding "AUTH-002" "High" "Automatic SAP* fallback user is enabled" "$file" \
          "login/no_automatic_user_sapstar=0 permits the kernel-level SAP* fallback when no SAP* user master record exists in a client." \
          "Set the parameter to 1, retain and lock a protected SAP* user master in every client, change default credentials, and verify the control in each client without deleting the account." \
          "SAP Security Note 68048; ERPScan default-account guidance; SAP Cloud ALM supported checks"
      fi
      ;;
    login/show_detailed_errors)
      if [[ "$normalized" == "TRUE" || "$normalized" == "YES" || "$compact" == "1" ]]; then
        add_finding "AUTH-003" "Medium" "Detailed ABAP logon errors are enabled" "$file" \
          "login/show_detailed_errors=$value can disclose whether a user, client, or password condition caused a failed logon and support account enumeration." \
          "Set the effective value to FALSE after compatibility testing and use protected server-side audit/trace data for diagnosis." \
          "SAP Cloud ALM information-disclosure check; OWASP PySAP DIAG documentation"
      fi
      ;;
    login/password_compliance_to_current_policy)
      if [[ "$compact" == "0" ]]; then
        add_finding "AUTH-004" "Medium" "Existing passwords are not checked against the current policy" "$file" \
          "login/password_compliance_to_current_policy=0 does not force a password change when an interactive user's password no longer satisfies the current rules." \
          "Set the effective profile parameter or security-policy attribute to 1 after reviewing service/system-user exclusions and the operational reset process." \
          "SAP Help: security policy attributes; SAP Cloud ALM supported checks"
      fi
      ;;
    login/password_downwards_compatibility)
      if [[ "$compact" =~ ^[1-5]$ ]]; then
        add_finding "AUTH-005" "Medium" "Backward-compatible password hashes are retained" "$file" \
          "login/password_downwards_compatibility=$compact creates a backward-compatible password hash; values 2 through 5 add progressively weaker compatibility behavior." \
          "Inventory old kernels and CUA dependencies, migrate them, then use value 0 where supported so only modern password hashes are generated." \
          "SAP Help: Parameters for Password Hash; SAP Cloud ALM supported checks"
      fi
      ;;
    login/min_password_lng)
      if [[ "$compact" =~ ^[0-9]+$ ]] && ((10#$compact < 12)); then
        add_finding "AUTH-006" "Medium" "Minimum ABAP password length is below current recommendation" "$file" \
          "login/min_password_lng=$compact is below SAP Cloud ALM's current check value of 12. A client-specific security policy can override this profile value." \
          "Confirm the effective security policy for every user group and raise the minimum to at least 12 where password logon remains enabled." \
          "SAP Cloud ALM supported checks; SAP Help security policy attributes"
      fi
      ;;
    rfc/reject_expired_passwd)
      if [[ "$compact" == "0" ]]; then
        add_finding "AUTH-007" "Medium" "RFC accepts expired passwords" "$file" \
          "rfc/reject_expired_passwd=0 does not enforce rejection of expired passwords for RFC communication." \
          "Set the effective value to 1 after validating technical destinations and migrate non-interactive integrations to appropriate system users and stronger authentication." \
          "SAP Cloud ALM supported checks; HackTricks SAP parameter review"
      fi
      ;;
    icf/reject_expired_passwd)
      if [[ "$compact" == "0" ]]; then
        add_finding "AUTH-008" "Medium" "ICF accepts expired passwords" "$file" \
          "icf/reject_expired_passwd=0 does not enforce rejection of expired passwords for ICF communication." \
          "Set the effective value to 1 after application testing and use appropriate non-dialog identities for integrations." \
          "SAP Cloud ALM supported checks"
      fi
      ;;
    rfc/callback_security_method)
      if [[ "$compact" =~ ^[0-2]$ ]]; then
        add_finding "RFC-001" "High" "RFC callback allow-list enforcement is incomplete" "$file" \
          "rfc/callback_security_method=$compact is below secure value 3; inactive callback allow-lists may not be enforced and value 0 invalidates all lists." \
          "Build and test exact callback allow-lists in audit/simulation mode, remove wildcard function entries, then set value 3 and monitor Security Audit Log rejections." \
          "SAP Help: Logon and Security; Onapsis RFC callback research"
      fi
      ;;
    rfc/allowoldticket4tt)
      if [[ "$normalized" == "YES" || "$normalized" == "TRUE" || "$normalized" == "ON" || "$compact" == "1" ]]; then
        add_finding "RFC-002" "High" "Legacy target-independent trusted RFC tickets are allowed" "$file" \
          "rfc/allowoldticket4tt=$value permits the old trusted/trusting method whose tickets are not bound to a target system." \
          "Set rfc/allowoldticket4tt=no after validating trust relationships and apply the release-specific correction in SAP Note 3157268." \
          "SAP Help ABAP Platform profile changes; SEC Consult RFC research"
      fi
      ;;
    ucon/rfc/active)
      if [[ -n "$compact" && "$compact" != "1" ]]; then
        add_finding "UCON-001" "Medium" "UCON RFC is not active" "$file" \
          "ucon/rfc/active=$value is not the recommended active value 1, so UCON phase/tool enforcement cannot provide its intended RFC function-module allow-list control." \
          "Follow the SAP UCON phase procedure on every application server, derive exact function-module allow-lists without wildcards, monitor rejections, and set the effective value to 1." \
          "SAP Help: UCON CCMS Monitoring; SEC Consult RFC research"
      fi
      ;;
    abap/path_normalization)
      if [[ "$normalized" == "OFF" || "$normalized" == "FALSE" || "$compact" == "0" ]]; then
        add_finding "ABAP-001" "High" "ABAP path normalization is disabled" "$file" \
          "abap/path_normalization=$value disables a cross-platform directory-traversal protection used by ABAP file operations." \
          "Enable the release-supported path normalization mode, test custom OPEN DATASET integrations, and review logical file/path and S_DATASET authorization design." \
          "SAP Cloud ALM directory-traversal check; SecuritySilverbacks filesystem attack paths"
      fi
      ;;
    gw/acl_mode)
      if [[ "$compact" == "0" ]]; then
        add_finding "GW-002" "High" "RFC Gateway restrictive fallback is disabled" "$file" \
          "Profile parameter gw/acl_mode is 0. If secinfo/reginfo are absent or ineffective, external start/registration is unrestricted." \
          "Set gw/acl_mode=1 and maintain restrictive secinfo and reginfo files; stage and monitor rules before enforcement to avoid business disruption." \
          "SAP RFC Gateway security parameters"
      fi
      ;;
    gw/sim_mode)
      if [[ "$compact" == "1" ]]; then
        add_finding "GW-003" "High" "RFC Gateway ACL simulation mode is enabled" "$file" \
          "gw/sim_mode=1 means gateway rules may be logged rather than enforced." \
          "Complete rule tuning, disable simulation mode, reload the ACLs, and monitor rejected registrations/starts." \
          "SAP Gateway security guidance"
      fi
      ;;
    gw/acl_mode_proxy)
      if [[ "$compact" == "0" ]]; then
        add_finding "GW-004" "High" "RFC Gateway proxy restrictive fallback is disabled" "$file" \
          "gw/acl_mode_proxy=0 disables the restrictive proxy security fallback when prxyinfo rules are missing or incomplete." \
          "Set gw/acl_mode_proxy=1 and maintain a least-privilege prxyinfo ACL after testing the impact." \
          "OWASP SSVS PT-I-IP-M01-005; SAP Gateway security settings"
      fi
      ;;
    gw/reg_no_conn_info)
      if [[ "$compact" =~ ^[0-9]+$ ]] && ((10#$compact == 0)); then
        add_finding "GW-005" "High" "RFC Gateway additional security features are disabled" "$file" \
          "gw/reg_no_conn_info=0 disables every security feature controlled by the bitmask." \
          "Review the kernel-specific valid bitmask and related SAP Notes; enable the protections applicable to the installed kernel without treating an arbitrary odd value as universally correct." \
          "SAP RFC Gateway security settings; OWASP SSVS PT-I-IP-M01-005"
      fi
      ;;
    gw/monitor)
      if [[ "$compact" =~ ^[0-9]+$ ]] && ((10#$compact > 1)); then
        add_finding "GW-006" "High" "RFC Gateway monitor permits remote access" "$file" \
          "gw/monitor=$compact can permit the gateway monitor beyond local access." \
          "Set gw/monitor=1 for local-only monitoring, then validate operational monitoring paths." \
          "OWASP SSVS PT-I-IP-M01-005; CBAS Attack Surface Discovery"
      fi
      ;;
    gw/rem_start)
      if [[ -n "$compact" && "$normalized" != "DISABLED" && "$normalized" != "DISABLE" && "$normalized" != "SSH_SHELL" ]]; then
        add_finding "GW-007" "High" "RFC Gateway remote program start is enabled" "$file" \
          "gw/rem_start is neither DISABLED nor SSH_SHELL. External-program start can become operating-system command execution when authorization and secinfo controls fail." \
          "Set gw/rem_start=DISABLED where possible. If a documented dependency remains, use the SAP-supported SSH_SHELL path and restrictive secinfo rules." \
          "OWASP Pentest Playbook: OS command execution; SSVS PT-I-IP-M01-005"
      fi
      ;;
    snc/permit_insecure_comm|snc/permit_insecure_start)
      if [[ "$compact" == "1" ]]; then
        add_finding "SNC-001" "Medium" "SNC configuration permits insecure communication" "$file" \
          "$name is enabled, allowing a fallback path without SNC protection." \
          "Confirm compatibility requirements, then disallow insecure communication/start paths and require SNC for sensitive RFC/DIAG traffic." \
          "OWASP SAP Pentest Playbook and SAP SNC parameters"
      fi
      ;;
    snc/accept_insecure_gui|snc/accept_insecure_rfc|snc/accept_insecure_cpic|snc/accept_insecure_r3int_rfc)
      if [[ "$compact" == "1" ]]; then
        add_finding "SNC-002" "Medium" "SNC accepts an insecure connection class" "$file" \
          "$name=1 permits this connection class without SNC protection." \
          "Confirm migration dependencies, then require SNC for sensitive channels and validate every destination before removing compatibility fallback." \
          "SAP SNC security parameters; OWASP sncscan research"
      fi
      ;;
    snc/data_protection/min|snc/data_protection/use|snc/data_protection/max)
      if [[ "$compact" =~ ^[0-9]+$ ]] && ((10#$compact < 3)); then
        add_finding "SNC-003" "Medium" "SNC quality of protection is below privacy" "$file" \
          "$name=$compact permits authentication-only or integrity-only protection rather than data privacy." \
          "For traffic that carries sensitive data, set and test the SNC protection chain so minimum, default, and maximum values negotiate privacy (3) consistently." \
          "SAP SNC QoP documentation; OWASP sncscan"
      fi
      ;;
    snc/only_encrypted_gui)
      if [[ "$compact" == "0" ]]; then
        add_finding "SNC-004" "Medium" "Encrypted SAP GUI connections are not enforced" "$file" \
          "snc/only_encrypted_gui=0 allows SAP GUI connections that do not use SNC." \
          "After confirming every client has working SNC, set snc/only_encrypted_gui=1 and monitor rejected logons." \
          "OWASP sncscan; SAP SNC configuration"
      fi
      ;;
    snc/enable)
      if [[ "$compact" == "0" ]]; then
        add_finding "SNC-005" "Medium" "Secure Network Communications is disabled" "$file" \
          "snc/enable=0 means the application server does not initialize SNC. Network isolation alone does not provide DIAG/RFC confidentiality or peer authentication." \
          "Plan SNC with the SAP Cryptographic Library or supported security product, provision the PSE/identity first, set snc/enable=1, and validate protection for each client and destination." \
          "SAP Help: snc/enable; OWASP PySAP SNC documentation"
      fi
      ;;
    ms/monitor|ms/admin_port)
      if [[ "$compact" =~ ^[1-9][0-9]*$ ]]; then
        add_finding "MS-002" "Medium" "SAP Message Server administration/monitor function is enabled" "$file" \
          "$name has a non-zero value. Reachability and ACLs determine exploitability." \
          "Disable the function if unused; otherwise restrict binding/firewalls and maintain the relevant message-server ACL file." \
          "SAP Message Server security settings"
      fi
      ;;
    system/secure_communication)
      if [[ -n "$compact" && "$normalized" != "ON" ]]; then
        add_finding "MS-004" "Medium" "SAP internal server communication is not secured" "$file" \
          "system/secure_communication=$value is not ON, so supported secure communication between application servers and the Message Server is not enabled." \
          "Follow the release-specific SAP Notes, set the effective value to ON where the kernel supports it, and retain restrictive Message Server ACL and network controls." \
          "SAP EarlyWatch Alert security guidance; SAP Note 2040644"
      fi
      ;;
    ms/acl_info|gw/sec_info|gw/reg_info|gw/prxy_info)
      if [[ -n "$value" && "$value" == /* ]]; then
        local configured_acl
        configured_acl=$(physical_path "$value")
        if [[ -e "$configured_acl" ]]; then
          record_path "$configured_acl" "ACL" "Referenced by $name"
        else
          add_finding "ACL-003" "High" "Configured SAP ACL file is missing" "$file" \
            "$name references $value, but that file was not present in the audited root." \
            "Confirm profile substitution and instance context, then restore a protected least-privilege ACL at the configured path before relying on the control." \
            "SAP Gateway/Message Server ACL guidance"
        fi
      fi
      ;;
    service/protectedwebmethods)
      if [[ "${normalized%% *}" == "NONE" || "${normalized%% *}" == "DEFAULT" || -z "$compact" ]]; then
        add_finding "START-001" "High" "SAP Start Service web methods are not strongly protected" "$file" \
          "service/protectedwebmethods is ${value:-empty}; NONE leaves all methods public and DEFAULT exposes more read/trace methods than SDEFAULT." \
          "Use SDEFAULT or ALL with a narrowly justified exception list, and restrict the HTTP/HTTPS endpoints with the supported ACL parameters." \
          "SAP Start Service security guidance; OWASP SSVS PT-P-DS-M01-002/PT-P-DS-M01-003"
      fi
      ;;
    rdisp/call_system)
      if [[ "$compact" == "1" ]]; then
        add_finding "OSCMD-001" "High" "ABAP CALL SYSTEM is enabled" "$file" \
          "rdisp/call_system=1 enables a legacy path that executes operating-system commands in the SAP service-user context." \
          "Set rdisp/call_system=0 after dependency testing; use controlled SXPG commands with least-privilege authorization for required integrations." \
          "OWASP Pentest Playbook: OS command execution; SAP KBA 2879860"
      fi
      ;;
    rec/client)
      if [[ "${normalized,,}" == "off" || "$compact" == "0" || -z "$compact" ]]; then
        add_finding "LOG-001" "Medium" "ABAP table-change logging is disabled" "$file" \
          "rec/client is ${value:-empty}, so changes to log-enabled tables may not be captured." \
          "Define the required clients (or ALL where policy requires), confirm critical tables have logging enabled, protect the logs, and monitor retention." \
          "OWASP SSVS DT-P-AE-M01-004"
      fi
      ;;
    rsau/enable)
      if [[ "$compact" == "0" ]]; then
        add_finding "LOG-002" "Medium" "Static Security Audit Log profile is disabled" "$file" \
          "rsau/enable=0 disables the static profile switch for the ABAP Security Audit Log. A dynamic configuration can differ, so this is evidence of a profile gap rather than proof that no audit events are recorded." \
          "Review the effective configuration and filters in SM19/RSAU_CONFIG on every application server, enable the Security Audit Log where required, and validate protected retention and central monitoring in SM20." \
          "SAP Security Audit Log documentation; SAP Cloud ALM supported checks"
      fi
      ;;
    is/http/show_detailed_errors)
      if [[ "$normalized" == "TRUE" || "$compact" == "1" ]]; then
        add_finding "ICM-001" "Medium" "ICM/Web Dispatcher returns detailed errors" "$file" \
          "is/HTTP/show_detailed_errors=$value can disclose host, module, component, and error details to clients." \
          "Set the parameter to FALSE for exposed services and use protected local traces for diagnostics." \
          "SAP ICM security guidance; OWASP SSVS information-disclosure controls"
      fi
      ;;
    is/http/show_server_header)
      if [[ "$normalized" == "TRUE" || "$compact" == "1" ]]; then
        add_finding "ICM-002" "Low" "ICM/Web Dispatcher server header is enabled" "$file" \
          "is/HTTP/show_server_header=$value exposes service identity/version clues." \
          "Set the parameter to FALSE unless a documented dependency requires it." \
          "SAP ICM/Web Dispatcher hardening guidance"
      fi
      ;;
    icm/http/allow_invalid_host_header)
      if [[ "$normalized" == "TRUE" || "$normalized" == "YES" || "$compact" == "1" ]]; then
        add_finding "ICM-004" "Medium" "ICM accepts invalid HTTP Host headers" "$file" \
          "icm/HTTP/allow_invalid_host_header=$value accepts invalid or duplicate Host headers contrary to the protocol and weakens request-routing validation." \
          "Restore the SAP default FALSE, validate reverse-proxy routing, and separately test Web Dispatcher/ICM request handling from authorized zones." \
          "SAP Help: icm/HTTP/allow_invalid_host_header; Attack Surface Discovery parameter inventory"
      fi
      ;;
    icf/set_httponly_flag_on_cookies)
      if [[ "$compact" =~ ^[1-3]$ ]]; then
        add_finding "ICM-005" "Medium" "HttpOnly is disabled for one or more ICF cookie classes" "$file" \
          "icf/set_HTTPonly_flag_on_cookies=$compact disables HttpOnly for some or all ICF cookies, allowing client-side code to access affected cookies." \
          "After application compatibility testing, use value 0 and activate HTTP security session management in SICF_SESSIONS." \
          "SAP Help: Session Security Protection"
      fi
      ;;
    login/ticket_only_by_https)
      if [[ "$compact" == "0" ]]; then
        add_finding "ICM-006" "High" "ABAP logon tickets are not restricted to HTTPS" "$file" \
          "login/ticket_only_by_https=0 allows the browser to send logon-ticket and security-session cookies over unencrypted HTTP." \
          "Enforce HTTPS for the complete authentication path, set the effective value to 1, and confirm secure cookie/session behavior through the supported ICF configuration." \
          "SAP Help: Session Security Protection"
      fi
      ;;
    icm/http/file_access_*|icm/http/file_access-[0-9]*)
      if [[ "${value,,}" == *"docroot=/"* || "${value,,}" == *"docroot=\\"* || "${value,,}" == *"docroot=.."* ]]; then
        add_finding "ICM-003" "Critical" "ICM file alias may expose a broad filesystem path" "$file" \
          "$name maps a DOCROOT to a root or parent-relative location; the report does not copy the full value." \
          "Remove broad aliases, constrain DOCROOT to a dedicated non-sensitive directory, and require an appropriate icm/HTTP/auth rule." \
          "OWASP Pentest Playbook: filesystem read"
      fi
      ;;
    execute_[0-9]*)
      if [[ -n "$compact" ]]; then
        add_finding "OSCMD-002" "High" "Instance profile executes an operating-system command" "$file" \
          "$name is configured and runs in the SAP service-user context at instance startup." \
          "Verify the command, owner, target, quoting, and business need; replace it with a controlled service unit where possible and remove any user-controlled input." \
          "OWASP Pentest Playbook: OS command execution"
      fi
      ;;
    igs/listener/http)
      if [[ "${value,,}" == *administration* ]]; then
        add_finding "IGS-001" "High" "IGS HTTP administration commands appear enabled" "$file" \
          "igs/listener/http includes the administration option; older IGS HTTP administration commands may lack authentication." \
          "Remove the administration option unless explicitly required, restrict the listener, and verify the IGS patch level and SAP Notes." \
          "OWASP SAP Pentest Playbook: IGS"
      fi
      ;;
    rsec/ssfs_datapath|rsec/ssfs_keypath|rsec/ssfs_lkypath)
      if [[ "$value" == /* ]]; then CONFIGURED_SSFS_PATHS+=("$value"); fi
      ;;
  esac

  if is_sensitive_parameter "$name" && [[ -n "$compact" && "$compact" != *'$('* && "$compact" != *'${'* && "$compact" != "********" ]]; then
    add_finding "CFG-001" "High" "Profile contains a non-empty secret-like parameter" "$file" \
      "Parameter $name has a literal-looking value. SAPstract deliberately did not record the value." \
      "Move secrets to the SAP-supported secure store or protected credential mechanism, rotate the value if exposure is possible, and remove it from profiles/backups." \
      "OWASP CBAS: filesystem read and credential exposure"
  fi
}

scan_acl_file() {
  local file=$1 logical category=$2
  logical=$(logical_path "$file")
  record_path "$file" "ACL" "$category"
  local compact
  if grep -Eiq '(^|[[:space:],])(P|KT)[[:space:]]+.*(TP|USER|HOST|SNC|SOURCE|DEST|S)=\*' "$file" 2>/dev/null ||
     grep -Eiq '^[[:space:]]*[Pp][[:space:]]+\*[[:space:]]+\*[[:space:]]+\*' "$file" 2>/dev/null ||
     { [[ "${file##*/}" == "saprouttab" ]] &&
       grep -Eiq '^[[:space:]]*[PpSs][[:space:]]+[^#;[:space:]]+[[:space:]]+\*([[:space:]]|$)' "$file" 2>/dev/null; }; then
    add_finding "ACL-001" "High" "SAP access-control file contains a broad wildcard rule" "$logical" \
      "A permissive wildcard pattern was detected in $category, including positional SAProuter target-host wildcards; rule contents were not copied into the report." \
      "Review rules in order, replace broad permits with explicit program/user/host or route entries, test in logging/simulation mode where supported, and reload safely." \
      "SAP RFC Gateway guidance; SAP Note 1895350; SEC Consult CVE-2022-27668"
  fi
  compact=$(sed -e 's/[#;].*$//' -e '/^[[:space:]]*$/d' "$file" 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$compact" == "0" ]]; then
    add_finding "ACL-002" "Medium" "SAP access-control file is empty" "$logical" \
      "$category exists but contains no active rules." \
      "Confirm the component's empty-file semantics and populate a deny-by-default, least-privilege policy before relying on this file." \
      "SAP component ACL documentation"
  fi
}

scan_profiles_and_acls() {
  log "Inspecting SAP profiles and security configuration"
  local roots=() logical physical file count=0
  for logical in /usr/sap /sapmnt /opt/sap /var/lib/sap; do
    physical=$(physical_path "$logical")
    [[ -d "$physical" ]] && roots+=("$physical")
  done
  local root base line name value shown
  for root in "${roots[@]}"; do
    while IFS= read -r -d '' file; do
      count=$((count + 1))
      if ((count > MAX_FILES)); then TRUNCATED_SCANS=$((TRUNCATED_SCANS + 1)); break 2; fi
      base=${file##*/}; logical=$(logical_path "$file")
      case "${base,,}" in
        secinfo|reginfo|saprouttab|icmauth.txt|icm_filter_rules.txt)
          scan_acl_file "$file" "$base"
          ;;
        *)
          record_path "$file" "Profile" "SAP profile/configuration"
          while IFS= read -r line || [[ -n "$line" ]]; do
            line=$(trim "$line")
            [[ -n "$line" && "$line" != \#* && "$line" != \;* && "$line" == *"="* ]] || continue
            name=$(trim "${line%%=*}")
            value=$(trim "${line#*=}")
            [[ -n "$name" ]] || continue
            shown=$(profile_value_for_report "$name" "$value")
            append_row "$PROFILES" "$logical" "$name" "$shown" "filesystem"
            evaluate_profile_parameter "$logical" "$name" "$value"
          done < "$file"
          ;;
      esac
    done < <(find "$root" -xdev -maxdepth 10 -type f \
      \( -path '*/SYS/profile/*' -o -path '*/profile/*' -o -name 'DEFAULT.PFL' -o -name 'START_*' \
         -o -name 'secinfo' -o -name 'reginfo' -o -name 'saprouttab' -o -name 'icmauth.txt' \
         -o -name 'host_profile' -o -name 'sapprofile.ini' -o -name 'global.ini' -o -name 'nameserver.ini' \
         -o -name 'indexserver.ini' -o -name 'xsengine.ini' -o -name 'daemon.ini' -o -name 'instance.properties' \
         -o -name 'local.properties' -o -name 'config_master' \) -print0 2>/dev/null)
  done
  if ((count > MAX_FILES)); then
    add_coverage "Profiles and ACLs" "partial" "Stopped at --max-files=$MAX_FILES"
  else
    add_coverage "Profiles and ACLs" "complete" "Known profile and ACL names under SAP roots inspected; secret-like values redacted"
  fi
}

tool_component() {
  case "${1,,}" in
    rsecssfx*) printf "SSFS administration" ;;
    sapcontrol*) printf "SAP Start Service client" ;;
    saphostctrl*|saphostexec*) printf "SAP Host Agent" ;;
    saprouter*) printf "SAProuter" ;;
    sapwebdisp*) printf "SAP Web Dispatcher" ;;
    sapgenpse*) printf "SAP cryptographic/PSE administration" ;;
    sapcar*) printf "SAP archive utility" ;;
    niping*) printf "SAP NI diagnostic" ;;
    startrfc*|rfcexec*) printf "SAP RFC utility" ;;
    hdbsql*) printf "SAP HANA SQL client" ;;
    hdbuserstore*) printf "SAP HANA secure user store" ;;
    hdblcm*) printf "SAP HANA lifecycle manager" ;;
    dataserver*|backupserver*|bcksrvr*) printf "SAP ASE database service" ;;
    disp+work*|dw.sap*) printf "SAP kernel dispatcher" ;;
    gwrd*) printf "SAP RFC Gateway" ;;
    ms.sap*) printf "SAP Message Server" ;;
    icmon*) printf "SAP ICM monitor" ;;
    msmon*) printf "SAP Message Server monitor" ;;
    r3trans*) printf "SAP transport/database utility" ;;
    tp*) printf "SAP transport control" ;;
    *) printf "SAP utility" ;;
  esac
}

record_tool() {
  local physical=$1 source=$2
  [[ -f "$physical" || -x "$physical" ]] || return 0
  local canonical logical name component digest=""
  canonical=$(readlink -f "$physical" 2>/dev/null || printf '%s' "$physical")
  logical=$(logical_path "$canonical")
  [[ -z "${SEEN_TOOL[$logical]+x}" ]] || return 0
  SEEN_TOOL[$logical]=1
  stat_fields "$canonical" || return 0
  name=${canonical##*/}; component=$(tool_component "$name")
  if command -v sha256sum >/dev/null 2>&1 && [[ "$STAT_SIZE" =~ ^[0-9]+$ ]] && ((STAT_SIZE <= 104857600)); then
    digest=$(sha256sum -- "$canonical" 2>/dev/null | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1 && [[ "$STAT_SIZE" =~ ^[0-9]+$ ]] && ((STAT_SIZE <= 104857600)); then
    digest=$(shasum -a 256 -- "$canonical" 2>/dev/null | awk '{print $1}')
  fi
  append_row "$TOOLS" "$name" "$component" "$logical" "$source" "$STAT_OWNER" "$STAT_GROUP" "$STAT_MODE" "$STAT_SIZE" "$digest"
  record_path "$canonical" "Executable" "$component"
  SAP_EVIDENCE_COUNT=$((SAP_EVIDENCE_COUNT + 1))

  local dir=${canonical%/*}
  if stat_fields "$dir"; then
    permission_bits "$STAT_MODE"
    if has_bit "$PERM_OTHER" 2 || has_bit "$PERM_GROUP" 2; then
      add_finding "TOOL-001" "High" "SAP tool resides in a writable directory" "$logical" \
        "Parent directory $(logical_path "$dir") has mode $STAT_MODE, enabling a local path-replacement risk for one or more users." \
        "Restrict directory write access to trusted software owners, verify the tool digest against approved media, and inspect service/PATH search order." \
        "OWASP CBAS: OS command execution and code integrity"
    fi
  fi
}

scan_tools() {
  log "Inventorying SAP administration and runtime tools"
  local names=(rsecssfx sapcontrol saphostctrl saphostexec saprouter sapwebdisp sapgenpse SAPCAR sapcar niping startrfc rfcexec hdbsql hdbuserstore hdblcm dataserver backupserver bcksrvr disp+work gwrd ms.sap icmon msmon R3trans tp sapstartsrv)
  local name resolved roots=() logical physical candidate count=0
  for name in "${names[@]}"; do
    resolved=$(command -v "$name" 2>/dev/null || true)
    [[ -n "$resolved" ]] && record_tool "$resolved" "PATH"
  done
  for logical in /usr/sap /sapmnt /hana/shared /opt/sap; do
    physical=$(physical_path "$logical")
    [[ -d "$physical" ]] && roots+=("$physical")
  done
  local root
  for root in "${roots[@]}"; do
    while IFS= read -r -d '' candidate; do
      record_tool "$candidate" "SAP filesystem"
      count=$((count + 1))
      if ((count >= MAX_FILES)); then TRUNCATED_SCANS=$((TRUNCATED_SCANS + 1)); break 2; fi
    done < <(find "$root" -xdev -maxdepth 12 -type f \
      \( -iname 'rsecssfx*' -o -iname 'sapcontrol*' -o -iname 'saphostctrl*' -o -iname 'saphostexec*' \
         -o -iname 'saprouter*' -o -iname 'sapwebdisp*' -o -iname 'sapgenpse*' -o -iname 'sapcar*' \
         -o -iname 'niping*' -o -iname 'startrfc*' -o -iname 'rfcexec*' -o -iname 'hdbsql*' \
         -o -iname 'hdbuserstore*' -o -iname 'hdblcm*' -o -iname 'dataserver*' -o -iname 'backupserver*' \
         -o -iname 'bcksrvr*' -o -name 'disp+work' -o -name 'gwrd' \
         -o -name 'ms.sap*' -o -iname 'icmon*' -o -iname 'msmon*' -o -iname 'r3trans*' \
         -o -name 'tp' -o -iname 'sapstartsrv*' \) -print0 2>/dev/null)
  done
  if ((count >= MAX_FILES)); then
    add_coverage "Tools" "partial" "Stopped at --max-files=$MAX_FILES"
  else
    add_coverage "Tools" "complete" "PATH and standard SAP roots inspected; binaries were not executed"
  fi
}

build_assessment_catalog() {
  add_assessment "Host footprint and permissions" "automated" "Processes, services, sockets, paths, owners, modes/ACLs, profiles, tools, and hashes" "Review every finding and repeat with elevation if collection coverage is partial." "OWASP SSVS OS controls; PySAP recognition"
  add_assessment "RFC Gateway and Message Server" "automated + manual" "Local ports, gateway/message profiles, secinfo/reginfo/prxyinfo/message ACL metadata" "Use an authorized segmented-zone test to prove external reachability and effective ACL behavior." "OWASP SSVS; Attack Surface Discovery; Pentest Playbook"
  add_assessment "Dispatcher, DIAG, SNC, SAProuter" "automated + manual" "Port/profile/SNC/saprouttab evidence" "Use authorized sncscan/SAP tooling to prove negotiated QoP and external route exposure." "OWASP sncscan; HoneySAP; Pentest Playbook"
  add_assessment "ICM, IGS, Start Service, Web Dispatcher" "automated + manual" "Listener, error/header, file alias, IGS admin, protected-webmethod, ACL, and local port evidence" "Perform approved HTTP/TLS and authentication validation from every relevant trust zone." "Attack Surface Discovery; Pentest Playbook; OWASP SSVS"
  add_assessment "SAP Cloud Connector and BTP" "footprint + manual" "SCC service/process/config/SSFS/keystore paths and local listener evidence" "Review SCC patch/JDK, HA, trust, admin roles, alerts, destinations, identity providers, and BTP controls in the authenticated consoles." "OWASP SSVS BTP controls; CBAS exposure research"
  add_assessment "SAP HANA and ASE" "footprint + manual" "Processes, ports, paths, INI/SSFS/secure user-store metadata, and local permissions" "Authenticate with read-only audit roles to review users, roles, password policy, audit policy, tenants, TLS, replication, and patch level." "OWASP SSVS HANA controls; Attack Surface Discovery"
  add_assessment "ABAP identity and authorization" "manual/authenticated" "Not derivable reliably from host files" "Review standard users, SAP_ALL, S_RFC/S_RFCACL, critical transactions/tables, password/hash policy, RFC destinations, and system trust." "OWASP SAPKiln; SSVS; Pentest Playbook"
  add_assessment "ABAP code and business data" "manual/authenticated" "Host artifacts cannot prove authorization checks, injection resistance, path traversal, or data classification" "Run SCI/ATC/CVA and controlled reviews for filesystem, database, dynamic code, OS commands, RFC modules, and sensitive data access." "OWASP SSVS IY controls; Pentest Playbook"
  add_assessment "Logging and detection" "partial + manual" "Local audit/system/trace file presence, metadata, and selected logging profiles" "Validate SAL, SM21, table logging, RAL, workload/user reports, HANA/Java/BTP audit, central forwarding, alerts, integrity, and retention." "OWASP SSVS DT controls"
  add_assessment "Transports and software supply chain" "automated + manual" "Transport/archive/tool paths, permissions, and tool hashes" "Review transport creation/import authorization, approvals, signatures, import routes, client libraries, and patch/Security Note posture." "Pentest Playbook; OWASP SSVS"
  add_assessment "SSFS, PSE, credentials, and key lifecycle" "metadata + manual" "All known SSFS families, PSE/credential/keystore artifacts, pair/header/type and permission metadata" "Validate with official product tools; review generation, rotation, backup, recovery, separation, certificate expiry, and supported SCC key mode." "SAP SSFS/HANA guidance; OWASP SSVS crypto controls; PySAP formats"
  add_assessment "SAP GUI clients and input history" "automated footprint + manual" "Known local history paths and metadata; no history content read" "Patch SAP GUI, apply SAP Notes for CVE-2025-0055/0056, disable or minimize history, and exclude sensitive fields." "OWASP CBAS SAP GUI history research"
  add_assessment "External attack surface" "not performed" "A host-local listener is not proof of Internet or cross-zone reachability" "Perform a separately authorized external inventory for SAProuter, Dispatcher, Gateway, Message Server, SCC, Java, HANA, ASE, ICM/IGS, Start Service, and Web Dispatcher." "CBAS Internet Scan 2025/2026; Attack Surface Discovery"
  add_assessment "Resilience and recovery" "manual" "Local footprints may show enqueue replication components but cannot prove failover, backups, or recovery objectives" "Validate ABAP/Java enqueue replication, SCC HA, HANA replication, backup protection, restore tests, and incident procedures." "OWASP SSVS availability controls; Security Matrix"
  add_assessment "Governance and response" "manual" "Policies, ownership, risk acceptance, detection workflows, and recovery exercises are organizational evidence" "Assess all Integration, Platform, Access, and Customization areas across Identify, Protect, Detect, Respond, and Recover." "CBAS Security Matrix"
  add_assessment "RFC callbacks, UCON, and trusted relationships" "profile evidence + authenticated" "Observed callback, UCON, authorization-check, legacy-ticket, and SNC parameters" "Review SM59 callback allow-lists, S_RFC/S_RFCACL, UCON phase/function allow-lists, trusted-system relationships, technical users, and Security Audit Log events. Remove wildcard functions." "SAP RFC documentation; Onapsis callback research; SEC Consult RFC research"
  add_assessment "Standard users and password policy" "profile evidence + authenticated" "Observed SAP* fallback and password-policy parameters; no password values or login attempts" "For every client, review SAP*, DDIC, SAPCPIC, TMSADM, EARLYWATCH and solution-specific users; lock/retain required accounts, change defaults, remove excess profiles, and confirm effective security policies." "ERPScan default-account guide; HackTricks references; SAP Cloud ALM"
  add_assessment "SAP HTTP endpoints and information disclosure" "not actively tested" "ICM/Java/IGS/Start Service/Web Dispatcher process, listener, artifact, and profile evidence" "From each approved trust zone, validate /sap/public/info, WebGUI, Fiori, NWA, IGS status/admin, Dispatcher login info, SOAP/WebSocket RFC, Start Service methods, headers, TLS, and authentication without brute force." "SecuritySilverbacks Attack Surface Discovery templates"
  add_assessment "SAP Security Notes and protocol CVEs" "manual/authenticated" "Host-local filenames and banners are not treated as patch proof" "Use SAP for Me/System Recommendations and component inventory to verify applicable Notes, including 3158375, 3007182, 3044754, 3032624, 3089413 and current corrections for CVE-2018-2392, CVE-2021-40495, CVE-2022-27668, and CVE-2025-31324." "SecuritySilverbacks templates; SEC Consult; SAP Security Notes"
  add_assessment "Java secure store, descriptors, and Download Manager" "metadata + manual" "SecStore.properties/SecStore.key, dlmanager.conf, PSE/keystore, archive, and Java host artifact metadata when present" "Verify strict pair permissions, supported credential protection and fixed Download Manager release; review web.xml, webdynpro.xml and portalapp.xml authorization, upload, XXE/SSRF, invoker, and logging controls." "Breaking SAP Portal; Hardcore SAP Pentesting; OWASP PySAP Download Manager"
  add_assessment "SAProuter routing and administration" "automated + active/manual" "Process flags, 3299 listener, saprouttab metadata/wildcards, and local tool version/hash" "Remove -X and target wildcards, restrict 3299 to required peers, require SNC where appropriate, inspect dev_rout, verify Note 3158375/current kernel, and perform an authorized route/admin test." "Rapid7 Piercing SAProuter; SEC Consult CVE-2022-27668"
  add_assessment "Enqueue and cluster coordination" "automated + manual" "Enqueue/replication process and listener evidence" "Restrict Enqueue and replication listeners to explicit cluster peers, validate monitor authorization and current patches, and test failover without exposing administrative operations." "OWASP PySAP Enqueue; SAP availability guidance"
  add_coverage "OWASP CBAS and SAP reference corpus" "cataloged" "Root page; 9 linked projects/resources; 74 playbook pages; 35 active Attack Surface checks plus 11 workflows; PySAP docs/notebooks/examples; every HackTricks SAP/SAProuter reference; SSVS, SAPKiln, HoneySAP, sncscan, Security Matrix, and research papers mapped in docs"
}

topology_slug() {
  local value=${1,,}
  value=${value//[^a-z0-9]/-}
  while [[ "$value" == *--* ]]; do value=${value//--/-}; done
  value=${value#-}; value=${value%-}
  printf '%s' "${value:-item}"
}

service_category_for() {
  local text=${1,,}
  case "$text" in
    *hana*|*database*|*oracle*|*db2*|*maxdb*|*sql\ server*|*ase*) printf 'Database services' ;;
    *cloud\ connector*|*saprouter*|*web\ dispatcher*) printf 'Boundary & cloud connectors' ;;
    *start\ service*|*host\ agent*|*sapinst*|*administration*|*sdm*|*update*|*upgrade*) printf 'Management services' ;;
    *rfc*|*gateway*|*p4*|*iiop*|*jms*) printf 'Integration services' ;;
    *http*|*https*|*icm*|*webgui*|*igs*) printf 'Web & UI services' ;;
    *java*) printf 'Java application services' ;;
    *dispatcher*|*message\ server*|*abap*|*sap\ dev\ instance*) printf 'ABAP core services' ;;
    *internal*|*enqueue*) printf 'Internal cluster services' ;;
    *) printf 'Other SAP services' ;;
  esac
}

database_engine_for_port() {
  local port=${1-}
  DB_ENGINE=""
  case "$port" in
    3[0-9][0-9]13|3[0-9][0-9]15|3[0-9][0-9]17|3[0-9][0-9][4-9][0-9]) DB_ENGINE="SAP HANA" ;;
    1521|1522|2484) DB_ENGINE="Oracle Database" ;;
    1433|1434) DB_ENGINE="Microsoft SQL Server" ;;
    446) DB_ENGINE="IBM Db2" ;;
    7200|7210) DB_ENGINE="SAP MaxDB" ;;
    49[0-9][0-9]|5000) DB_ENGINE="SAP ASE" ;;
    2638) DB_ENGINE="SAP IQ" ;;
  esac
  [[ -n "$DB_ENGINE" ]]
}

database_engine_for_text() {
  local text=${1,,}
  case "$text" in
    *hana*|*hdbdaemon*|*hdbnameserver*|*hdbindexserver*|*hdbsql*) printf 'SAP HANA' ;;
    *sybase*|*sap\ ase*|*dataserver*|*backupserver*|*bcksrvr*) printf 'SAP ASE' ;;
    *oracle*|*ora_pmon*|*tnslsnr*) printf 'Oracle Database' ;;
    *db2sysc*|*db2wdog*|*ibm\ db2*|*/db2/*) printf 'IBM Db2' ;;
    *sqlservr*|*mssql*|*microsoft\ sql*) printf 'Microsoft SQL Server' ;;
    *maxdb*|*sapdb*|*dbmsrv*|*x_server*) printf 'SAP MaxDB' ;;
    *sap\ iq*|*iqsrv*) printf 'SAP IQ' ;;
  esac
}

add_service_map_entry() {
  local category=$1 component=$2 status=$3 endpoint=$4 scope=$5 transport=$6 process=$7 source=$8
  local key="$category|$component|$status|$endpoint|$process|$source"
  [[ -z "${SEEN_SERVICE_MAP[$key]+x}" ]] || return 0
  SEEN_SERVICE_MAP[$key]=1
  append_row "$SERVICE_MAP" "$category" "$component" "$status" "$endpoint" "$scope" "$transport" "$process" "$source"
}

add_topology_node() {
  local id=$1 label=$2 kind=$3 scope=$4 status=$5 detail=$6
  [[ -z "${SEEN_TOPOLOGY_NODE[$id]+x}" ]] || return 0
  SEEN_TOPOLOGY_NODE[$id]=1
  append_row "$TOPOLOGY_NODES" "$id" "$label" "$kind" "$scope" "$status" "$detail"
}

add_topology_edge() {
  local source=$1 target=$2 relation=$3 state=$4 confidence=$5 evidence=$6
  local key="$source|$target|$relation|$evidence"
  [[ -z "${SEEN_TOPOLOGY_EDGE[$key]+x}" ]] || return 0
  SEEN_TOPOLOGY_EDGE[$key]=1
  append_row "$TOPOLOGY_EDGES" "$source" "$target" "$relation" "$state" "$confidence" "$evidence"
}

add_database_evidence() {
  local engine=$1 placement=$2 endpoint=$3 state=$4 confidence=$5 evidence=$6
  local key="$engine|$placement|$endpoint|$state|$evidence"
  [[ -z "${SEEN_DATABASE[$key]+x}" ]] || return 0
  SEEN_DATABASE[$key]=1
  append_row "$DATABASES" "$engine" "$placement" "$endpoint" "$state" "$confidence" "$evidence"
  local node_id relation
  case "$placement" in
    remote) node_id="db-remote-$(topology_slug "$endpoint")"; relation="observed database connection" ;;
    local) node_id="db-local-$(topology_slug "$engine")"; relation="local database evidence" ;;
    configured) node_id="db-configured-$(topology_slug "$engine-$endpoint")"; relation="configured database target" ;;
    *) node_id="db-undetermined"; relation="database placement undetermined" ;;
  esac
  add_topology_node "$node_id" "$engine" "database" "$placement" "$state" "$endpoint — $evidence"
  add_topology_edge "host" "$node_id" "$relation" "$state" "$confidence" "$evidence"
}

add_capability() {
  local key=$1 category=$2 title=$3 status=$4 confidence=$5 evidence=$6 validation=$7
  [[ -z "${SEEN_CAPABILITY[$key]+x}" ]] || return 0
  SEEN_CAPABILITY[$key]=1
  append_row "$CAPABILITIES" "$key" "$category" "$title" "$status" "$confidence" "$evidence" "$validation"
}

build_topology_model() {
  log "Building evidence-backed SAP service topology"
  : > "$SERVICE_MAP"; : > "$CAPABILITIES"; : > "$DATABASES"
  : > "$TOPOLOGY_NODES"; : > "$TOPOLOGY_EDGES"
  SEEN_SERVICE_MAP=(); SEEN_DATABASE=(); SEEN_TOPOLOGY_NODE=(); SEEN_TOPOLOGY_EDGE=(); SEEN_CAPABILITY=()
  add_topology_node "host" "$HOST_NAME" "sap-host" "local" "observed" "Audited host; relationships are derived only from local evidence."

  local classification transport protocol state local_ep remote_ep exposure pid process service
  local local_addr local_port remote_addr remote_port category component status endpoint engine placement
  local remote_id evidence socket_confidence
  declare -A local_addresses=()
  while IFS=$'\t' read -r classification transport protocol state local_ep remote_ep exposure pid process service || [[ -n "$classification" ]]; do
    [[ -n "$classification" ]] || continue
    endpoint_parts "$local_ep"; local_addr=$EP_ADDR
    if [[ -n "$local_addr" ]] && ! is_wildcard "$local_addr"; then local_addresses["${local_addr,,}"]=1; fi
  done < "$SOCKETS"

  while IFS=$'\t' read -r classification transport protocol state local_ep remote_ep exposure pid process service || [[ -n "$classification" ]]; do
    [[ -n "$classification" ]] || continue
    category=$(service_category_for "$classification $transport $process $service")
    component=$classification
    status=${state:-observed}
    endpoint=$local_ep
    [[ "$exposure" == "connected" && -n "$remote_ep" ]] && endpoint="$local_ep → $remote_ep"
    add_service_map_entry "$category" "$component" "$status" "$endpoint" "$exposure" "$transport" "${process:-$service}" "socket"
    socket_confidence="medium"
    if is_collected_sap_pid "$pid" || is_sap_process "$process $service"; then socket_confidence="high"; fi

    endpoint_parts "$local_ep"; local_addr=$EP_ADDR; local_port=$EP_PORT
    if [[ "${state^^}" =~ ^(LISTEN|LISTENING|UNCONN|UDP|BOUND)$ ]]; then
      engine=$(database_engine_for_text "$classification $transport $process")
      if [[ -z "$engine" && ( "${classification,,}" == *database* || "${classification,,}" == *hana* ) ]]; then
        database_engine_for_port "$local_port" && engine=$DB_ENGINE
      fi
      if [[ -n "$engine" ]]; then
        add_service_map_entry "Database services" "$engine listener" "${state:-listening}" "$local_ep" "$exposure" "$transport" "${process:-$service}" "socket/database inference"
        add_database_evidence "$engine" "local" "$local_ep" "listening" "$socket_confidence" "$classification listener owned by ${process:-unknown process}"
      fi
    fi

    if [[ "$exposure" == "connected" && -n "$remote_ep" && "$remote_ep" != "*:*" && "$remote_ep" != "0.0.0.0:*" ]]; then
      endpoint_parts "$remote_ep"; remote_addr=$EP_ADDR; remote_port=$EP_PORT
      [[ -n "$remote_addr" ]] || continue
      engine=""
      if database_engine_for_port "$remote_port"; then engine=$DB_ENGINE
      elif [[ "${classification,,} ${transport,,}" == *database* || "${classification,,}" == *hana* ]]; then
        engine=$(database_engine_for_text "$classification $transport")
      fi
      evidence="${process:-SAP process} ${state:-connected}: $local_ep → $remote_ep"
      if [[ -n "$engine" ]]; then
        if is_loopback "$remote_addr" || [[ -n "${local_addresses[${remote_addr,,}]+x}" ]]; then placement="local"; else placement="remote"; fi
        add_service_map_entry "Database services" "$engine database connection" "${state:-connected}" "$local_ep → $remote_ep" "$placement" "$transport" "${process:-$service}" "socket/database inference"
        add_database_evidence "$engine" "$placement" "$remote_ep" "${state:-connected}" "$socket_confidence" "$evidence"
      else
        remote_id="remote-$(topology_slug "$remote_ep")"
        add_topology_node "$remote_id" "$remote_ep" "remote-peer" "remote" "${state:-connected}" "Peer observed from ${process:-SAP-owned socket}"
        add_topology_edge "host" "$remote_id" "observed SAP connection" "${state:-connected}" "$socket_confidence" "$evidence"
      fi
    fi
  done < "$SOCKETS"

  local name start_mode account path description user group executable command_line source
  while IFS=$'\t' read -r name state start_mode account path description || [[ -n "$name" ]]; do
    [[ -n "$name" ]] || continue
    component=$(component_for_process "$name $description $path")
    category=$(service_category_for "$component $name $description")
    add_service_map_entry "$category" "$component" "${state:-installed}" "not attributed" "local" "service manager" "$account" "service"
    engine=$(database_engine_for_text "$component $name $description $path")
    [[ -z "$engine" ]] || add_database_evidence "$engine" "local" "${path:-service $name}" "${state:-installed}" "medium" "Local service definition: $name"
  done < "$SERVICES"

  while IFS=$'\t' read -r pid user group name executable command_line component || [[ -n "$pid" ]]; do
    [[ -n "$pid" ]] || continue
    category=$(service_category_for "$component $name $command_line")
    add_service_map_entry "$category" "${component:-$(component_for_process "$name $command_line")}" "running" "not attributed" "local" "process" "$name (PID $pid)" "process"
    engine=$(database_engine_for_text "$component $name $executable $command_line")
    [[ -z "$engine" ]] || add_database_evidence "$engine" "local" "${executable:-$name}" "running" "high" "Local database process $name (PID $pid)"
  done < "$PROCESSES"

  local path_category path_value path_type owner path_group mode size modified note
  while IFS=$'\t' read -r path_category path_value path_type owner path_group mode size modified note || [[ -n "$path_category" ]]; do
    [[ -n "$path_category" ]] || continue
    engine=$(database_engine_for_text "$path_category $path_value")
    [[ -z "$engine" ]] || add_database_evidence "$engine" "local" "$path_value" "filesystem footprint" "medium" "$path_category path observed"
  done < "$PATHS"

  local profile_file parameter value profile_source lower
  while IFS=$'\t' read -r profile_file parameter value profile_source || [[ -n "$profile_file" ]]; do
    [[ -n "$parameter" ]] || continue
    lower=${parameter,,}
    [[ "$value" == \[REDACTED* ]] && continue
    case "$lower" in
      sapdbhost|db/host|db/server|dbms/host|dbs/*/host|dbs/*/server)
        engine=$(database_engine_for_text "$parameter $value")
        [[ -n "$engine" ]] || engine="Configured SAP database"
        placement="configured"
        if is_loopback "$value" || [[ "${value,,}" == "${HOST_NAME,,}" ]]; then placement="local"; fi
        add_database_evidence "$engine" "$placement" "$value" "configured" "medium" "$parameter in $profile_file"
        ;;
      dbms/type|db/type|dbs/type)
        engine=$(database_engine_for_text "$value")
        [[ -z "$engine" ]] || add_database_evidence "$engine" "configured" "$value" "configured engine" "medium" "$parameter in $profile_file"
        ;;
    esac
  done < "$PROFILES"

  declare -A category_count=() category_listener_count=()
  local map_category map_component map_status map_endpoint map_scope map_transport map_process map_source
  while IFS=$'\t' read -r map_category map_component map_status map_endpoint map_scope map_transport map_process map_source || [[ -n "$map_category" ]]; do
    [[ -n "$map_category" ]] || continue
    category_count[$map_category]=$(( ${category_count[$map_category]:-0} + 1 ))
    if [[ "${map_status^^}" =~ ^(LISTEN|LISTENING|UNCONN|UDP|BOUND)$ ]]; then
      category_listener_count[$map_category]=$(( ${category_listener_count[$map_category]:-0} + 1 ))
    fi
  done < "$SERVICE_MAP"
  for category in "${!category_count[@]}"; do
    local category_id="service-$(topology_slug "$category")"
    add_topology_node "$category_id" "$category" "service-group" "local" "observed" \
      "${category_count[$category]} evidence record(s); ${category_listener_count[$category]:-0} listener(s)"
    add_topology_edge "host" "$category_id" "runs or exposes" "observed" "high" \
      "${category_count[$category]} process/service/socket record(s)"
  done

  local remote_count local_count configured_count
  remote_count=$(awk -F '\t' '$2=="remote"{n++} END{print n+0}' "$DATABASES")
  local_count=$(awk -F '\t' '$2=="local"{n++} END{print n+0}' "$DATABASES")
  configured_count=$(awk -F '\t' '$2=="configured"{n++} END{print n+0}' "$DATABASES")
  if ((remote_count > 0 && local_count > 0)); then
    DATABASE_POSTURE_STATUS="mixed"
    DATABASE_POSTURE_SUMMARY="Both local database footprint and remote/non-loopback database connections were observed."
    if awk -F '\t' '($2=="local" || $2=="remote") && $5=="high"{found=1} END{exit !found}' "$DATABASES"; then
      DATABASE_POSTURE_CONFIDENCE="high"
    else
      DATABASE_POSTURE_CONFIDENCE="medium"
    fi
  elif ((remote_count > 0)); then
    DATABASE_POSTURE_STATUS="remote-observed"
    DATABASE_POSTURE_SUMMARY="A remote/non-loopback database connection was observed from a recognized local socket."
    if awk -F '\t' '$2=="remote" && $5=="high"{found=1} END{exit !found}' "$DATABASES"; then
      DATABASE_POSTURE_CONFIDENCE="high"
    else
      DATABASE_POSTURE_CONFIDENCE="medium"
    fi
  elif ((local_count > 0)); then
    DATABASE_POSTURE_STATUS="local-observed"
    DATABASE_POSTURE_SUMMARY="Local database process, listener, or filesystem evidence was observed."
    if awk -F '\t' '$2=="local" && $5=="high"{found=1} END{exit !found}' "$DATABASES"; then
      DATABASE_POSTURE_CONFIDENCE="high"
    else
      DATABASE_POSTURE_CONFIDENCE="medium"
    fi
  elif ((configured_count > 0)); then
    DATABASE_POSTURE_STATUS="configured"
    DATABASE_POSTURE_SUMMARY="Database configuration evidence was found, but no active local or remote connection was observed."
    DATABASE_POSTURE_CONFIDENCE="medium"
  else
    DATABASE_POSTURE_STATUS="undetermined"
    DATABASE_POSTURE_SUMMARY="No database placement evidence was observed in the collected process, socket, path, or profile data."
    DATABASE_POSTURE_CONFIDENCE="low"
    add_database_evidence "Unknown" "undetermined" "not observed" "undetermined" "low" "Active database placement requires authenticated or runtime follow-up."
  fi

  local abap_status="Not observed" abap_confidence="low" abap_evidence="No ABAP dispatcher/system footprint observed."
  if grep -Eiq $'\t(SAP NetWeaver|SAP Dispatcher/Work Process|SAP Dispatcher / SAP DIAG)' "$SYSTEMS" "$PROCESSES" "$SOCKETS" 2>/dev/null; then
    abap_status="Observed"; abap_confidence="high"; abap_evidence="NetWeaver system, dispatcher process, or DIAG listener observed."
  fi
  add_capability "abap" "Application stack" "ABAP application server" "$abap_status" "$abap_confidence" "$abap_evidence" "Confirm active instances and roles with SAPControl and authenticated SAP administration."

  if awk -F '\t' '$1=="SAP WebGUI artifact"{found=1} END{exit !found}' "$PATHS"; then
    add_capability "webgui" "Web & UI" "SAP WebGUI for ABAP" "Enabled (host artifact observed)" "medium" \
      "A WebGUI-named host artifact exists and an ABAP footprint is ${abap_status,,}." \
      "Confirm that /sap/bc/gui/sap/its/webgui is active and appropriately authenticated in SICF; a host artifact alone cannot prove runtime activation."
  elif awk -F '\t' '$1 ~ /^SAP ICM HTTP/ && toupper($4) ~ /^(LISTEN|LISTENING|UNCONN|UDP|BOUND)$/ {found=1} END{exit !found}' "$SOCKETS" &&
       [[ "$abap_status" == "Observed" ]]; then
    add_capability "webgui" "Web & UI" "SAP WebGUI for ABAP" "Possible; not confirmed" "low" \
      "ABAP and ICM HTTP(S) evidence exists, but no WebGUI-named host artifact was observed." \
      "Check the WebGUI ICF service in SICF using an authorized SAP account."
  else
    add_capability "webgui" "Web & UI" "SAP WebGUI for ABAP" "Not observed" "low" \
      "No WebGUI-named host artifact was observed; this is not proof that the database-backed ICF service is disabled." \
      "Confirm /sap/bc/gui/sap/its/webgui status in SICF."
  fi

  if awk -F '\t' '$1 ~ /^SAP (ICM|NetWeaver Java) HTTP/ && toupper($4) ~ /^(LISTEN|LISTENING|UNCONN|UDP|BOUND)$/ {found=1} END{exit !found}' "$SOCKETS"; then
    add_capability "http" "Web & UI" "SAP HTTP(S) application surface" "Listening" "high" "ICM or Java HTTP(S) listener observed." "Validate virtual hosts, TLS, authentication, and exposed ICF/Java applications from approved network zones."
  else
    add_capability "http" "Web & UI" "SAP HTTP(S) application surface" "Not observed" "medium" "No recognized application HTTP(S) listener was recorded." "A clean host result is not proof of firewall or proxy absence."
  fi
  if awk -F '\t' '$1 ~ /^SAP RFC Gateway/ && toupper($4) ~ /^(LISTEN|LISTENING|UNCONN|UDP|BOUND)$/ {found=1} END{exit !found}' "$SOCKETS"; then
    add_capability "rfc" "Integration" "RFC Gateway" "Listening" "high" "RFC Gateway listener observed." "Validate effective secinfo/reginfo/prxyinfo and SNC with authorized SAP tooling."
  else
    add_capability "rfc" "Integration" "RFC Gateway" "Not observed" "medium" "No recognized RFC Gateway listener was recorded." "Confirm instance state and collection privilege."
  fi
  if awk -F '\t' 'tolower($2) ~ /^snc\//{found=1} END{exit !found}' "$PROFILES"; then
    add_capability "snc" "Transport security" "Secure Network Communications (SNC)" "Configured" "medium" "One or more snc/* profile parameters were observed." "Validate effective runtime values and negotiated QoP per connection; configuration presence is not proof of enforcement."
  else
    add_capability "snc" "Transport security" "Secure Network Communications (SNC)" "Not observed" "low" "No snc/* profile parameter was collected." "Check effective instance profiles and client/destination settings."
  fi
  local capability_key capability_category capability_title capability_pattern
  while IFS='|' read -r capability_key capability_category capability_title capability_pattern; do
    if grep -Eiq "$capability_pattern" "$SERVICES" "$PROCESSES" "$SOCKETS" "$PROFILES"; then
      add_capability "$capability_key" "$capability_category" "$capability_title" "Observed" "high" "Matching service, process, or socket evidence was collected." "Review the corresponding technical evidence and validate effective configuration."
    else
      add_capability "$capability_key" "$capability_category" "$capability_title" "Not observed" "medium" "No matching local runtime evidence was collected." "Confirm collection coverage before treating this as disabled."
    fi
  done <<'EOF'
java|Application stack|SAP NetWeaver Java|NetWeaver Java|jstart|jlaunch
scc|Boundary & cloud|SAP Cloud Connector|Cloud Connector|scc_daemon
saprouter|Boundary & cloud|SAProuter|SAProuter|saprouter
webdispatcher|Boundary & cloud|SAP Web Dispatcher|Web Dispatcher|sapwebdisp
igs|Web & UI|Internet Graphics Server (IGS)|SAP IGS|igswd|igsmux|igs/
management|Management|SAP Host Agent / Start Service|Host Agent|Start Service|saphost|sapstartsrv
EOF
  add_capability "database" "Data tier" "Database placement" "$DATABASE_POSTURE_STATUS" "$DATABASE_POSTURE_CONFIDENCE" "$DATABASE_POSTURE_SUMMARY" "Validate the inferred engine and placement with SAP profiles, SAPControl, and the database owner before changing connectivity."
  add_coverage "Service topology" "derived" "Nodes, edges, capabilities, service categories, and database placement were inferred from collected local evidence; no connection was initiated."
}

collect_host_metadata() {
  local elevated="no" os kernel user
  [[ ${EUID:-$(id -u)} -eq 0 ]] && elevated="yes"
  os=$( ( . /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME-}" ) || true)
  [[ -n "$os" ]] || os=$(uname -s 2>/dev/null || printf unknown)
  kernel=$(uname -r 2>/dev/null || printf unknown)
  user=$(id -un 2>/dev/null || printf unknown)
  append_row "$COVERAGE" "Host metadata" "complete" "Host=$HOST_NAME; OS=$os; kernel=$kernel; user=$user; elevated=$elevated; root=$ROOT_PATH"
  if [[ "$elevated" == "no" ]]; then
    add_coverage "Privilege" "partial" "Not elevated: process ownership, sockets, ACLs, and protected paths may be incomplete"
    warn "Not elevated; the report will explicitly mark permission-related coverage as partial"
  else
    add_coverage "Privilege" "complete" "Collector is running as root"
  fi
}

json_escape() {
  local value=${1-}
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//$'\b'/\\b}
  value=${value//$'\f'/\\f}
  value=${value//$'\n'/\\n}
  value=${value//$'\r'/\\r}
  value=${value//$'\t'/\\t}
  printf '%s' "$value"
}

write_json_array() {
  local file=$1
  shift
  local columns=("$@") first_row=1 line values i
  printf '['
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -n "$line" ]] || continue
    IFS=$'\t' read -r -a values <<< "$line"
    ((first_row)) || printf ','
    printf '\n    {'
    for i in "${!columns[@]}"; do
      ((i == 0)) || printf ','
      printf '"%s":"%s"' "$(json_escape "${columns[$i]}")" "$(json_escape "${values[$i]-}")"
    done
    printf '}'
    first_row=0
  done < "$file"
  ((first_row)) || printf '\n  '
  printf ']'
}

grade_for_score() {
  local score=$1
  if ((score < 10)); then printf 'A'
  elif ((score < 25)); then printf 'B'
  elif ((score < 50)); then printf 'C'
  elif ((score < 75)); then printf 'D'
  else printf 'F'
  fi
}

label_for_score() {
  local score=$1
  if ((score < 10)); then printf 'Low observed risk'
  elif ((score < 25)); then printf 'Limited hardening gaps'
  elif ((score < 50)); then printf 'Material hardening gaps'
  elif ((score < 75)); then printf 'High observed risk'
  else printf 'Critical remediation priority'
  fi
}

get_risk_grade() { grade_for_score "$RISK_SCORE"; }
get_risk_label() { label_for_score "$RISK_SCORE"; }

section_key_for_rule() {
  case "$1" in
    NET-*|DIAG-*|JAVA-*|ENQ-*|GW-001|MS-001|MS-003) printf 'network' ;;
    ABAP-*|ACL-*|AUTH-*|CFG-*|GW-*|ICM-*|IGS-*|MS-*|RFC-*|SNC-*|START-*|UCON-*) printf 'configuration' ;;
    FILE-*|TOOL-*) printf 'filesystem' ;;
    SSFS-*|GUI-*) printf 'secrets' ;;
    LOG-*|OSCMD-*) printf 'operations' ;;
    *) printf 'operations' ;;
  esac
}

section_title() {
  case "$1" in
    network) printf 'Network & exposed services' ;;
    configuration) printf 'Configuration & access controls' ;;
    filesystem) printf 'Files & executable integrity' ;;
    secrets) printf 'SSFS, credentials & client data' ;;
    operations) printf 'Operations, logging & command execution' ;;
  esac
}

build_section_scores() {
  : > "$SECTION_SCORES"
  local keys=(network configuration filesystem secrets operations)
  local id severity points rest key score capped grade label
  local count critical high medium low
  declare -A raw_score=() finding_count=() critical_count=() high_count=() medium_count=() low_count=()
  while IFS=$'\t' read -r id severity points rest || [[ -n "$id" ]]; do
    [[ -n "$id" ]] || continue
    key=$(section_key_for_rule "$id")
    raw_score[$key]=$(( ${raw_score[$key]:-0} + points ))
    finding_count[$key]=$(( ${finding_count[$key]:-0} + 1 ))
    case "$severity" in
      Critical) critical_count[$key]=$(( ${critical_count[$key]:-0} + 1 )) ;;
      High) high_count[$key]=$(( ${high_count[$key]:-0} + 1 )) ;;
      Medium) medium_count[$key]=$(( ${medium_count[$key]:-0} + 1 )) ;;
      Low) low_count[$key]=$(( ${low_count[$key]:-0} + 1 )) ;;
    esac
  done < "$FINDINGS"
  for key in "${keys[@]}"; do
    score=${raw_score[$key]:-0}
    ((score > 100)) && capped=100 || capped=$score
    grade=$(grade_for_score "$capped")
    label=$(label_for_score "$capped")
    count=${finding_count[$key]:-0}
    critical=${critical_count[$key]:-0}; high=${high_count[$key]:-0}
    medium=${medium_count[$key]:-0}; low=${low_count[$key]:-0}
    append_row "$SECTION_SCORES" "$key" "$(section_title "$key")" "$capped" "$grade" "$label" \
      "$count" "$critical" "$high" "$medium" "$low"
  done
}

write_section_scores_json() {
  local first=1 key title score grade label findings critical high medium low
  printf '['
  while IFS=$'\t' read -r key title score grade label findings critical high medium low || [[ -n "$key" ]]; do
    [[ -n "$key" ]] || continue
    ((first)) || printf ','
    printf '\n    {"key":"%s","title":"%s","score":%s,"grade":"%s","label":"%s","findings":%s,"critical":%s,"high":%s,"medium":%s,"low":%s}' \
      "$(json_escape "$key")" "$(json_escape "$title")" "$score" "$(json_escape "$grade")" \
      "$(json_escape "$label")" "$findings" "$critical" "$high" "$medium" "$low"
    first=0
  done < "$SECTION_SCORES"
  ((first)) || printf '\n  '
  printf ']'
}

generate_json() {
  log "Writing JSON evidence report"
  local grade grade_text
  grade=$(get_risk_grade)
  grade_text=$(get_risk_label)
  {
    printf '{\n'
    printf '  "schema":"%s",\n' "$(json_escape "$SCHEMA")"
    printf '  "tool_version":"%s",\n' "$VERSION"
    printf '  "generated_at":"%s",\n' "$COLLECTED_AT"
    printf '  "host":"%s",\n' "$(json_escape "$HOST_NAME")"
    printf '  "audit_root":"%s",\n' "$(json_escape "$ROOT_PATH")"
    printf '  "report_note":"%s",\n' "$(json_escape "$REPORT_NOTE")"
    printf '  "risk_score":%s,\n' "$RISK_SCORE"
    printf '  "risk_grade":"%s",\n' "$grade"
    printf '  "risk_label":"%s",\n' "$(json_escape "$grade_text")"
    printf '  "section_scores":'; write_section_scores_json; printf ',\n'
    printf '  "topology":{"database_posture":{"status":"%s","summary":"%s","confidence":"%s"},' \
      "$(json_escape "$DATABASE_POSTURE_STATUS")" "$(json_escape "$DATABASE_POSTURE_SUMMARY")" "$(json_escape "$DATABASE_POSTURE_CONFIDENCE")"
    printf '"nodes":'; write_json_array "$TOPOLOGY_NODES" id label kind scope status detail; printf ','
    printf '"edges":'; write_json_array "$TOPOLOGY_EDGES" source target relation state confidence evidence; printf ','
    printf '"services":'; write_json_array "$SERVICE_MAP" category component status endpoint scope transport process source; printf ','
    printf '"capabilities":'; write_json_array "$CAPABILITIES" key category title status confidence evidence validation; printf ','
    printf '"databases":'; write_json_array "$DATABASES" engine placement endpoint state confidence evidence; printf '},\n'
    printf '  "summary":{"findings":%s,"critical":%s,"high":%s,"medium":%s,"low":%s,"systems":%s,"services":%s,"processes":%s,"sockets":%s,"ssfs":%s,"tools":%s},\n' \
      "$(count_rows "$FINDINGS")" "$(count_severity Critical)" "$(count_severity High)" \
      "$(count_severity Medium)" "$(count_severity Low)" "$(count_rows "$SYSTEMS")" \
      "$(count_rows "$SERVICES")" "$(count_rows "$PROCESSES")" "$(count_rows "$SOCKETS")" \
      "$(count_rows "$SSFS")" "$(count_rows "$TOOLS")"
    printf '  "findings":'; write_json_array "$FINDINGS" id severity points title asset evidence recommendation reference; printf ',\n'
    printf '  "systems":'; write_json_array "$SYSTEMS" sid stack instances root source; printf ',\n'
    printf '  "services":'; write_json_array "$SERVICES" name state start_mode account path description; printf ',\n'
    printf '  "processes":'; write_json_array "$PROCESSES" pid user group name executable command component; printf ',\n'
    printf '  "sockets":'; write_json_array "$SOCKETS" classification transport protocol state local remote exposure pid process service; printf ',\n'
    printf '  "paths":'; write_json_array "$PATHS" category path type owner group mode size_bytes modified note; printf ',\n'
    printf '  "ssfs":'; write_json_array "$SSFS" family sid role path size_bytes owner group mode detail; printf ',\n'
    printf '  "tools":'; write_json_array "$TOOLS" name component path source owner group mode size_bytes sha256; printf ',\n'
    printf '  "profiles":'; write_json_array "$PROFILES" file parameter value source; printf ',\n'
    printf '  "coverage":'; write_json_array "$COVERAGE" check status detail; printf ',\n'
    printf '  "assessment_catalog":'; write_json_array "$ASSESSMENT" area status evidence next_step source; printf '\n'
    printf '}\n'
  } > "$JSON_PATH"
}

html_escape() {
  local value=${1-}
  value=${value//&/&amp;}
  value=${value//</&lt;}
  value=${value//>/&gt;}
  value=${value//\"/&quot;}
  value=${value//\'/&#39;}
  printf '%s' "$value"
}

render_table_rows() {
  local file=$1 class_col=${2--1}
  local line values value class="" i
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -n "$line" ]] || continue
    IFS=$'\t' read -r -a values <<< "$line"
    class=""
    if ((class_col >= 0)); then class=" severity-${values[$class_col],,}"; fi
    printf '<tr class="search-row%s">' "$class"
    for i in "${!values[@]}"; do
      value=${values[$i]}
      printf '<td>%s</td>' "$(html_escape "$value")"
    done
    printf '</tr>\n'
  done < "$file"
}

count_rows() { awk 'NF {n++} END {print n+0}' "$1"; }
count_severity() { awk -F '\t' -v s="$1" '$2==s {n++} END {print n+0}' "$FINDINGS"; }

score_class_for_grade() {
  case "${1,,}" in
    a) printf 'score-a' ;;
    b) printf 'score-b' ;;
    c) printf 'score-c' ;;
    d) printf 'score-d' ;;
    *) printf 'score-f' ;;
  esac
}

render_section_score_cards() {
  local key title score grade label findings critical high medium low score_class
  while IFS=$'\t' read -r key title score grade label findings critical high medium low || [[ -n "$key" ]]; do
    [[ -n "$key" ]] || continue
    score_class=$(score_class_for_grade "$grade")
    printf '<a class="score-card %s" href="#findings-%s"><div class="score-card-head"><h3>%s</h3><span class="grade">%s</span></div>' \
      "$score_class" "$(html_escape "$key")" "$(html_escape "$title")" "$(html_escape "$grade")"
    printf '<div class="score-value"><strong>%s</strong><span>/ 100</span></div><div class="score-meter" aria-label="%s out of 100"><span style="width:%s%%"></span></div>' \
      "$score" "$score" "$score"
    printf '<p>%s</p><small>%s finding(s) · %s critical · %s high · %s medium · %s low</small></a>\n' \
      "$(html_escape "$label")" "$findings" "$critical" "$high" "$medium" "$low"
  done < "$SECTION_SCORES"
}

render_finding_sections() {
  local section_key section_name score grade label findings critical high medium low
  local id severity points title asset evidence recommendation reference current_key severity_class
  while IFS=$'\t' read -r section_key section_name score grade label findings critical high medium low || [[ -n "$section_key" ]]; do
    [[ -n "$section_key" ]] || continue
    printf '<details id="findings-%s" class="report-section finding-section"><summary><h2>%s findings</h2><span class="count-badge">%s finding(s) · %s/100 · grade %s</span></summary><div class="section-body">' \
      "$(html_escape "$section_key")" "$(html_escape "$section_name")" "$findings" "$score" "$(html_escape "$grade")"
    printf '<div class="section-head"><div><strong>%s</strong><div class="muted">%s critical · %s high · %s medium · %s low</div></div><input class="filter" placeholder="Filter %s findings…" data-target="finding-list-%s"></div><div class="finding-list" id="finding-list-%s">\n' \
      "$(html_escape "$label")" "$critical" "$high" "$medium" "$low" "$(html_escape "$section_name")" "$(html_escape "$section_key")" "$(html_escape "$section_key")"
    if ((findings == 0)); then printf '<p class="empty">No findings recorded for this risk section.</p>'; fi
    while IFS=$'\t' read -r id severity points title asset evidence recommendation reference || [[ -n "$id" ]]; do
      [[ -n "$id" ]] || continue
      current_key=$(section_key_for_rule "$id")
      [[ "$current_key" == "$section_key" ]] || continue
      severity_class=${severity,,}
      printf '<details class="finding search-item severity-%s"><summary><span class="severity-badge">%s</span><code>%s</code><span class="finding-title">%s</span><span class="finding-summary-meta">%s · +%s</span></summary>' \
        "$severity_class" "$(html_escape "$severity")" "$(html_escape "$id")" "$(html_escape "$title")" "$(html_escape "$asset")" "$points"
      printf '<div class="finding-body"><dl><div><dt>Affected asset</dt><dd>%s</dd></div><div><dt>Evidence and impact</dt><dd>%s</dd></div><div><dt>Recommended change</dt><dd>%s</dd></div><div><dt>Reference</dt><dd>%s</dd></div></dl></div></details>\n' \
        "$(html_escape "$asset")" "$(html_escape "$evidence")" "$(html_escape "$recommendation")" "$(html_escape "$reference")"
    done < "$FINDINGS"
    printf '</div></div></details>\n'
  done < "$SECTION_SCORES"
}

render_topology_graph() {
  local id label kind scope status detail found=0
  printf '<div class="topology-graph" role="img" aria-label="Observed SAP services connect through the audited host to database and remote peers"><div class="graph-lane"><h3>Enabled and observed service groups</h3>'
  while IFS=$'\t' read -r id label kind scope status detail || [[ -n "$id" ]]; do
    [[ "$kind" == "service-group" ]] || continue
    found=1
    printf '<div class="graph-node service-node"><strong>%s</strong><small>%s</small></div>' "$(html_escape "$label")" "$(html_escape "$detail")"
  done < "$TOPOLOGY_NODES"
  ((found)) || printf '<div class="graph-node muted">No service group observed</div>'
  printf '</div><div class="graph-connector"><span>runs / listens</span><b>→</b></div><div class="graph-host"><span>SAP host</span><strong>%s</strong><small>%s system(s) · %s socket(s)</small></div><div class="graph-connector"><span>connects to</span><b>→</b></div><div class="graph-lane"><h3>Database and remote peers</h3>' \
    "$(html_escape "$HOST_NAME")" "$(count_rows "$SYSTEMS")" "$(count_rows "$SOCKETS")"
  found=0
  while IFS=$'\t' read -r id label kind scope status detail || [[ -n "$id" ]]; do
    [[ "$kind" == "database" || "$kind" == "remote-peer" ]] || continue
    found=1
    printf '<div class="graph-node %s-node"><strong>%s</strong><span class="node-scope">%s</span><small>%s</small></div>' \
      "$(html_escape "$kind")" "$(html_escape "$label")" "$(html_escape "$scope")" "$(html_escape "$detail")"
  done < "$TOPOLOGY_NODES"
  ((found)) || printf '<div class="graph-node muted">No connected peer observed</div>'
  printf '</div></div>'
}

render_service_map_groups() {
  local category count map_category component status endpoint scope transport process source
  while IFS= read -r category; do
    [[ -n "$category" ]] || continue
    count=$(awk -F '\t' -v c="$category" '$1==c{n++} END{print n+0}' "$SERVICE_MAP")
    printf '<details class="technical-group service-category"><summary><span>%s</span><span class="summary-meta">%s evidence record(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table><thead><tr><th>Component</th><th>Status</th><th>Endpoint</th><th>Scope</th><th>Transport</th><th>Process/account</th><th>Source</th></tr></thead><tbody>' \
      "$(html_escape "$category")" "$count"
    while IFS=$'\t' read -r map_category component status endpoint scope transport process source || [[ -n "$map_category" ]]; do
      [[ "$map_category" == "$category" ]] || continue
      printf '<tr class="search-row"><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' \
        "$(html_escape "$component")" "$(html_escape "$status")" "$(html_escape "$endpoint")" "$(html_escape "$scope")" \
        "$(html_escape "$transport")" "$(html_escape "$process")" "$(html_escape "$source")"
    done < "$SERVICE_MAP"
    printf '</tbody></table></div></div></details>'
  done < <(cut -f1 "$SERVICE_MAP" | sort -u)
}

render_capability_rows() {
  local key category title status confidence evidence validation status_class
  while IFS=$'\t' read -r key category title status confidence evidence validation || [[ -n "$key" ]]; do
    [[ -n "$key" ]] || continue
    case "$status" in
      Enabled*) status_class=enabled ;;
      Observed*) status_class=observed ;;
      Listening*) status_class=listening ;;
      Configured*) status_class=configured ;;
      Possible*) status_class=possible ;;
      "Not observed"*) status_class=not-observed ;;
      *) status_class=$(topology_slug "$status") ;;
    esac
    printf '<tr class="search-row"><td>%s</td><td>%s</td><td><span class="status-badge status-%s">%s</span></td><td>%s</td><td>%s</td><td>%s</td></tr>' \
      "$(html_escape "$category")" "$(html_escape "$title")" "$(html_escape "$status_class")" "$(html_escape "$status")" \
      "$(html_escape "$confidence")" "$(html_escape "$evidence")" "$(html_escape "$validation")"
  done < "$CAPABILITIES"
}

render_socket_rows() {
  local requested=$1 classification transport protocol state local_ep remote_ep exposure pid process service
  while IFS=$'\t' read -r classification transport protocol state local_ep remote_ep exposure pid process service || [[ -n "$classification" ]]; do
    [[ -n "$classification" ]] || continue
    if [[ "$requested" == "connected" ]]; then [[ "$exposure" == "connected" ]] || continue
    else [[ "$exposure" != "connected" ]] || continue
    fi
    printf '<tr class="search-row"><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' \
      "$(html_escape "$classification")" "$(html_escape "$transport")" "$(html_escape "$protocol")" "$(html_escape "$state")" \
      "$(html_escape "$local_ep")" "$(html_escape "$remote_ep")" "$(html_escape "$exposure")" "$(html_escape "$pid")" \
      "$(html_escape "$process")" "$(html_escape "$service")"
  done < "$SOCKETS"
}

render_path_groups() {
  local category count row_category path_value type owner group mode size modified note
  while IFS= read -r category; do
    [[ -n "$category" ]] || continue
    count=$(awk -F '\t' -v c="$category" '$1==c{n++} END{print n+0}' "$PATHS")
    printf '<details class="technical-group path-category"><summary><span>%s</span><span class="summary-meta">%s path(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table><thead><tr><th>Path</th><th>Type</th><th>Owner</th><th>Group</th><th>Mode</th><th>Bytes</th><th>Modified</th><th>Note</th></tr></thead><tbody>' "$(html_escape "$category")" "$count"
    while IFS=$'\t' read -r row_category path_value type owner group mode size modified note || [[ -n "$row_category" ]]; do
      [[ "$row_category" == "$category" ]] || continue
      printf '<tr class="search-row"><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' \
        "$(html_escape "$path_value")" "$(html_escape "$type")" "$(html_escape "$owner")" "$(html_escape "$group")" \
        "$(html_escape "$mode")" "$(html_escape "$size")" "$(html_escape "$modified")" "$(html_escape "$note")"
    done < "$PATHS"
    printf '</tbody></table></div></div></details>'
  done < <(cut -f1 "$PATHS" | sort -u)
}

generate_html() {
  log "Writing self-contained HTML report"
  local finding_count system_count service_count process_count socket_count ssfs_count tool_count
  local profile_count path_count assessment_count coverage_count
  local service_map_count capability_count database_count edge_count listener_count connected_count
  local critical high medium low grade grade_text
  finding_count=$(count_rows "$FINDINGS"); system_count=$(count_rows "$SYSTEMS")
  service_count=$(count_rows "$SERVICES"); process_count=$(count_rows "$PROCESSES")
  socket_count=$(count_rows "$SOCKETS"); ssfs_count=$(count_rows "$SSFS"); tool_count=$(count_rows "$TOOLS")
  profile_count=$(count_rows "$PROFILES"); path_count=$(count_rows "$PATHS")
  assessment_count=$(count_rows "$ASSESSMENT"); coverage_count=$(count_rows "$COVERAGE")
  service_map_count=$(count_rows "$SERVICE_MAP"); capability_count=$(count_rows "$CAPABILITIES")
  database_count=$(count_rows "$DATABASES"); edge_count=$(count_rows "$TOPOLOGY_EDGES")
  listener_count=$(awk -F '\t' '$7!="connected"{n++} END{print n+0}' "$SOCKETS")
  connected_count=$(awk -F '\t' '$7=="connected"{n++} END{print n+0}' "$SOCKETS")
  critical=$(count_severity Critical); high=$(count_severity High); medium=$(count_severity Medium); low=$(count_severity Low)
  grade=$(get_risk_grade)
  grade_text=$(get_risk_label)

  {
    cat <<EOF
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="generator" content="SAPstract $VERSION">
<title>SAPstract audit — $(html_escape "$HOST_NAME")</title>
<script>try{document.documentElement.dataset.theme=localStorage.getItem('sapstract-theme')||'light'}catch(e){document.documentElement.dataset.theme='light'}</script>
<style>
:root{color-scheme:light;--bg:#f3f4f6;--surface:#fff;--surface-alt:#f8fafc;--text:#1f2937;--muted:#64748b;--line:#cbd5e1;--line-strong:#94a3b8;--accent:#1d4ed8;--accent-soft:#dbeafe;--critical:#b91c1c;--critical-soft:#fee2e2;--high:#c2410c;--high-soft:#ffedd5;--medium:#a16207;--medium-soft:#fef3c7;--low:#1d4ed8;--low-soft:#dbeafe;--ok:#15803d;--ok-soft:#dcfce7}
html[data-theme="dark"]{color-scheme:dark;--bg:#161616;--surface:#222;--surface-alt:#2b2b2b;--text:#ededed;--muted:#b8b8b8;--line:#484848;--line-strong:#686868;--accent:#e5e5e5;--accent-soft:#363636;--critical:#fca5a5;--critical-soft:#4c1d24;--high:#fdba74;--high-soft:#4a2918;--medium:#fde68a;--medium-soft:#473b16;--low:#d4d4d4;--low-soft:#333;--ok:#86efac;--ok-soft:#163b28}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 Arial,Helvetica,sans-serif}a{color:var(--accent)}code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.wrap{max-width:1500px;margin:auto;padding:24px}.hero{display:flex;justify-content:space-between;gap:24px;align-items:flex-start;padding:24px;border:1px solid var(--line);border-top:5px solid var(--accent);background:var(--surface)}.brand{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:var(--accent);font-weight:700}.hero h1{font-size:clamp(28px,4vw,44px);line-height:1.1;margin:.2em 0}.hero-actions{display:flex;flex-direction:column;align-items:flex-end;gap:10px;min-width:180px}.overall-index{padding:10px 12px;border:1px solid var(--line);background:var(--surface-alt);text-align:right}.overall-index strong{font-size:22px}.muted{color:var(--muted)}button,.filter{font:inherit;color:var(--text);background:var(--surface);border:1px solid var(--line-strong);padding:8px 11px;border-radius:3px}.theme-toggle{cursor:pointer;white-space:nowrap}.theme-toggle:hover{border-color:var(--accent)}
nav{position:sticky;top:0;z-index:4;margin:14px 0;display:flex;overflow-x:auto;background:var(--surface);border:1px solid var(--line)}nav a{text-decoration:none;color:var(--text);white-space:nowrap;padding:9px 12px;border-right:1px solid var(--line)}nav a:hover{background:var(--accent-soft);color:var(--accent)}section,.report-section{display:block;margin:14px 0;border:1px solid var(--line);background:var(--surface)}section{padding:18px}.report-section>summary{display:flex;justify-content:space-between;gap:16px;align-items:center;padding:15px 18px;cursor:pointer;list-style-position:inside;background:var(--surface-alt)}.report-section[open]>summary{border-bottom:1px solid var(--line)}.report-section>summary h2{display:inline;margin:0}.section-body{padding:18px}.section-head{display:flex;justify-content:space-between;gap:16px;align-items:end;margin-bottom:12px}h2{margin:0 0 4px;font-size:22px}h3{margin:0;font-size:16px}.filter{min-width:270px}.pill,.count-badge{display:inline-block;padding:3px 8px;border:1px solid var(--line);background:var(--surface-alt);white-space:nowrap}
.score-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin:14px 0}.score-card{border:1px solid var(--line);border-top:4px solid var(--line-strong);padding:14px;background:var(--surface)}.score-card-head{display:flex;justify-content:space-between;gap:8px;align-items:start}.score-card h3{font-size:15px}.grade{display:grid;place-items:center;width:30px;height:30px;border:1px solid currentColor;font-weight:700}.score-value{display:flex;align-items:baseline;gap:4px;margin-top:8px}.score-value strong{font-size:30px}.score-value span,.score-card p,.score-card small{color:var(--muted)}.score-card p{margin:6px 0}.score-meter{height:7px;background:var(--surface-alt);border:1px solid var(--line)}.score-meter span{display:block;height:100%;background:currentColor}.score-a{color:var(--ok);border-top-color:var(--ok)}.score-b{color:var(--low);border-top-color:var(--low)}.score-c{color:var(--medium);border-top-color:var(--medium)}.score-d{color:var(--high);border-top-color:var(--high)}.score-f{color:var(--critical);border-top-color:var(--critical)}.score-card h3,.score-card .score-value strong{color:var(--text)}
.score-card{text-decoration:none;display:block}.score-card:hover{background:var(--surface-alt);border-color:currentColor}.topology-graph{display:grid;grid-template-columns:minmax(210px,1fr) auto minmax(190px,.7fr) auto minmax(210px,1fr);gap:12px;align-items:center;padding:16px;border:1px solid var(--line);background:var(--surface-alt)}.graph-lane{display:grid;gap:8px;align-content:center}.graph-lane h3{text-align:center;color:var(--muted);font-size:13px}.graph-node,.graph-host{padding:10px;border:1px solid var(--line-strong);background:var(--surface);display:grid;gap:3px}.graph-node strong,.graph-host strong{overflow-wrap:anywhere}.graph-node small,.graph-host small{color:var(--muted)}.graph-host{border:3px solid var(--accent);text-align:center;padding:18px}.graph-host span,.node-scope{text-transform:uppercase;font-size:11px;letter-spacing:.06em;color:var(--muted)}.graph-connector{display:grid;gap:4px;text-align:center;color:var(--muted)}.graph-connector b{font-size:25px;color:var(--accent)}.database-node{border-left:5px solid var(--medium)}.remote-peer-node{border-left:5px solid var(--accent)}.posture-card{border:1px solid var(--line);border-left:5px solid var(--medium);padding:12px;background:var(--surface-alt);margin:12px 0}.status-badge{display:inline-block;padding:2px 7px;border:1px solid var(--line-strong);background:var(--surface-alt);font-weight:700}.status-observed,.status-enabled,.status-listening,.status-configured,.status-local-observed,.status-remote-observed,.status-mixed{color:var(--ok);background:var(--ok-soft)}.status-possible,.status-undetermined{color:var(--medium);background:var(--medium-soft)}.status-not-observed{color:var(--muted)}
.risk{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}.risk div{padding:12px;border:1px solid currentColor;background:var(--surface-alt)}.risk b{font-size:22px;display:block}.critical{color:var(--critical)}.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin:12px 0}.card{padding:12px;border:1px solid var(--line);background:var(--surface-alt)}.card b{font-size:22px;display:block}.card small{color:var(--muted)}.notice{padding:11px 13px;border-left:4px solid var(--accent);background:var(--accent-soft)}
.technical-group,.finding-group,.finding{margin-top:10px;border:1px solid var(--line);background:var(--surface)}.technical-group>summary,.finding-group>summary{display:flex;justify-content:space-between;gap:12px;padding:11px 13px;cursor:pointer;background:var(--surface-alt);font-weight:700}.technical-group[open]>summary,.finding-group[open]>summary{border-bottom:1px solid var(--line)}.technical-group-body,.finding-list{padding:12px}.summary-meta{color:var(--muted);font-weight:400}.finding{border-left:5px solid var(--line-strong)}.finding>summary{display:grid;grid-template-columns:auto auto minmax(220px,1fr) auto;gap:9px;align-items:center;padding:10px;cursor:pointer}.finding-title{font-weight:700}.finding-summary-meta{color:var(--muted);text-align:right}.severity-critical{border-left-color:var(--critical)}.severity-high{border-left-color:var(--high)}.severity-medium{border-left-color:var(--medium)}.severity-low{border-left-color:var(--low)}.severity-badge{padding:2px 7px;border:1px solid currentColor;font-size:12px;font-weight:700}.severity-critical .severity-badge{color:var(--critical);background:var(--critical-soft)}.severity-high .severity-badge{color:var(--high);background:var(--high-soft)}.severity-medium .severity-badge{color:var(--medium);background:var(--medium-soft)}.severity-low .severity-badge{color:var(--low);background:var(--low-soft)}.finding-body{padding:0 12px 12px}.finding-body dl{margin:0;display:grid;gap:8px}.finding-body dl>div{display:grid;grid-template-columns:150px 1fr;border-top:1px solid var(--line);padding-top:8px}.finding-body dt{font-weight:700}.finding-body dd{margin:0;overflow-wrap:anywhere}
.scroll-hint{display:flex;justify-content:flex-end;color:var(--muted);font-size:12px;margin:4px 0}.table-wrap{width:100%;max-width:100%;overflow-x:auto;overflow-y:visible;border:1px solid var(--line);scrollbar-gutter:stable}.table-wrap::-webkit-scrollbar{height:12px}.table-wrap::-webkit-scrollbar-track{background:var(--surface-alt)}.table-wrap::-webkit-scrollbar-thumb{background:var(--line-strong);border:2px solid var(--surface-alt)}table{border-collapse:collapse;width:max-content;min-width:100%}th,td{text-align:left;vertical-align:top;padding:9px 11px;border-bottom:1px solid var(--line);min-width:110px;max-width:430px;overflow-wrap:anywhere}th{position:sticky;top:0;background:var(--surface-alt);font-size:12px;text-transform:uppercase;letter-spacing:.04em}tbody tr:hover td{background:var(--accent-soft)}.empty{padding:18px;color:var(--muted)}footer{text-align:center;color:var(--muted);padding:26px}.hide{display:none!important}
@media(max-width:900px){.topology-graph{grid-template-columns:1fr}.graph-connector b{transform:rotate(90deg)}.graph-connector span{display:none}}@media(max-width:760px){.wrap{padding:10px}.hero{flex-direction:column}.hero-actions{align-items:stretch;width:100%}.overall-index{text-align:left}.risk{grid-template-columns:1fr 1fr}.section-head{align-items:stretch;flex-direction:column}.filter{min-width:0;width:100%}.finding>summary{grid-template-columns:auto auto 1fr}.finding-summary-meta{grid-column:1/-1;text-align:left}.finding-body dl>div{grid-template-columns:1fr}.summary-meta{display:none}}
@media print{:root,html[data-theme="dark"]{color-scheme:light;--bg:#fff;--surface:#fff;--surface-alt:#f4f4f4;--text:#111;--muted:#555;--line:#aaa;--line-strong:#777;--accent:#174ea6}body{background:#fff}.wrap{max-width:none;padding:0}.theme-toggle,nav,.filter,.scroll-hint{display:none}.report-section{break-inside:avoid}.table-wrap{overflow:visible}table{width:100%;min-width:0;font-size:9px}th,td{min-width:0;max-width:none;padding:4px}.finding-group,.finding{break-inside:avoid}}
</style>
</head>
<body><div class="wrap">
<header class="hero">
  <div><div class="brand">SAPstract · Host posture</div><h1>$(html_escape "$HOST_NAME")</h1>
    <p class="muted">Generated $(html_escape "$COLLECTED_AT") · Schema $SCHEMA · Audit root $(html_escape "$ROOT_PATH")</p>
    $([[ -z "$REPORT_NOTE" ]] || printf '<p class="notice"><strong>Report context:</strong> %s</p>' "$(html_escape "$REPORT_NOTE")")
    <p>Review the section scores below to see where risk is concentrated. Scores reflect observed local evidence, not proof of exploitability or an SAP application-layer certification.</p>
  </div>
  <div class="hero-actions"><button class="theme-toggle" id="theme-toggle" type="button" aria-label="Switch color theme">Dark theme</button><div class="overall-index"><span class="muted">Aggregate index</span><br><strong>$RISK_SCORE/100 · $grade</strong><br><small>$grade_text</small></div></div>
</header>
<nav><a href="#summary">Summary</a><a href="#topology">Topology</a><a href="#capabilities">Capabilities</a><a href="#database">Database</a><a href="#service-catalog">Service catalog</a><a href="#findings">Findings</a><a href="#systems">Systems</a><a href="#runtime">Runtime</a><a href="#sockets">Connections</a><a href="#ssfs">SSFS</a><a href="#profiles">Profiles</a><a href="#paths">Files</a><a href="#assessment">Assessment</a><a href="#coverage">Coverage</a></nav>
<section id="summary"><div class="section-head"><div><h2>Executive summary</h2><div class="muted">Passive evidence collected from this host</div></div><span class="pill">$finding_count findings</span></div>
  <h3>Risk by section</h3><div class="score-grid">$(render_section_score_cards)</div>
  <div class="risk"><div><b class="critical">$critical</b>Critical</div><div><b class="high">$high</b>High</div><div><b class="medium">$medium</b>Medium</div><div><b class="low">$low</b>Low</div></div>
  <div class="cards"><div class="card"><b>$system_count</b><small>SAP systems</small></div><div class="card"><b>$service_map_count</b><small>service evidence rows</small></div><div class="card"><b>$listener_count</b><small>listening endpoints</small></div><div class="card"><b>$connected_count</b><small>observed connections</small></div><div class="card"><b>$capability_count</b><small>capability checks</small></div><div class="card"><b>$database_count</b><small>database evidence rows</small></div><div class="card"><b>$ssfs_count</b><small>SSFS artifacts</small></div><div class="card"><b>$tool_count</b><small>SAP tools</small></div></div>
  <div class="posture-card"><strong>Database placement: $(html_escape "$DATABASE_POSTURE_STATUS")</strong><br><span>$(html_escape "$DATABASE_POSTURE_SUMMARY")</span> <small>Confidence: $(html_escape "$DATABASE_POSTURE_CONFIDENCE")</small></div>
  <p class="notice">SAPstract is deliberately read-only: it does not scan another host, call SAP web methods, log in, brute-force, decrypt SSFS, or print secrets. Validate high-impact changes with the responsible SAP Basis, security, database, and infrastructure owners.</p>
</section>
<details id="topology" class="report-section" open><summary><h2>SAP service and connection topology</h2><span class="count-badge">$edge_count relationship(s)</span></summary><div class="section-body"><p class="notice">This graph shows observed local processes, services, listeners, and connections. “Remote” means the peer address was not loopback or another collected local socket address; confirm routing and database ownership before relying on the placement.</p>$(render_topology_graph)<details class="technical-group"><summary><span>Topology relationships and evidence</span><span class="summary-meta">$edge_count edge(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table id="topology-edges-table"><thead><tr><th>Source</th><th>Target</th><th>Relationship</th><th>State</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>$(render_table_rows "$TOPOLOGY_EDGES")</tbody></table></div></div></details></div></details>
<details id="capabilities" class="report-section" open><summary><h2>SAP capabilities and enabled surfaces</h2><span class="count-badge">$capability_count check(s)</span></summary><div class="section-body"><p class="muted">Observed means local evidence exists. Not observed is never equivalent to disabled. WebGUI host artifacts are marked enabled with medium confidence and still require SICF confirmation.</p><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table id="capabilities-table"><thead><tr><th>Category</th><th>Capability</th><th>Status</th><th>Confidence</th><th>Evidence</th><th>Required validation</th></tr></thead><tbody>$(render_capability_rows)</tbody></table></div></div></details>
<details id="database" class="report-section" open><summary><h2>Database landscape</h2><span class="count-badge">$(html_escape "$DATABASE_POSTURE_STATUS") · $database_count evidence row(s)</span></summary><div class="section-body"><div class="posture-card"><strong>$(html_escape "$DATABASE_POSTURE_SUMMARY")</strong><br><small>Confidence: $(html_escape "$DATABASE_POSTURE_CONFIDENCE"). A non-loopback peer can still be another address on the same host if socket coverage is incomplete.</small></div><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table id="database-table"><thead><tr><th>Engine</th><th>Placement</th><th>Endpoint/artifact</th><th>State</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>$(render_table_rows "$DATABASES")</tbody></table></div></div></details>
<details id="service-catalog" class="report-section" open><summary><h2>Categorized SAP service catalog</h2><span class="count-badge">$service_map_count evidence row(s)</span></summary><div class="section-body"><div class="section-head"><div class="muted">Processes, service-manager entries, listeners, and established connections grouped by technical purpose</div><input class="filter" placeholder="Filter service evidence…" data-target="service-catalog-groups"></div><div id="service-catalog-groups">$(render_service_map_groups)</div></div></details>
<section id="findings"><div class="section-head"><div><h2>Prioritized findings by risk section</h2><div class="muted">Each risk domain has its own report section and filter below.</div></div><span class="pill">$finding_count total finding(s)</span></div></section>
$(render_finding_sections)
EOF
    cat <<EOF
<details id="systems" class="report-section"><summary><h2>SAP systems</h2><span class="count-badge">$system_count system(s)</span></summary><div class="section-body"><div class="section-head"><div class="muted">SID and instance footprints</div><input class="filter" placeholder="Filter systems…" data-target="systems-table"></div><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table id="systems-table"><thead><tr><th>SID</th><th>Stack</th><th>Instances</th><th>Root</th><th>Source</th></tr></thead><tbody>
EOF
    render_table_rows "$SYSTEMS"
    cat <<EOF
</tbody></table></div></div></details>
<details id="runtime" class="report-section"><summary><h2>Raw services and processes</h2><span class="count-badge">$service_count service(s) · $process_count process(es)</span></summary><div class="section-body"><div class="section-head"><div class="muted">Underlying service-manager and process evidence; use the categorized catalog above for analysis</div><input class="filter" placeholder="Filter services/processes…" data-target="service-tables"></div><div id="service-tables">
<details class="technical-group" open><summary><span>Services</span><span class="summary-meta">$service_count instance(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table><thead><tr><th>Name</th><th>State</th><th>Start mode</th><th>Account</th><th>Definition/path</th><th>Description</th></tr></thead><tbody>
EOF
    render_table_rows "$SERVICES"
    cat <<EOF
</tbody></table></div></div></details><details class="technical-group"><summary><span>Processes</span><span class="summary-meta">$process_count instance(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table><thead><tr><th>PID</th><th>User</th><th>Group</th><th>Name</th><th>Executable</th><th>Command</th><th>Component</th></tr></thead><tbody>
EOF
    render_table_rows "$PROCESSES"
    cat <<EOF
</tbody></table></div></div></details></div></div></details>
<details id="sockets" class="report-section"><summary><h2>Listening endpoints and open connections</h2><span class="count-badge">$listener_count listener(s) · $connected_count connection(s)</span></summary><div class="section-body"><div class="section-head"><div class="muted">Separated listener and connection evidence; no remote probes were sent</div><input class="filter" placeholder="Filter network evidence…" data-target="socket-groups"></div><div id="socket-groups"><details class="technical-group" open><summary><span>Listening endpoints</span><span class="summary-meta">$listener_count observation(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table><thead><tr><th>Classification</th><th>Transport</th><th>Protocol</th><th>State</th><th>Local</th><th>Remote</th><th>Exposure</th><th>PID</th><th>Process</th><th>Service</th></tr></thead><tbody>
EOF
    render_socket_rows "listening"
    cat <<EOF
</tbody></table></div></div></details><details class="technical-group" open><summary><span>Established and open connections</span><span class="summary-meta">$connected_count observation(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table><thead><tr><th>Classification</th><th>Transport</th><th>Protocol</th><th>State</th><th>Local</th><th>Remote</th><th>Exposure</th><th>PID</th><th>Process</th><th>Service</th></tr></thead><tbody>
EOF
    render_socket_rows "connected"
    cat <<EOF
</tbody></table></div></div></details></div></div></details>
<details id="ssfs" class="report-section"><summary><h2>SAP secure stores (SSFS)</h2><span class="count-badge">$ssfs_count artifact(s)</span></summary><div class="section-body"><div class="section-head"><div class="muted">Metadata-only coverage: ABAP/RSEC, HANA instance, HANA System-PKI, hdbuserstore, enhanced LKY, and Cloud Connector</div><input class="filter" placeholder="Filter SSFS…" data-target="ssfs-table"></div>
<p class="notice">The presence of a <code>.DAT</code> and <code>.KEY</code> pair is operational evidence—not a guarantee of secure key lifecycle. Conversely, a missing key can mean a separate configured path; Cloud Connector and default-key contexts require product-specific confirmation. No record names, values, HMAC keys, master keys, or decrypted bytes are included.</p>
<details class="technical-group" open><summary><span>Secure-store artifacts</span><span class="summary-meta">$ssfs_count metadata record(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table id="ssfs-table"><thead><tr><th>Family</th><th>SID/store</th><th>Role</th><th>Path</th><th>Bytes</th><th>Owner</th><th>Group</th><th>Mode</th><th>Safe inspection detail</th></tr></thead><tbody>
EOF
    render_table_rows "$SSFS"
    cat <<EOF
</tbody></table></div></div></details></div></details>
<details id="tools" class="report-section"><summary><h2>SAP tools</h2><span class="count-badge">$tool_count tool(s)</span></summary><div class="section-body"><div class="section-head"><div class="muted">Administration and runtime binaries; not executed</div><input class="filter" placeholder="Filter tools…" data-target="tools-table"></div><details class="technical-group" open><summary><span>Tool instances and integrity metadata</span><span class="summary-meta">$tool_count binary record(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table id="tools-table"><thead><tr><th>Name</th><th>Capability</th><th>Path</th><th>Source</th><th>Owner</th><th>Group</th><th>Mode</th><th>Bytes</th><th>SHA-256</th></tr></thead><tbody>
EOF
    render_table_rows "$TOOLS"
    cat <<EOF
</tbody></table></div></div></details></div></details>
<details id="profiles" class="report-section"><summary><h2>Profiles and parameters</h2><span class="count-badge">$profile_count parameter(s)</span></summary><div class="section-body"><div class="section-head"><div class="muted">Security-relevant local configuration; secret-like values are always redacted</div><input class="filter" placeholder="Filter parameters…" data-target="profiles-table"></div><details class="technical-group" open><summary><span>Observed parameter instances</span><span class="summary-meta">$profile_count record(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table id="profiles-table"><thead><tr><th>File</th><th>Parameter</th><th>Value</th><th>Source</th></tr></thead><tbody>
EOF
    render_table_rows "$PROFILES"
    cat <<EOF
</tbody></table></div></div></details></div></details>
<details id="paths" class="report-section"><summary><h2>Files, directories, and permissions</h2><span class="count-badge">$path_count path(s)</span></summary><div class="section-body"><div class="section-head"><div class="muted">Filesystem evidence split into technical categories</div><input class="filter" placeholder="Filter path evidence…" data-target="path-groups"></div><div id="path-groups">$(render_path_groups)</div></div></details>
EOF
    cat <<EOF
<details id="assessment" class="report-section"><summary><h2>Assessment map</h2><span class="count-badge">$assessment_count area(s)</span></summary><div class="section-body"><div class="section-head"><div class="muted">Automated evidence and the authenticated or active work still required—absence of evidence is never shown as a pass</div><input class="filter" placeholder="Filter assessment map…" data-target="assessment-table"></div><details class="technical-group" open><summary><span>Coverage areas and required follow-up</span><span class="summary-meta">$assessment_count area(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table id="assessment-table"><thead><tr><th>Area</th><th>Status</th><th>Evidence collected</th><th>Required next step</th><th>Research source</th></tr></thead><tbody>
EOF
    render_table_rows "$ASSESSMENT"
    cat <<EOF
</tbody></table></div></div></details></div></details>
<details id="coverage" class="report-section"><summary><h2>Coverage and limitations</h2><span class="count-badge">$coverage_count check(s)</span></summary><div class="section-body"><p class="muted">Use this section when interpreting a clean result.</p><details class="technical-group" open><summary><span>Collection coverage</span><span class="summary-meta">$coverage_count check(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table><thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead><tbody>
EOF
    render_table_rows "$COVERAGE"
    cat <<EOF
</tbody></table></div></div></details>
<details class="technical-group"><summary><span>Scoring model</span><span class="summary-meta">How section and aggregate scores work</span></summary><div class="technical-group-body"><p>Each unique affected asset contributes Critical 30, High 18, Medium 8, or Low 3 points. Each section is capped independently at 100; the backward-compatible aggregate index is also capped at 100. Grade A is 0–9, B 10–24, C 25–49, D 50–74, and F 75–100. A score is a prioritization aid, not a probability of compromise. Duplicate evidence for the same rule and asset is de-duplicated.</p></div></details>
<details class="technical-group"><summary><span>Assessment boundary</span><span class="summary-meta">What this host-local pass cannot prove</span></summary><div class="technical-group-body"><p>This host-local pass can prove file metadata, selected profile values, running processes/services, and local socket state at collection time. It cannot prove firewall reachability from another zone, SAP authorization design, current Security Notes, TLS cipher quality, SNC use on each session, database role design, ABAP code security, or whether an observed version is vulnerable. Those require authenticated and change-controlled follow-up.</p></div></details>
<details class="technical-group"><summary><span>Research basis</span><span class="summary-meta">References behind recognition and risk context</span></summary><div class="technical-group-body"><p>Service recognition and threat context are aligned with SAP documentation, OWASP Core Business Application Security, the community SAP Pentest Playbook, and PySAP protocol/file-format modules. SAPstract has no PySAP, Scapy, Python, browser-CDN, or network-scanner runtime dependency.</p></div></details>
</div></details>
<footer>SAPstract $VERSION · JSON companion: $(html_escape "$(basename -- "$JSON_PATH")") · Evidence may contain sensitive topology; protect the report.</footer>
</div>
<script>
const root=document.documentElement,themeButton=document.getElementById('theme-toggle');
function syncThemeButton(){themeButton.textContent=root.dataset.theme==='dark'?'Light theme':'Dark theme'}
syncThemeButton();
themeButton.addEventListener('click',()=>{
  root.dataset.theme=root.dataset.theme==='dark'?'light':'dark';
  try{localStorage.setItem('sapstract-theme',root.dataset.theme)}catch(e){}
  syncThemeButton();
});
document.querySelectorAll('.filter').forEach(input=>input.addEventListener('input',()=>{
  const q=input.value.toLowerCase(), target=input.dataset.target;
  let rows=[],items=[];
  const direct=document.getElementById(target);
  if(direct){rows=[...direct.querySelectorAll('tbody tr')];items=[...direct.querySelectorAll('.search-item')]}
  else rows=[...document.querySelectorAll('.'+target+' tbody tr')];
  rows.forEach(row=>row.classList.toggle('hide',!row.textContent.toLowerCase().includes(q)));
  items.forEach(item=>item.classList.toggle('hide',!item.textContent.toLowerCase().includes(q)));
  if(direct) direct.querySelectorAll('.search-group,.service-category,.path-category').forEach(group=>{
    const visibleItems=[...group.querySelectorAll('.search-item')].some(item=>!item.classList.contains('hide'));
    const visibleRows=[...group.querySelectorAll('tbody tr')].some(row=>!row.classList.contains('hide'));
    group.classList.toggle('hide',!(visibleItems||visibleRows));
  });
}));
document.querySelectorAll('nav a,.score-card').forEach(link=>link.addEventListener('click',()=>{
  const target=document.querySelector(link.getAttribute('href'));
  if(target&&target.tagName==='DETAILS')target.open=true;
}));
document.querySelectorAll('tbody').forEach(body=>{
  if(!body.children.length){const tr=document.createElement('tr'),td=document.createElement('td');td.className='empty';td.colSpan=20;td.textContent='No evidence recorded for this section.';tr.appendChild(td);body.appendChild(tr)}
});
</script></body></html>
EOF
  } > "$REPORT_PATH"
}

show_banner
log "Starting SAPstract $VERSION host-local audit"
collect_host_metadata
collect_processes
collect_services
collect_sockets
discover_systems
scan_known_paths
scan_profiles_and_acls
scan_ssfs
scan_tools
scan_security_artifacts
build_topology_model
build_assessment_catalog
build_section_scores

if ((TRUNCATED_SCANS > 0)); then
  add_coverage "Collection limits" "partial" "$TRUNCATED_SCANS scan(s) reached --max-files=$MAX_FILES"
fi
if ((SAP_EVIDENCE_COUNT == 0)); then
  add_coverage "SAP footprint" "none observed" "No SAP-specific service, process, socket, standard path, SSFS artifact, profile, or tool was found in the inspected scope"
fi

generate_json
generate_html

ok "Audit complete"
printf 'HTML report: %s\nJSON report: %s\nRisk score: %s/100\n' "$REPORT_PATH" "$JSON_PATH" "$RISK_SCORE"
