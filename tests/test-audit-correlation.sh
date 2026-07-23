#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/sapstract-correlation.XXXXXXXX")
trap 'rm -rf -- "$test_root"' EXIT

fixture="$test_root/root"
mock_bin="$test_root/bin"
output="$test_root/output"
mkdir -p "$fixture/usr/sap/ABC/D00" "$fixture/usr/sap/ABC/SYS/profile"
mkdir -p "$fixture/home/test/project/data" "$mock_bin" "$output"
printf '%s\n' '# ordinary source artifact' > "$fixture/home/test/project/audit.h"
printf '%s\n' 'not SAP' > "$fixture/home/test/project/example-webgui.yaml"
printf '%s\n' 'login/min_password_lng = 12' > "$fixture/usr/sap/ABC/SYS/profile/DEFAULT.PFL"

cat > "$mock_bin/ps" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' \
  '101 user users python python whatsapp-worker.py' \
  '200 abcadm sapsys sapstartsrv sapstartsrv pf=/usr/sap/ABC/SYS/profile/ABC_D00_host' \
  '300 sybabc sapsys dataserver /sybase/ABC/ASE-16_0/bin/dataserver -sABC' \
  '301 sybxyz sybase dataserver /sybase/XYZ/ASE-16_0/bin/dataserver -sXYZ'
EOF

cat > "$mock_bin/systemctl" <<'EOF'
#!/usr/bin/env bash
case "${1-}" in
  list-units)
    printf '%s\n' \
      'WhatsAppUpdater.service loaded active running WhatsApp Update Service' \
      'SAPABC_00.service loaded active running SAP ABC Instance 00'
    ;;
  show)
    printf '%s\n' ''
    ;;
esac
EOF

cat > "$mock_bin/ss" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' \
  'tcp LISTEN 0 128 0.0.0.0:8000 0.0.0.0:* users:(("python",pid=101,fd=3))' \
  'tcp LISTEN 0 128 0.0.0.0:3200 0.0.0.0:*' \
  'tcp LISTEN 0 128 0.0.0.0:3301 0.0.0.0:*' \
  'tcp LISTEN 0 128 127.0.0.1:55555 0.0.0.0:* users:(("sapstartsrv",pid=200,fd=4))' \
  'tcp ESTAB 0 0 127.0.0.1:4901 127.0.0.1:40402' \
  'tcp ESTAB 0 0 127.0.0.1:4901 127.0.0.1:40403 users:(("dataserver",pid=300,fd=5))'
EOF

chmod +x "$mock_bin/ps" "$mock_bin/systemctl" "$mock_bin/ss"
sed 's/\r$//' "$repo_root/SAPaudit.sh" > "$test_root/SAPaudit.sh"

PATH="$mock_bin:/usr/bin:/bin" bash "$test_root/SAPaudit.sh" \
  --root "$fixture" --output-dir "$output" --quiet --no-color >/dev/null

report=$(find "$output" -maxdepth 1 -type f -name '*.json' -print -quit)
[[ -n "$report" ]]
if ! jq -e '
  .summary.systems == 1 and
  .summary.services == 1 and
  .summary.processes == 2 and
  .summary.sockets == 4 and
  .summary.socket_candidates == 1 and
  ([.services[].name] == ["SAPABC_00.service"]) and
  ([.processes[].name] | sort == ["dataserver", "sapstartsrv"]) and
  ([.sockets[] | select(.local == "0.0.0.0:3200" and .confidence == "medium")] | length == 1) and
  ([.sockets[] | select(.local == "127.0.0.1:55555" and .confidence == "high")] | length == 1) and
  ([.sockets[] | select(.local == "127.0.0.1:4901" and .classification == "SAP ASE Data Server" and .confidence == "medium")] | length == 1) and
  ([.sockets[] | select(.remote == "127.0.0.1:40403" and .classification == "SAP ASE Data Server" and .confidence == "high")] | length == 1) and
  ([.socket_candidates[] | select(.local == "0.0.0.0:8000")] | length == 0) and
  ([.socket_candidates[] | select(.local == "0.0.0.0:3301")] | length == 1) and
  ([.paths[] | select(.path | test("audit[.]h|example-webgui[.]yaml|/project/data$"))] | length == 0)
' "$report" >/dev/null; then
  jq '{summary, systems, services, processes, sockets, socket_candidates, paths}' "$report" >&2
  exit 1
fi

printf '%s\n' 'Bash correlation regression: OK'
