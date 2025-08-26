#WinnyTaam

function Write-Log   { param($msg) Write-Host "[SAPstract] $msg" }
function Write-Warn  { param($msg) Write-Host "[SAPstract] [!] $msg" }
function Write-Found { param($msg) Write-Host "[SAPstract] [FOUND] $msg" }
function Write-Match { param($msg) Write-Host "[SAPstract] [PORT] $msg" }

try {
    $principal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warn "Not running as Administrator; run elevated if possible"
    }
} catch {
    Write-Warn "Privilege check failed: $($_.Exception.Message)"
}

$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' }
if (-not $drives) {
    Write-Warn "No filesystem drives found."
} else {
    Write-Log "[*] Probing drive roots for placeholder directory: \usr\sap"
    foreach ($d in $drives) {
        $root = $d.Root.TrimEnd('\')
        $p_usr_sap = Join-Path $root 'usr\sap'
        if (Test-Path -LiteralPath $p_usr_sap -PathType Container) {
            Write-Found $p_usr_sap
        }
    }
    Write-Log "[*] Directory probe complete."
}

function Add-Rule { param([string]$Pattern, [string]$Label) [pscustomobject]@{ Regex=[regex]$Pattern; Label=$Label } }

$rules = @(
    # NetWeaver ABAP + ICM
    (Add-Rule '^(80\d{2})$'  'NW ABAP/ICM HTTP 80NN'),
    (Add-Rule '^(443\d{2})$' 'NW ABAP/ICM HTTPS 443NN'),
    (Add-Rule '^(81\d{2})$'  'NW ABAP/ICM HTTP 81NN'),
    (Add-Rule '^(444\d{2})$' 'NW ABAP/ICM HTTPS 444NN'),
    (Add-Rule '^(32\d{2})$'  'NW Dispatcher 32NN'),
    (Add-Rule '^(33\d{2})$'  'NW Gateway 33NN'),
    (Add-Rule '^(48\d{2})$'  'NW Secure GW 48NN'),
    (Add-Rule '^(36\d{2})$'  'NW Msg Server 36NN'),

    # NetWeaver JAVA
    (Add-Rule '^5\d{2}00$'   'NW JAVA HTTP 5NN00'),
    (Add-Rule '^5\d{2}01$'   'NW JAVA HTTPS 5NN01'),
    (Add-Rule '^5\d{2}05$'   'NW JAVA P4/HTTP 5NN05'),
    (Add-Rule '^5\d{2}06$'   'NW JAVA P4/HTTPS 5NN06'),
    (Add-Rule '^5\d{2}02$'   'NW JAVA IIOP Init 5NN02'),
    (Add-Rule '^5\d{2}03$'   'NW JAVA IIOP SSL 5NN03'),
    (Add-Rule '^5\d{2}04$'   'NW JAVA P4 Remoting 5NN04'),
    (Add-Rule '^5\d{2}07$'   'NW JAVA IIOP 5NN07'),
    (Add-Rule '^5\d{2}08$'   'NW JAVA Telnet 5NN08'),
    (Add-Rule '^5\d{2}10$'   'NW JAVA JMS 5NN10'),

    # Admin Services
    (Add-Rule '^1128$'       'SAPHostControl 1128'),
    (Add-Rule '^1129$'       'SAPHostControlS 1129'),
    (Add-Rule '^5\d{2}13$'   'SAP Start Service 5NN13'),
    (Add-Rule '^5\d{2}14$'   'SAP Start Service 5NN14'),

    # SAP IGS
    (Add-Rule '^4\d{2}80$'   'IGS HTTP 4NN80'),
    (Add-Rule '^4\d{2}00$'   'IGS Multiplexer 4NN00'),
    (Add-Rule '^4\d{2}01$'   'IGS Portwatcher 4NN01'),
    (Add-Rule '^4\d{2}02$'   'IGS Portwatcher 4NN02'),

    # Install Tools
    (Add-Rule '^5\d{2}19$'   'SDM HTTP 5NN19'),
    (Add-Rule '^5\d{2}17$'   'SDM Admin 5NN17'),
    (Add-Rule '^5\d{2}18$'   'SDM GUI 5NN18'),
    (Add-Rule '^21212$'      'SAPinst HTTP UI 21212'),
    (Add-Rule '^21213$'      'SAPinst HTTP UI 21213'),
    (Add-Rule '^59975$'      'SAPinst AS400 59975'),
    (Add-Rule '^59976$'      'SAPinst AS400 59976'),
    (Add-Rule '^4238$'       'Upgrade Monitor 4238'),
    (Add-Rule '^4239$'       'Upgrade UA HTTP 4239'),
    (Add-Rule '^4240$'       'Upgrade R3up 4240'),
    (Add-Rule '^4241$'       'Upgrade UA 4241'),

    # Utilities
    (Add-Rule '^3299$'       'SAProuter 3299'),
    (Add-Rule '^3298$'       'SAP niping 3298'),
    (Add-Rule '^515$'        'SAPlpd 515'),

    # ITS
    (Add-Rule '^3950$'       'ITS HTTP 3950'),
    (Add-Rule '^3951$'       'ITS HTTP 3951'),
    (Add-Rule '^3954$'       'ITS HTTP 3954'),
    (Add-Rule '^3964$'       'ITS HTTP 3964'),

    # Databases
    (Add-Rule '^1433$'       'MSSQL 1433'),
    (Add-Rule '^1527$'       'Oracle 1527'),
    (Add-Rule '^50000$'      'DB6 50000'),
    (Add-Rule '^4402$'       'DB2 4402'),
    (Add-Rule '^7200$'       'MaxDB 7200'),
    (Add-Rule '^7210$'       'MaxDB 7210'),
    (Add-Rule '^7269$'       'MaxDB 7269'),
    (Add-Rule '^7270$'       'MaxDB 7270'),
    (Add-Rule '^7275$'       'MaxDB 7275'),

    # Common Internet Services
    (Add-Rule '^80$'         'HTTP 80'),
    (Add-Rule '^443$'        'HTTPS 443'),
    (Add-Rule '^21$'         'FTP 21'),
    (Add-Rule '^22$'         'SSH 22'),
    (Add-Rule '^23$'         'Telnet 23'),
    (Add-Rule '^25$'         'SMTP 25'),
    (Add-Rule '^110$'        'POP 110'),
    (Add-Rule '^3389$'       'RDP 3389')
)

$procMap = @{}
Get-Process | ForEach-Object { $procMap[$_.Id] = $_.ProcessName }

$svcByPid = @{}
try {
    Get-CimInstance Win32_Service | ForEach-Object {
        if ($_.ProcessId -and $_.ProcessId -gt 0) {
            if (-not $svcByPid.ContainsKey($_.ProcessId)) { $svcByPid[$_.ProcessId] = @() }
            $svcByPid[$_.ProcessId] += ("{0} ({1})" -f $_.Name, $_.DisplayName)
        }
    }
} catch {
    Write-Warn "Service enumeration limited: $($_.Exception.Message)"
}

function Split-EndPoint {
    param([string]$ep)
    if (-not $ep) { return @('','') }
    $clean = $ep -replace '^\[|\]',''
    $lastColon = $clean.LastIndexOf(':')
    if ($lastColon -lt 0) { return @($clean,'') }
    $addr = $clean.Substring(0,$lastColon)
    $port = $clean.Substring($lastColon+1)
    return @($addr,$port)
}

function Classify-Port {
    param([string]$portStr)
    if (-not $portStr) { return $null }
    if ($portStr -notmatch '^\d+$') { return $null }
    foreach ($r in $rules) {
        if ($r.Regex.IsMatch($portStr)) { return $r.Label }
    }
    return $null
}

Write-Log "[*] Scanning netstat for SAP/infra ports..."
$lines = @()
$lines += netstat -ano -p tcp 2>$null
$lines += netstat -ano -p udp 2>$null

Write-Host "[SAPstract] [PORT] $( '{0,-24} {1,-4} {2,-39} {3,-39} {4}' -f 'LABEL','PROT','LOCAL','REMOTE','EXTRA' )"

foreach ($line in $lines) {
    if ($line -match '^(Proto|Active Connections)') { continue }
    $cols = ($line -split '\s+') | Where-Object { $_ -ne '' }
    if ($cols.Count -lt 4) { continue }

    $proto = $cols[0].ToUpperInvariant()
    if ($proto -notin @('TCP','UDP')) { continue }

    if ($proto -eq 'TCP') {
        if ($cols.Count -lt 5) { continue }
        $local   = $cols[1]
        $foreign = $cols[2]
        $state   = $cols[3]
        $procId  = [int]$cols[-1]
    } else {
        $local   = $cols[1]
        if ($cols.Count -gt 3) { $foreign = $cols[2] } else { $foreign = '*:*' }
        $state   = 'UDP'
        $procId  = [int]$cols[-1]
    }

    $laddr,$lport = Split-EndPoint -ep $local
    $raddr,$rport = Split-EndPoint -ep $foreign

    $hitLocal  = Classify-Port $lport
    $hitRemote = Classify-Port $rport
    if (-not $hitLocal -and -not $hitRemote) { continue }

    $label = if ($hitLocal) { $hitLocal } else { $hitRemote }

    $extra = ''
    if ($svcByPid.ContainsKey($procId) -and $svcByPid[$procId].Count -gt 0) {
        $pname = if ($procMap.ContainsKey($procId)) { $procMap[$procId] } else { (Get-Process -Id $procId -ErrorAction SilentlyContinue).ProcessName }
        if (-not $pname) { $pname = "-" }
        $svcList = ($svcByPid[$procId] -join '; ')
        $extra = ("pid={0} proc={1} svc={2}" -f $procId, $pname, $svcList)
    }

    Write-Match ( '{0,-24} {1,-4} {2,-39} {3,-39} {4}' -f $label, $proto, $local, $foreign, $extra )
}

Write-Log "[*] Done."

