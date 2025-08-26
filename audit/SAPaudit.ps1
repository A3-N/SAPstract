
param(
  [string]$LogPath = $null,
  [switch]$ShowEstablished
)

function Append-Log {
  param([string]$Line)
  if ($null -ne $LogPath -and $LogPath -ne '') {
    try {
      $dir = Split-Path -Path $LogPath -Parent
      if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
      }
      Add-Content -Path $LogPath -Value $Line
    } catch {
      if (-not (Get-Variable -Name SAPstractLogWarned -Scope Script -ErrorAction SilentlyContinue)) {
        $script:SAPstractLogWarned = $true
        Write-Host "[SAPstract]" -ForegroundColor Yellow -NoNewline
        Write-Host " Logging disabled: $($_.Exception.Message)"
      }
    }
  }
}

function Write-Log      { param([string]$Msg) Write-Host "[SAPstract]" -ForegroundColor Cyan  -NoNewline; Write-Host " $Msg";   Append-Log $Msg }
function Write-Success  { param([string]$Msg) Write-Host "[SAPstract]" -ForegroundColor Green -NoNewline; Write-Host " $Msg";   Append-Log $Msg }
function Write-Warn     { param([string]$Msg) Write-Host "[SAPstract]" -ForegroundColor Yellow -NoNewline; Write-Host " $Msg";  Append-Log $Msg }
function Write-ErrorMsg { param([string]$Msg) Write-Host "[SAPstract]" -ForegroundColor Red   -NoNewline; Write-Host " $Msg";   Append-Log $Msg }

function Test-IsAdmin {
  try {
    $current   = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    Write-Warn "Admin check failed: $($_.Exception.Message)"
    return $false
  }
}

function Add-Rule($pattern, $label) { @{ Regex = $pattern; Label = $label } }

function Get-PortRules {
  @(
    # NetWeaver ABAP + ICM
    (Add-Rule '^(80\d{2})$'  'NW ABAP/ICM HTTP'),  # 80NN
    (Add-Rule '^(443\d{2})$' 'NW ABAP/ICM HTTPS'), # 443NN
    (Add-Rule '^(81\d{2})$'  'NW ABAP/ICM HTTP'),  # 81NN
    (Add-Rule '^(444\d{2})$' 'NW ABAP/ICM HTTPS'), # 444NN
    (Add-Rule '^(32\d{2})$'  'NW Dispatcher'),     # 32NN
    (Add-Rule '^(33\d{2})$'  'NW Gateway'),        # 33NN
    (Add-Rule '^(48\d{2})$'  'NW Secure GW'),      # 48NN
    (Add-Rule '^(36\d{2})$'  'NW Msg Server'),     # 36NN

    # NetWeaver JAVA
    (Add-Rule '^5\d{2}00$'   'NW JAVA HTTP'),      # 5NN00
    (Add-Rule '^5\d{2}01$'   'NW JAVA HTTPS'),     # 5NN01
    (Add-Rule '^5\d{2}05$'   'NW JAVA P4/HTTP'),   # 5NN05
    (Add-Rule '^5\d{2}06$'   'NW JAVA P4/HTTPS'),  # 5NN06
    (Add-Rule '^5\d{2}02$'   'NW JAVA IIOP Init'), # 5NN02
    (Add-Rule '^5\d{2}03$'   'NW JAVA IIOP SSL'),  # 5NN03
    (Add-Rule '^5\d{2}04$'   'NW JAVA P4 Remote'), # 5NN04
    (Add-Rule '^5\d{2}07$'   'NW JAVA IIOP'),      # 5NN07
    (Add-Rule '^5\d{2}08$'   'NW JAVA Telnet'),    # 5NN08
    (Add-Rule '^5\d{2}10$'   'NW JAVA JMS'),       # 5NN10

    # Admin Services
    (Add-Rule '^1128$'       'SAPHostControl'),
    (Add-Rule '^1129$'       'SAPHostControlS'),
    (Add-Rule '^5\d{2}13$'   'SAP Start Service'), # 5NN13
    (Add-Rule '^5\d{2}14$'   'SAP Start Service'), # 5NN14

    # SAP IGS (Internet Graphics Service)
    (Add-Rule '^4\d{2}80$'   'IGS HTTP'),          # 4NN80
    (Add-Rule '^4\d{2}00$'   'IGS Multiplexer'),   # 4NN00
    (Add-Rule '^4\d{2}01$'   'IGS Portwatcher'),   # 4NN01
    (Add-Rule '^4\d{2}02$'   'IGS Portwatcher'),   # 4NN02

    # Install Tools
    (Add-Rule '^5\d{2}19$'   'SDM HTTP'),          # 5NN19
    (Add-Rule '^5\d{2}17$'   'SDM Admin'),         # 5NN17
    (Add-Rule '^5\d{2}18$'   'SDM GUI'),           # 5NN18
    (Add-Rule '^21212$'      'SAPinst HTTP UI'),
    (Add-Rule '^21213$'      'SAPinst HTTP UI'),
    (Add-Rule '^59975$'      'SAPinst AS400'),
    (Add-Rule '^59976$'      'SAPinst AS400'),
    (Add-Rule '^4238$'       'Upgrade Monitor'),
    (Add-Rule '^4239$'       'Upgrade UA HTTP'),
    (Add-Rule '^4240$'       'Upgrade R3up'),
    (Add-Rule '^4241$'       'Upgrade UA'),

    # Utilities
    (Add-Rule '^3299$'       'SAProuter'),
    (Add-Rule '^3298$'       'SAP niping'),
    (Add-Rule '^515$'        'SAPlpd'),

    # ITS
    (Add-Rule '^3950$'       'ITS HTTP'),
    (Add-Rule '^3951$'       'ITS HTTP'),
    (Add-Rule '^3954$'       'ITS HTTP'),
    (Add-Rule '^3964$'       'ITS HTTP'),

    # Databases
    (Add-Rule '^1433$'       'MSSQL'),
    (Add-Rule '^1527$'       'Oracle'),
    (Add-Rule '^50000$'      'DB6'),
    (Add-Rule '^4402$'       'DB2'),
    (Add-Rule '^7200$'       'MaxDB'),
    (Add-Rule '^7210$'       'MaxDB'),
    (Add-Rule '^7269$'       'MaxDB'),
    (Add-Rule '^7270$'       'MaxDB'),
    (Add-Rule '^7275$'       'MaxDB'),

    # Common Internet Services
    (Add-Rule '^80$'         'HTTP'),
    (Add-Rule '^443$'        'HTTPS'),
    (Add-Rule '^21$'         'FTP'),
    (Add-Rule '^22$'         'SSH'),
    (Add-Rule '^23$'         'Telnet'),
    (Add-Rule '^25$'         'SMTP'),
    (Add-Rule '^110$'        'POP'),
    (Add-Rule '^3389$'       'RDP')
  )
}

function Get-ProcMap {
  $map = @{}
  try { Get-Process | ForEach-Object { $map[$_.Id] = $_.ProcessName } } catch {}
  $map
}

function Get-ServiceMap {
  $svcmap = @{}
  try {
    Get-CimInstance -ClassName Win32_Service | ForEach-Object {
      $svcPid = $_.ProcessId
      if ($svcPid -gt 0) {
        if (-not $svcmap.ContainsKey($svcPid)) { $svcmap[$svcPid] = @() }
        $svcmap[$svcPid] += ($_.Name + "(" + $_.DisplayName + ")")
      }
    }
  } catch {
    Write-Warn "Service enumeration failed: $($_.Exception.Message)"
  }
  $svcmap
}

function Split-EndPoint {
  param([string]$ep)
  $addr = $ep; $port = $null
  if ($ep -match '^\[(?<v6>.+)\]:(?<p>\d+)$') {
    $addr = $Matches.v6; $port = $Matches.p
  } elseif ($ep -match '^(?<h>.+?):(?<p>\d+)$') {
    $addr = $Matches.h;  $port = $Matches.p
  }
  ,$addr, $port
}

function Classify-Port {
  param([string]$p, [array]$Rules)
  if (-not $p -or -not ($p -match '^\d+$')) { return $null }
  foreach ($r in $Rules) { if ($p -match $r.Regex) { return $r.Label } }
  $null
}

function Emit-NetstatMatches {
  $rules   = Get-PortRules
  $procmap = Get-ProcMap
  $svcmap  = Get-ServiceMap

  Write-Log "Collecting sockets via netstat..."
  $tcp = netstat -ano -p tcp 2>$null
  $udp = netstat -ano -p udp 2>$null
  $lines = @($tcp + $udp)

  $hdr = ("{0,-35} {1,-5} {2,-28} {3,-28} {4}" -f "LABEL","PROT","LOCAL","REMOTE","EXTRA")
  Write-Success $hdr

  foreach ($line in $lines) {
    $t = $line.Trim()
    if (-not $t) { continue }
    if ($t -match '^(Proto|Active Connections)') { continue }

    $parts = ($t -split '\s+')
    if ($parts.Count -lt 4) { continue }

    $proto = $parts[0].ToUpper()
    if ($proto -notin @('TCP','UDP')) { continue }

    $local   = $parts[1]
    $foreign = $parts[2]

    $state  = $null
    $procId = $null
    if ($proto -eq 'TCP') {
      if ($parts.Count -lt 5) { continue }
      $state = $parts[3]
      if ($parts[4] -match '^\d+$') { $procId = [int]$parts[4] } else { continue }
    } else {
      $state = 'UDP'
      if ($parts[-1] -match '^\d+$') { $procId = [int]$parts[-1] } else { continue }
    }

    $null, $lport = Split-EndPoint $local
    $null, $rport = Split-EndPoint $foreign

    $lp = Classify-Port $lport $rules  # local match label (if any)
    if (-not $lp) { continue }

    if ($proto -eq 'TCP') {
      $st = ($state -as [string]).Trim().ToUpperInvariant()
      if ($st -eq 'LISTENING') {
        if (-not $lp) { continue }
      } elseif ($st -eq 'ESTABLISHED') {
      } else {
        continue
      }
    }

    $label = if ($lp) { $lp } else { $rp }

    $pname = $procmap[$procId]
    if (-not $pname) { try { $pname = (Get-Process -Id $procId -ErrorAction Stop).ProcessName } catch { $pname = $null } }
    $svc = $null
    if ($svcmap.ContainsKey($procId)) { $svc = ($svcmap[$procId] -join "; ") }

    $extra = "pid=$procId"
    if ($pname) { $extra += " proc=$pname" }
    if ($svc)   { $extra += " svc=$svc"   }

    $out = ("{0,-35} {1,-5} {2,-28} {3,-28} {4}" -f $label,$proto,$local,$foreign,$extra)
    Write-Success $out
  }
}

function Probe-SAPRoots {
  Write-Log "Scanning mounted filesystem drives for \usr\sap ..."
  $fsDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -match '^[A-Za-z]$' }
  foreach ($d in $fsDrives) {
    $drive = ($d.Name + ':')
    try {
      $path = Join-Path -Path $drive -ChildPath 'usr\sap'
      if ($null -ne $path -and (Test-Path -LiteralPath $path)) {
        Write-Success "$path"
      }
    } catch {
      Write-Warn "Drive $($d.Name) scan error: $($_.Exception.Message)"
    }
  }
}

$null = Test-IsAdmin | ForEach-Object {
  if (-not $_) { Write-Warn "Not running as Administrator; run elevated if possible" }
}

Write-Log "Starting audit"
Emit-NetstatMatches -ShowEstablished:$ShowEstablished
Probe-SAPRoots
Write-Log "Done."

