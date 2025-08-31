Set-StrictMode -Version Latest

$script:OutDir   = if ($env:TEMP) { $env:TEMP } else { [IO.Path]::GetTempPath() }
$script:Stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:BaseName = "SAPaudit_$($script:Stamp)"
$script:NDJPath  = Join-Path $script:OutDir ("$($script:BaseName).ndjson")

function Write-Info     { param([string]$Msg) Write-Host "[SAPstract]" -ForegroundColor Cyan    -NoNewline;  Write-Host " $Msg" }
function Write-Success  { param([string]$Msg) Write-Host "[SAPstract]" -ForegroundColor Green   -NoNewline;  Write-Host " $Msg" }
function Write-Warn     { param([string]$Msg) Write-Host "[SAPstract]" -ForegroundColor Yellow  -NoNewline;  Write-Host " $Msg" }
function Write-ErrorMsg { param([string]$Msg) Write-Host "[SAPstract]" -ForegroundColor Red     -NoNewline;  Write-Host " $Msg" }

function Write-NDJSON {
  param([hashtable]$Obj)
  try {
    $json = $Obj | ConvertTo-Json -Depth 6 -Compress
    Add-Content -Path $script:NDJPath -Value $json -Encoding UTF8
  } catch {
    Write-ErrorMsg "Failed to write NDJSON: $($_.Exception.Message)"
  }
}

function Test-IsAdmin {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    Write-ErrorMsg "Admin check failed: $($_.Exception.Message)"
    return $false
  }
}

$IsAdmin = Test-IsAdmin
if (-not $IsAdmin) {
  Write-Warn "Not running as Administrator."

  Write-Host "[SAPstract]" -ForegroundColor Yellow -NoNewline
  Write-Host " Continue anyway? (y/n): " -NoNewline

  $resp = [Console]::ReadLine()

  if ($resp -notmatch '^[Yy]$') {
    Write-Warn "Exiting..."
    exit 1
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

    # SAP IGS
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

function Get-ProcMap { $m=@{}; try { Get-Process | ForEach-Object { $m[$_.Id] = $_.ProcessName } } catch {}; $m }
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
  } catch { Write-ErrorMsg "Service enumeration failed: $($_.Exception.Message)" }
  $svcmap
}
function Split-EndPoint {
  param([string]$ep)
  $addr = $ep; $port = $null
  if ($ep -match '^\[(?<v6>.+)\]:(?<p>\d+)$') { $addr = $Matches.v6; $port = $Matches.p }
  elseif ($ep -match '^(?<h>.+?):(?<p>\d+)$') { $addr = $Matches.h;  $port = $Matches.p }
  ,$addr, $port
}
function Classify-Port { param([string]$p, [array]$Rules) if (-not $p -or -not ($p -match '^\d+$')) { return $null }; foreach ($r in $Rules) { if ($p -match $r.Regex) { return $r.Label } }; $null }

function Emit-NetstatMatches {
  $rules   = Get-PortRules
  $procmap = Get-ProcMap
  $svcmap  = Get-ServiceMap

  Write-Info "Collecting sockets via netstat..."
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

    $lhost,$lport = Split-EndPoint $local
    $rhost,$rport = Split-EndPoint $foreign

    $lp = Classify-Port $lport $rules
    if (-not $lp) { continue }

    if ($proto -eq 'TCP') {
      $st = ($state -as [string]).Trim().ToUpperInvariant()
      if ($st -notin @('LISTENING','ESTABLISHED')) { continue }
    }

    $pname = $procmap[$procId]
    if (-not $pname) { try { $pname = (Get-Process -Id $procId -ErrorAction Stop).ProcessName } catch { $pname = $null } }
    $svc = $null
    if ($svcmap.ContainsKey($procId)) { $svc = $svcmap[$procId] }

    $extra = "pid=$procId"
    if ($pname) { $extra += " proc=$pname" }
    if ($svc)   { $extra += " svc=$($svc -join '; ')" }
    $out = ("{0,-35} {1,-5} {2,-28} {3,-28} {4}" -f $lp,$proto,$local,$foreign,$extra)
    Write-Success $out

    Write-NDJSON @{
      type        = 'socket'
      label       = $lp
      proto       = $proto
      state       = $state
      local_addr  = $lhost
      local_port  = $lport
      remote_addr = $rhost
      remote_port = $rport
      pid         = $procId
      process     = $pname
      services    = $svc
    }
  }
}

function Format-Arrow { param([int]$Depth)
  if ($Depth -le 0) { return '' }
  $hy = 4 * $Depth - 2
  return ('-' * $hy) + '> '
}
function InfoD { param([string]$Msg, [int]$Depth = 1) Write-Info ("{0}{1}" -f (Format-Arrow $Depth), $Msg) }
function WarnD { param([string]$Msg, [int]$Depth = 1) Write-Warn ("{0}{1}" -f (Format-Arrow $Depth), $Msg) }


# Sub-check 
function SubCheck-SapUsr {
  param([string]$RootPath)

  $sidRe       = '^[A-Z][A-Z0-9]{2}$'
  $reserved    = @('SYS','TRANS','SUM','SAPHOSTCTRL','SAPHOSTAGENT','TOOLS')
  $instanceRe  = '^(?:D|J)\d{2}$|^(?:DVEBMGS)\d{2}$|^(?:ASCS|SCS|ERS|SMDA|HDB|PAS|AAS)\d{2}$'

  $children = @(Get-ChildItem -LiteralPath $RootPath -Directory -Force -ErrorAction SilentlyContinue)

  foreach ($c in $children) {
    $nameU = $c.Name.ToUpperInvariant()

    if ($reserved -contains $nameU) { continue }
    if ($nameU -match $instanceRe)  { continue }
    if ($nameU -notmatch $sidRe)    { continue }

    $sidPath    = $c.FullName
    $sysRoot    = Join-Path $sidPath 'SYS'
    $profileDir = Join-Path $sysRoot 'profile'
    $globalDir  = Join-Path $sysRoot 'global'
    $rsecRoot   = Join-Path $globalDir 'security\rsecssfs'
    $keyDir     = Join-Path $rsecRoot  'key'
    $dataDir    = Join-Path $rsecRoot  'data'

    $instDirs  = @(Get-ChildItem -LiteralPath $sidPath -Directory -Force -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -match $instanceRe })
    $instNames = @($instDirs | ForEach-Object { $_.Name } | Sort-Object)

    $hasSys = $false; $hasProfile = $false; $hasGlobal = $false
    $hasRsec = $false; $hasKeyDir = $false; $hasDataDir = $false
    try { $hasSys = Test-Path -LiteralPath $sysRoot -PathType Container } catch {}

    if ($hasSys) {
      try { $hasProfile = Test-Path -LiteralPath $profileDir -PathType Container } catch {}
      try { $hasGlobal  = Test-Path -LiteralPath $globalDir  -PathType Container } catch {}
      if ($hasGlobal) {
        try { $hasRsec    = Test-Path -LiteralPath $rsecRoot -PathType Container } catch {}
        if ($hasRsec) {
          try { $hasKeyDir  = Test-Path -LiteralPath $keyDir  -PathType Container } catch {}
          try { $hasDataDir = Test-Path -LiteralPath $dataDir -PathType Container } catch {}
        }
      }
    }

    $isValid = $hasProfile -or ($instNames.Count -gt 0)

    if ($isValid) {
      Write-Success ("SID {0} @ {1}" -f $nameU, $sidPath)

      if ($instNames.Count -gt 0) {
        InfoD ("Instances ({0}): {1}" -f $instNames.Count, ($instNames -join ', ')) 1
      }

      if (-not $hasSys) {
        WarnD "SYS missing (often centralized/not mounted); skipping SYS checks" 1
      } else {
        InfoD "SYS present" 1

        $profileState = if ($hasProfile) { 'present' } else { 'missing' }
        $globalState  = if ($hasGlobal)  { 'present' } else { 'missing' }
        InfoD ("profile: {0}" -f $profileState) 2
        InfoD ("global: {0}"  -f $globalState)  2

        if ($hasGlobal) {
          if ($hasRsec) {
            InfoD "global\security\rsecssfs: present" 3

            $keys  = @()
            $datas = @()
            if ($hasKeyDir) {
              $keys = @(Get-ChildItem -LiteralPath $keyDir -File -Force -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -match '^SSFS_.+\.KEY$' } | ForEach-Object { $_.Name } | Sort-Object)
              if ($keys.Count -gt 0) { InfoD ("key files ({0}): {1}" -f $keys.Count, ($keys -join ', ')) 4 }
              else { WarnD "key directory present but no SSFS_*.KEY files" 3 }
            } else {
              WarnD "key directory missing" 3
            }

            if ($hasDataDir) {
              $datas = @(Get-ChildItem -LiteralPath $dataDir -File -Force -ErrorAction SilentlyContinue |
                         Where-Object { $_.Name -match '^SSFS_.+\.DAT$' } | ForEach-Object { $_.Name } | Sort-Object)
              if ($datas.Count -gt 0) { InfoD ("data files ({0}): {1}" -f $datas.Count, ($datas -join ', ')) 4 }
              else { WarnD "data directory present but no SSFS_*.DAT files" 3 }
            } else {
              WarnD "data directory missing" 3
            }

            Write-NDJSON @{
              type                 = 'sid'
              sid                  = $nameU
              path                 = $sidPath
              instances            = $instNames
              has_sys              = $hasSys
              has_sys_profile      = $hasProfile
              has_sys_global       = $hasGlobal
              rsecssfs_present     = $hasRsec
              rsecssfs_key_files   = $keys
              rsecssfs_data_files  = $datas
            }
          } else {
            WarnD "global\security\rsecssfs missing" 3
            Write-NDJSON @{
              type            = 'sid'
              sid             = $nameU
              path            = $sidPath
              instances       = $instNames
              has_sys         = $hasSys
              has_sys_profile = $hasProfile
              has_sys_global  = $hasGlobal
              rsecssfs_present= $false
            }
          }
        } else {
          Write-NDJSON @{
            type            = 'sid'
            sid             = $nameU
            path            = $sidPath
            instances       = $instNames
            has_sys         = $hasSys
            has_sys_profile = $hasProfile
            has_sys_global  = $false
            rsecssfs_present= $false
          }
        }
      }
    } else {
      Write-Warn ("Candidate SID-like folder {0} (no profile/instances)" -f $nameU)
      Write-NDJSON @{
        type   = 'sid_candidate'
        sid    = $nameU
        path   = $sidPath
        reason = 'no_profile_or_instances'
      }
    }
  }
}

function SubCheck-Sapinst {
  param([string]$RootPath)
  # TODO: scan for installer logs, control files, etc.
  # $files = Get-ChildItem -LiteralPath $RootPath -File -Force -ErrorAction SilentlyContinue
  # foreach ($f in $files) {
  #   Write-NDJSON @{ type='sapinst_sub'; parent=$RootPath; file=$f.Name; size=$f.Length; path=$f.FullName }
  # }
}

# (only if not already defined elsewhere)
if (-not (Get-Variable -Name PathSpecs -Scope Script -ErrorAction SilentlyContinue)) {
  $script:PathSpecs = @(
    @{
      Key       = 'sap_usr'
      ChildPath = 'usr\sap'
      SubCheck  = ${function:SubCheck-SapUsr}
    },
    @{
      Key       = 'sapinst_instdir'
      ChildPath = 'Program Files\sapinst_instdir'
      SubCheck  = ${function:SubCheck-Sapinst}
    }
  )
}

function Probe-ConfiguredPaths {
  param([array]$Specs)

  Write-Info "Scanning mounted filesystem drives for configured SAP paths..."
  $fsDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -match '^[A-Za-z]$' }

  foreach ($spec in $Specs) {
    $key      = $spec.Key
    $child    = $spec.ChildPath
    $subCheck = $spec.SubCheck

    foreach ($d in $fsDrives) {
      $drive = ($d.Name + ':')
      try {
        $candidate = Join-Path -Path $drive -ChildPath $child
        if ($null -ne $candidate -and (Test-Path -LiteralPath $candidate)) {
          Write-Success $candidate
          Write-NDJSON @{
            type  = 'path'
            key   = $key
            drive = $drive
            child = $child
            path  = $candidate
          }

          if ($subCheck) {
            try { & $subCheck $candidate }
            catch {
              $msg = $_.Exception.Message
              Write-ErrorMsg ("SubCheck for '{0}' failed on {1}: {2}" -f $key, $candidate, $msg)
              Write-NDJSON @{ type='subcheck_error'; key=$key; path=$candidate; error=$msg }
            }
          }
        }
      } catch {
        $msg = $_.Exception.Message
        Write-Warn ("Drive {0} scan error for '{1}/{2}': {3}" -f $d.Name, $key, $child, $msg)
        Write-NDJSON @{
          type  = 'probe_error'
          key   = $key
          drive = $drive
          child = $child
          error = $msg
        }
      }
    }
  }
}

function Probe-SAPRoots {
  if (-not $script:PathSpecs) { $script:PathSpecs = @() }
  Probe-ConfiguredPaths -Specs $script:PathSpecs
}

Write-NDJSON @{
  type        = 'meta'
  phase       = 'start'
  timestamp   = (Get-Date).ToString('s')
  host        = $env:COMPUTERNAME
  username    = $env:USERNAME
  is_admin    = [bool]$IsAdmin
  ndjson_path = $script:NDJPath
  version     = '1.2-ndjson-only'
}

Write-Info "Starting audit"
Emit-NetstatMatches
Probe-SAPRoots
Write-Info "Done."

Write-NDJSON @{
  type        = 'meta'
  phase       = 'end'
  timestamp   = (Get-Date).ToString('s')
  ndjson_path = $script:NDJPath
  stats       = @{}
}

Write-Success ("Results saved. NDJSON: {0}" -f $script:NDJPath)

