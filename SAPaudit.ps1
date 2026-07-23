#requires -version 5.1
<#
.SYNOPSIS
  SAPstract read-only, host-local SAP footprint and posture audit.

.DESCRIPTION
  Inventories local SAP systems, services, processes, listening/connected
  sockets, profiles, ACLs, tools, paths, permissions, and SAP SSFS families.
  Produces a self-contained HTML report and a JSON evidence companion using
  the sapstract-audit/v2 schema.

  The collector does not connect to remote services, decrypt SSFS data, call
  SAP administration web methods, or modify the audited host.

.PARAMETER OutputDirectory
  Directory for generated reports. Defaults to the current directory.

.PARAMETER ReportPath
  Explicit HTML report path.

.PARAMETER JsonPath
  Explicit JSON evidence report path.

.PARAMETER RootPath
  Alternate filesystem root for offline audits.

.PARAMETER HostLabel
  Override the hostname shown in the report, for example for an offline image.

.PARAMETER ReportNote
  Scope or context note included in the HTML and JSON reports.

.PARAMETER MaxFiles
  Maximum number of files processed by each broad recursive scan.

.EXAMPLE
  .\SAPaudit.ps1 -OutputDirectory C:\Audit\SAPstract

#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = (Get-Location).Path,
    [string]$ReportPath,
    [string]$JsonPath,
    [string]$RootPath,
    [string]$HostLabel,
    [string]$ReportNote,
    [ValidateRange(1, 1000000)]
    [int]$MaxFiles = 6000,
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$script:Version = '2.2.0'
$script:Schema = 'sapstract-audit/v2'
$script:IsWindowsHost = ($env:OS -eq 'Windows_NT')
$script:CustomRoot = -not [string]::IsNullOrWhiteSpace($RootPath)
$script:RiskScore = 0
$script:SapEvidenceCount = 0
$script:SapServerEvidenceCount = 0
$script:SocketCandidateCount = 0
$script:TruncatedScans = 0
$script:SeenFinding = @{}
$script:SeenPath = @{}
$script:SeenSsfs = @{}
$script:SeenTool = @{}
$script:SeenSystem = @{}
$script:SapPids = @{}
$script:SapProcessByPid = @{}
$script:SapSids = @{}
$script:SapInstanceNumbers = @{}
$script:SapProductContext = @{}
$script:SsfsData = @{}
$script:SsfsKey = @{}
$script:SsfsFamily = @{}
$script:SeenServiceMap = @{}
$script:SeenDatabase = @{}
$script:SeenTopologyNode = @{}
$script:SeenTopologyEdge = @{}
$script:SeenCapability = @{}
$script:ConfiguredSsfsPaths = New-Object System.Collections.Generic.List[string]
$script:Tables = [ordered]@{
    Findings = New-Object System.Collections.Generic.List[object]
    Systems = New-Object System.Collections.Generic.List[object]
    Services = New-Object System.Collections.Generic.List[object]
    Processes = New-Object System.Collections.Generic.List[object]
    Sockets = New-Object System.Collections.Generic.List[object]
    SocketCandidates = New-Object System.Collections.Generic.List[object]
    Paths = New-Object System.Collections.Generic.List[object]
    Ssfs = New-Object System.Collections.Generic.List[object]
    Tools = New-Object System.Collections.Generic.List[object]
    Profiles = New-Object System.Collections.Generic.List[object]
    Coverage = New-Object System.Collections.Generic.List[object]
    Assessment = New-Object System.Collections.Generic.List[object]
    SectionScores = New-Object System.Collections.Generic.List[object]
    ServiceMap = New-Object System.Collections.Generic.List[object]
    Capabilities = New-Object System.Collections.Generic.List[object]
    Databases = New-Object System.Collections.Generic.List[object]
    TopologyNodes = New-Object System.Collections.Generic.List[object]
    TopologyEdges = New-Object System.Collections.Generic.List[object]
}
$script:DatabasePosture = [ordered]@{
    status = 'undetermined'
    summary = 'No database placement evidence was observed.'
    confidence = 'low'
}

function Write-AuditLog {
    param([string]$Message)
    if (-not $Quiet) { Write-Host "[SAPstract] $Message" -ForegroundColor Cyan }
}

function Write-AuditWarning {
    param([string]$Message)
    Write-Warning "[SAPstract] $Message"
}

function Write-Banner {
    if ($Quiet) { return }
    $useColor = -not [Console]::IsOutputRedirected
    $escape = [char]27
    $blue = if ($useColor) { "$escape[94m" } else { '' }
    $white = if ($useColor) { "$escape[97m" } else { '' }
    $reset = if ($useColor) { "$escape[0m" } else { '' }
    $banner = @'
\033[94m
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\033[97m.dBBBBP dBBBBBBP dBBBBBb dBBBBBb     dBBBP dBBBBBBP\033[94m
     @@@@#+-     .=+*%@@@@@*:::::=@@@@@*:::::::-==+*%@@@@@@@@@@@@@@@@ \033[97m.BP                   dBP      BB\033[94m
     @@+              *@@@%       =@@@@+              +@@@@@@@@@@@@   \033[97m`BBBBb   dBP     dBBBBK   dBP BB   dBP      dBP\033[94m
     @=      .::     %@@@@         +@@@+               :@@@@@@@@@@       \033[97mdBP  dBP     dBP  BB  dBP  BB  dBP      dBP\033[94m
     @      @@@@@@@@@@@@@-          %@@+     +@@@%-     +@@@@@@     \033[97mdBBBBP'  dBP     dBP  dB' dBBBBBBB dBBBBP   dBP\033[94m
     @.       :*%@@@@@@@+     =     =@@+     +@@@@=     +@@@@      \033[97m-----------------------------------------------------\033[94m
     @%:           =*@@#     -%=     +@+     :+++:      %@@@        \033[97mTool: SAPstract  — SAP enumeration & fuzzing toolkit\033[94m
     @@@#+           :*:     *@@      #+               #@@          \033[97mBy:   @A3-N      — github.com/A3-N/SAPstract\033[94m
     @@@@@@@%#+.             +#*:     -+            =#@@            \033[97mCred: Bizsploit  — Mariano Nuñez Di Croce\033[94m
     @@%*@@@@@@@-                      .     +@@@@@@@@                    \033[97mMetasploit — rapid7\033[94m
     @%.                                     +@@@@@@                      \033[97mpysap      — OWASP\033[94m
     @-                   -@@%%%@@+          +@@@@
     @@@#+=-. .-=@@@@@@@@@@@@@@@@@+=@@@#@@@@@@@@
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                          \033[97mRead-only host-local SAP posture assessment\033[94m
'@
    $banner = $banner.Replace('\033[94m', $blue).Replace('\033[97m', $white)
    [Console]::WriteLine($banner.Trim([char[]]"`r`n") + $reset + [Environment]::NewLine)
}

function Add-TableRow {
    param(
        [Parameter(Mandatory = $true)][string]$Table,
        [Parameter(Mandatory = $true)][hashtable]$Data
    )
    [void]$script:Tables[$Table].Add([pscustomobject]$Data)
}

function Get-SeverityWeight {
    param([string]$Severity)
    switch ($Severity) {
        'Critical' { 30 }
        'High' { 18 }
        'Medium' { 8 }
        'Low' { 3 }
        default { 0 }
    }
}

function Add-Finding {
    param(
        [string]$Id,
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')][string]$Severity,
        [string]$Title,
        [string]$Asset,
        [string]$Evidence,
        [string]$Recommendation,
        [string]$Reference = ''
    )
    $key = "$Id|$Asset"
    if ($script:SeenFinding.ContainsKey($key)) { return }
    $script:SeenFinding[$key] = $true
    $points = Get-SeverityWeight $Severity
    $script:RiskScore = [Math]::Min(100, $script:RiskScore + $points)
    Add-TableRow Findings ([ordered]@{
        id = $Id
        severity = $Severity
        points = $points
        title = $Title
        asset = $Asset
        evidence = $Evidence
        recommendation = $Recommendation
        reference = $Reference
    })
}

function Add-Coverage {
    param([string]$Check, [string]$Status, [string]$Detail)
    Add-TableRow Coverage ([ordered]@{ check = $Check; status = $Status; detail = $Detail })
}

function Add-Assessment {
    param([string]$Area, [string]$Status, [string]$Evidence, [string]$NextStep, [string]$Source)
    Add-TableRow Assessment ([ordered]@{
        area = $Area; status = $Status; evidence = $Evidence; next_step = $NextStep; source = $Source
    })
}

function ConvertTo-LogicalPath {
    param([string]$Physical)
    if (-not $script:CustomRoot) { return $Physical }
    $fullRoot = [IO.Path]::GetFullPath($RootPath).TrimEnd('\', '/')
    $fullPath = [IO.Path]::GetFullPath($Physical)
    if ($fullPath.StartsWith($fullRoot, [StringComparison]::OrdinalIgnoreCase)) {
        $relative = $fullPath.Substring($fullRoot.Length).Replace('\', '/')
        if (-not $relative.StartsWith('/')) { $relative = '/' + $relative }
        if ($relative -eq '') { return '/' }
        return $relative
    }
    return $Physical
}

function ConvertTo-PhysicalPath {
    param([string]$Logical)
    if (-not $script:CustomRoot) { return $Logical }
    $relative = $Logical.TrimStart('\', '/')
    return Join-Path -Path $RootPath -ChildPath $relative
}

function Test-IsAdministrator {
    if ($script:IsWindowsHost) {
        try {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object Security.Principal.WindowsPrincipal($identity)
            return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        } catch { return $false }
    }
    try { return ([int](& id -u 2>$null) -eq 0) } catch { return $false }
}

function Get-UnixMode {
    param([string]$Path)
    if ($script:IsWindowsHost) { return '' }
    try {
        $value = (& stat -c '%a' -- $Path 2>$null)
        if ($LASTEXITCODE -eq 0) { return [string]$value }
    } catch {}
    try {
        $value = (& stat -f '%Lp' -- $Path 2>$null)
        if ($LASTEXITCODE -eq 0) { return [string]$value }
    } catch {}
    return ''
}

function Get-PathEvidence {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $owner = ''
    $group = ''
    $mode = ''
    $aclSummary = ''
    if ($script:IsWindowsHost) {
        try {
            $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
            $owner = [string]$acl.Owner
            $aclSummary = (($acl.Access | ForEach-Object {
                '{0}:{1}:{2}' -f $_.IdentityReference, $_.FileSystemRights, $_.AccessControlType
            }) -join '; ')
        } catch {
            $aclSummary = "ACL unavailable: $($_.Exception.Message)"
        }
    } else {
        try {
            $owner = [string]$item.UnixStat.UserName
            $group = [string]$item.UnixStat.GroupName
        } catch {
            try {
                $parts = (& stat -c '%U|%G' -- $Path 2>$null) -split '\|', 2
                if ($parts.Count -ge 2) { $owner = $parts[0]; $group = $parts[1] }
            } catch {}
        }
        $mode = Get-UnixMode $Path
    }
    $type = if ($item.PSIsContainer) { 'Directory' } elseif ($item.LinkType) { "Link ($($item.LinkType))" } else { 'File' }
    $size = if ($item.PSIsContainer) { 0 } else { [long]$item.Length }
    [pscustomobject]@{
        Item = $item
        Owner = $owner
        Group = $group
        Mode = $mode
        AclSummary = $aclSummary
        Type = $type
        Size = $size
        Modified = $item.LastWriteTimeUtc.ToString('s') + 'Z'
    }
}

function Test-WeakWindowsAcl {
    param([string]$Path, [string]$Category)
    if (-not $script:IsWindowsHost -or $Category -eq 'SAP root/product') { return }
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        foreach ($entry in $acl.Access) {
            if ($entry.AccessControlType -ne 'Allow') { continue }
            $identity = [string]$entry.IdentityReference
            if ($identity -notmatch '(?i)(^|\\)(Everyone|Users|Authenticated Users)$') { continue }
            $rights = [string]$entry.FileSystemRights
            if ($rights -notmatch '(?i)(Write|Modify|FullControl|CreateFiles|Delete|ChangePermissions|TakeOwnership)') { continue }
            $logical = ConvertTo-LogicalPath $Path
            $severity = 'High'
            $id = 'FILE-002'
            $title = 'SAP security-relevant path is writable by a broad Windows principal'
            if ($Category -eq 'SSFS key' -or $Category -eq 'SSFS local protection') {
                $severity = 'Critical'; $id = 'SSFS-001'
                $title = 'SSFS key material is writable by a broad Windows principal'
            } elseif ($Category -eq 'Executable') {
                $severity = 'Critical'; $id = 'FILE-001'
                $title = 'SAP executable is writable by a broad Windows principal'
            }
            Add-Finding $id $severity $title $logical `
                "$identity has $rights through the effective file ACL." `
                'Remove broad write/modify rights, retain access only for the SAP service owner and explicitly managed administrators, then verify component integrity.' `
                'OWASP CBAS filesystem-write and code-integrity attack paths'
        }
    } catch {}
}

function Test-WeakUnixMode {
    param([string]$Path, [string]$Category, [string]$Mode, [string]$Group)
    if ([string]::IsNullOrWhiteSpace($Mode) -or $Mode.Length -lt 3) { return }
    $triad = $Mode.Substring($Mode.Length - 3)
    try {
        $groupDigit = [Convert]::ToInt32($triad.Substring(1, 1), 8)
        $otherDigit = [Convert]::ToInt32($triad.Substring(2, 1), 8)
    } catch { return }
    $logical = ConvertTo-LogicalPath $Path
    $isDirectory = (Test-Path -LiteralPath $Path -PathType Container)
    if (($otherDigit -band 2) -ne 0) {
        if ($Category -eq 'SSFS key' -or $Category -eq 'SSFS local protection') {
            Add-Finding 'SSFS-001' 'Critical' 'SSFS key material is writable by everyone' $logical `
                "Mode $Mode permits other users to alter key material." `
                'Restrict the file and parent path to the SAP service owner and only the explicitly required administration group; validate with official SAP tooling.' `
                'SAP SSFS least-privilege guidance'
        } elseif ($Category -eq 'Executable') {
            Add-Finding 'FILE-001' 'Critical' 'SAP executable is writable by everyone' $logical `
                "Mode $Mode permits arbitrary local users to modify executable code." `
                'Remove other-write, restore the vendor binary from trusted media if integrity is uncertain, and verify ownership and patch level.' `
                'OWASP CBAS code integrity'
        } else {
            Add-Finding 'FILE-002' 'High' 'SAP security-relevant path is writable by everyone' $logical `
                "Mode $Mode permits arbitrary local modification of this $Category." `
                'Remove other-write and grant changes only to the SAP service owner or an explicitly managed administrator group.' `
                'OWASP CBAS filesystem-write attack paths'
        }
    }
    if (($groupDigit -band 2) -ne 0) {
        if ($Category -eq 'SSFS key' -or $Category -eq 'SSFS local protection') {
            Add-Finding 'SSFS-002' 'High' 'SSFS key material is group-writable' $logical `
                "Mode $Mode permits members of group $Group to alter key material." `
                'Confirm the group is required and tightly controlled; otherwise remove group-write and preserve matched data/key recovery copies.' `
                'SAP SSFS least-privilege guidance'
        } elseif ($Category -eq 'Executable') {
            Add-Finding 'FILE-003' 'High' 'SAP executable is group-writable' $logical `
                "Mode $Mode permits group $Group to alter executable code." `
                'Restrict writes to the trusted software owner and verify the binary against approved media.' `
                'OWASP CBAS code integrity'
        } elseif ($Category -match '^(Profile|ACL|Credential|SSFS data)$') {
            Add-Finding 'FILE-004' 'Medium' 'Sensitive SAP file is group-writable' $logical `
                "Mode $Mode permits group $Group to alter this $Category." `
                'Validate every group member requires write access; otherwise remove it and use a dedicated SAP administration group.' `
                'SAP configuration hardening'
        }
    }
    if ($Category -eq 'SSFS key' -or $Category -eq 'SSFS local protection') {
        if (($otherDigit -band 4) -ne 0) {
            Add-Finding 'SSFS-003' 'Critical' 'SSFS key material is readable by everyone' $logical `
                "Mode $Mode exposes key material to arbitrary local users." `
                'Remove other-read immediately, review local access, and rotate/re-encrypt through supported SAP procedures if disclosure cannot be excluded.' `
                'SAP SSFS least-privilege guidance'
        }
        if (($groupDigit -band 4) -ne 0) {
            Add-Finding 'SSFS-004' 'Medium' 'SSFS key material is group-readable' $logical `
                "Mode $Mode exposes key material to every member of group $Group." `
                'Confirm all group members require access and prefer owner-only read access where the SAP deployment permits it.' `
                'SAP SSFS least-privilege guidance'
        }
    } elseif (($Category -eq 'SSFS data' -or $Category -eq 'Credential') -and (($otherDigit -band 4) -ne 0)) {
        Add-Finding 'FILE-005' 'High' 'Secret-bearing SAP data is readable by everyone' $logical `
            "Mode $Mode permits arbitrary local users to copy credential-bearing material." `
            'Remove other-read, restrict parent traversal, and review whether matching keys or credentials were also exposed.' `
            'OWASP CBAS filesystem-read attack paths'
    }
    if ($isDirectory -and (($otherDigit -band 2) -ne 0)) {
        Add-Finding 'FILE-006' 'High' 'SAP directory is writable by everyone' $logical `
            "Directory mode $Mode permits arbitrary users to add, replace, or rename SAP files." `
            'Remove other-write; isolate intentional shared drop paths from executables, profiles, transports, and secure stores.' `
            'OWASP CBAS filesystem-write and transport attack paths'
    }
}

function Add-PathEvidence {
    param([string]$Path, [string]$Category, [string]$Note = '')
    if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) { return }
    $logical = ConvertTo-LogicalPath $Path
    if ($script:SeenPath.ContainsKey($logical)) { return }
    $script:SeenPath[$logical] = $true
    try {
        $evidence = Get-PathEvidence $Path
        Add-TableRow Paths ([ordered]@{
            category = $Category; path = $logical; type = $evidence.Type
            owner = $evidence.Owner; group = $evidence.Group; mode = $evidence.Mode
            acl = $evidence.AclSummary; size_bytes = $evidence.Size
            modified = $evidence.Modified; note = $Note
        })
        Test-WeakWindowsAcl $Path $Category
        Test-WeakUnixMode $Path $Category $evidence.Mode $evidence.Group
    } catch {
        Add-TableRow Paths ([ordered]@{
            category = $Category; path = $logical; type = 'unknown'; owner = ''
            group = ''; mode = ''; acl = ''; size_bytes = ''; modified = ''
            note = "$Note; metadata error: $($_.Exception.Message)"
        })
    }
    $script:SapEvidenceCount++
}

function Register-SapInstance {
    param([string]$Sid, [string]$InstanceNumber = '')
    if ($Sid -match '^(?i)[A-Z][A-Z0-9]{2}$') { $script:SapSids[$Sid.ToUpperInvariant()] = $true }
    if ($InstanceNumber -match '^\d{2}$') { $script:SapInstanceNumbers[$InstanceNumber] = $true }
}

function Test-SapRegistrySidEvidence {
    param([string]$Sid, [object]$EnvironmentProperties)
    if ($Sid -notmatch '^(?i)[A-Z][A-Z0-9]{2}$' -or $null -eq $EnvironmentProperties) {
        return $false
    }
    $property = $EnvironmentProperties.PSObject.Properties['SAPSYSTEMNAME']
    return ($null -ne $property -and [string]$property.Value -ieq $Sid)
}

function Test-SapNativeProcessText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return ($Text -match '(?i)(^|[\s/\\])(disp\+work|dw\.sap|gwrd|ms\.sap|enserver|enrepserver|icman|igswd_mt|igsmux|sapstartsrv(\.exe)?|saphostexec(\.exe)?|saphostctrl(\.exe)?|saposcol(\.exe)?|saprouter(\.exe)?|sapwebdisp(\.exe)?|jstart(\.exe)?|jlaunch(\.exe)?|hdbdaemon|hdbnameserver|hdbindexserver|hdbcompileserver|hdbpreprocessor|hdbxsengine|hdbscriptserver|hdbwebdispatcher|hdbesserver|hdbdocstore|hdbdpserver|hdbdiserver|sapinst|sapup|r3trans(\.exe)?|scc_daemon|cloud.?connector)([\s/\\]|$)' -or
            $Text -match '(?i)[/\\](usr[/\\]sap|sapmnt|sap[/\\]hostctrl|sapdb|maxdb|hana[/\\](shared|data|log))[/\\]')
}

function Test-SapDatabaseProcessCandidateText {
    param([string]$Text)
    return ($Text -match '(?i)(^|[\s/\\])(dataserver(\.exe)?|backupserver(\.exe)?|bcksrvr(\.exe)?|jsagent(\.exe)?|oracle|ora_[a-z0-9_]+|tnslsnr|db2sysc|db2wdog|sqlservr(\.exe)?|dbmsrv|x_server|tp(\.exe)?)([\s/\\]|$)')
}

function Test-SapDatabaseProcessText {
    param([string]$Text, [string]$Account = '')
    if (-not (Test-SapDatabaseProcessCandidateText $Text)) { return $false }
    foreach ($sid in @($script:SapSids.Keys)) {
        $escaped = [regex]::Escape([string]$sid)
        if ($Account -match "(?i)(^|[\\/@])(SAPService)?$escaped(adm)?$" -or
            $Account -match "(?i)(^|[\\/@])ora$escaped$" -or
            $Account -match "(?i)(^|[\\/@])syb$escaped$" -or
            $Text -match "(?i)[/\\]oracle[/\\]$escaped[/\\]" -or
            $Text -match "(?i)[/\\]sybase[/\\]$escaped[/\\]" -or
            $Text -match "(?i)ora_(pmon|smon)_$escaped(\s|$)") {
            return $true
        }
    }
    return $false
}

function Test-SapProcessText {
    param([string]$Text, [string]$Account = '')
    return ((Test-SapNativeProcessText $Text) -or (Test-SapDatabaseProcessText $Text $Account))
}

function Test-SapServiceEvidence {
    param([string]$Name, [string]$Description = '', [string]$Path = '')
    $text = "$Name $Description $Path"
    return ($Name -match '^(?i)SAP[A-Z0-9]{3}_\d{2}$' -or
            $Name -match '^(?i)(SAP(Host(Control|Exec)?|Router|WebDisp|OsCol|StartSrv)|HDB|HANA)[A-Z0-9_.@-]*$' -or
            $text -match '(?i)(^|[\s_.:/\\-])(SAP|HANA|HDB|Cloud[\s_.-]*Connector)([\s_.:/\\-]|$)' -or
            $Path -match '(?i)[/\\](usr[/\\]sap|program files[/\\]sap)[/\\]')
}

function Test-SapServerServiceEvidence {
    param([string]$Name, [string]$Path = '')
    return ($Name -match '^(?i)SAP[A-Z0-9]{3}_\d{2}(\.service)?$' -or
            $Name -match '^(?i)(SAP(Host(Control|Exec)?|Router|WebDisp|OsCol|StartSrv)|HDB|HANA)[A-Z0-9_.@-]*(\.service)?$' -or
            $Path -match '(?i)[/\\](usr[/\\]sap|sapmnt|hana[/\\](shared|data|log)|sybase|oracle|db2)[/\\]')
}

function Get-SapComponent {
    param([string]$Text)
    switch -Regex ($Text) {
        '(?i)hdb' { return 'SAP HANA' }
        '(?i)(dataserver|backupserver|bcksrvr|jsagent)' { return 'SAP ASE' }
        '(?i)(ora_pmon|tnslsnr|[/\\]oracle[/\\]|\boracle\b)' { return 'Oracle Database' }
        '(?i)(db2sysc|db2wdog|[/\\]db2[/\\])' { return 'IBM Db2' }
        '(?i)sqlservr' { return 'Microsoft SQL Server' }
        '(?i)(dbmsrv|x_server|[/\\](sapdb|maxdb)[/\\])' { return 'SAP MaxDB' }
        '(?i)saprouter' { return 'SAProuter' }
        '(?i)sapwebdisp' { return 'SAP Web Dispatcher' }
        '(?i)saphost' { return 'SAP Host Agent' }
        '(?i)sapstartsrv' { return 'SAP Start Service' }
        '(?i)(enserver|enrepserver)' { return 'SAP Enqueue Server' }
        '(?i)gwrd' { return 'SAP RFC Gateway' }
        '(?i)ms\.sap' { return 'SAP Message Server' }
        '(?i)(disp\+work|dw\.sap)' { return 'SAP Dispatcher/Work Process' }
        '(?i)icman' { return 'SAP ICM' }
        '(?i)igs' { return 'SAP IGS' }
        '(?i)(jstart|jlaunch)' { return 'SAP NetWeaver Java' }
        '(?i)(cloud.?connector|scc_daemon)' { return 'SAP Cloud Connector' }
        '(?i)sapinst' { return 'SAP Software Provisioning Manager' }
        '(?i)sapup' { return 'SAP Software Update Manager' }
        default { return 'SAP component' }
    }
}

function Test-ProcessSecurity {
    param([string]$Name, [string]$Command)
    if ("$Name $Command" -match '(?i)saprouter' -and $Command -match '(^|\s)-X(\s|$)') {
        Add-Finding 'ROUTER-001' 'High' 'SAProuter remote administration loopback is enabled' $Name `
            'The observed SAProuter command line includes -X, which explicitly permits routes from SAProuter back to itself and exposes administrative operations when network and route controls permit access.' `
            'Remove -X unless a documented, tightly controlled dependency requires it; restrict port 3299, use a least-privilege saprouttab, and verify SAP Note 3158375 and the current kernel patch level.' `
            'SAP Note 1853140; SEC Consult CVE-2022-27668; HackTricks SAProuter references'
    }
}

function Collect-Processes {
    Write-AuditLog 'Collecting SAP processes'
    if ($script:IsWindowsHost) {
        try {
            foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
                $text = "$($process.Name) $($process.ExecutablePath) $($process.CommandLine)"
                if (-not (Test-SapNativeProcessText $text) -and
                    -not (Test-SapDatabaseProcessCandidateText $text)) {
                    continue
                }
                $account = ''
                try {
                    $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner -ErrorAction Stop
                    if ($owner.ReturnValue -eq 0) { $account = "$($owner.Domain)\$($owner.User)" }
                } catch {}
                if (-not (Test-SapProcessText $text $account)) { continue }
                $component = Get-SapComponent $text
                switch ($component) {
                    'SAP ASE' { $script:SapProductContext['ase'] = $true }
                    'SAP Software Provisioning Manager' { $script:SapProductContext['installer'] = $true }
                    'SAP Software Update Manager' { $script:SapProductContext['upgrade'] = $true }
                }
                Add-TableRow Processes ([ordered]@{
                    pid = [string]$process.ProcessId; user = $account; group = ''; name = $process.Name
                    executable = $process.ExecutablePath; command = $process.CommandLine; component = $component
                })
                $script:SapPids[[string]$process.ProcessId] = $true
                $script:SapProcessByPid[[string]$process.ProcessId] = [string]$process.Name
                $script:SapEvidenceCount++
                $script:SapServerEvidenceCount++
                Test-ProcessSecurity ([string]$process.Name) ([string]$process.CommandLine)
                if ($process.ExecutablePath) { Add-PathEvidence $process.ExecutablePath 'Executable' "Running $component binary" }
            }
            Add-Coverage 'Processes' 'complete' 'Win32_Process inspected; owner and command-line visibility depend on elevation'
        } catch {
            Add-Coverage 'Processes' 'unavailable' $_.Exception.Message
        }
    } else {
        try {
            $lines = @(& ps -eo 'pid=,user=,group=,comm=,args=' 2>$null)
            foreach ($line in $lines) {
                if ($line -notmatch '^\s*(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$') { continue }
                $pidValue = $Matches[1]; $user = $Matches[2]; $group = $Matches[3]
                $name = $Matches[4]; $command = $Matches[5]
                if (-not (Test-SapProcessText "$name $command" $user)) { continue }
                $exe = ''
                try { $exe = (& readlink "/proc/$pidValue/exe" 2>$null) } catch {}
                $component = Get-SapComponent "$name $exe $command"
                switch ($component) {
                    'SAP ASE' { $script:SapProductContext['ase'] = $true }
                    'SAP Software Provisioning Manager' { $script:SapProductContext['installer'] = $true }
                    'SAP Software Update Manager' { $script:SapProductContext['upgrade'] = $true }
                }
                Add-TableRow Processes ([ordered]@{
                    pid = $pidValue; user = $user; group = $group; name = $name
                    executable = $exe; command = $command; component = $component
                })
                $script:SapPids[$pidValue] = $true
                $script:SapProcessByPid[$pidValue] = $name
                $script:SapEvidenceCount++
                $script:SapServerEvidenceCount++
                Test-ProcessSecurity $name $command
                if ($exe) { Add-PathEvidence $exe 'Executable' "Running $component binary" }
            }
            Add-Coverage 'Processes' 'complete' 'Local process table inspected'
        } catch {
            Add-Coverage 'Processes' 'unavailable' $_.Exception.Message
        }
    }
}

function Collect-Services {
    Write-AuditLog 'Collecting SAP services'
    if ($script:IsWindowsHost) {
        try {
            foreach ($service in @(Get-CimInstance Win32_Service -ErrorAction Stop)) {
                if (-not (Test-SapServiceEvidence ([string]$service.Name) ([string]$service.DisplayName) ([string]$service.PathName))) { continue }
                Add-TableRow Services ([ordered]@{
                    name = $service.Name; state = $service.State; start_mode = $service.StartMode
                    account = $service.StartName; path = $service.PathName; description = $service.DisplayName
                })
                $script:SapEvidenceCount++
                if (Test-SapServerServiceEvidence ([string]$service.Name) ([string]$service.PathName)) {
                    $script:SapServerEvidenceCount++
                }
                if ([string]$service.Name -match '^(?i)SAP[A-Z0-9]{3}_(\d{2})$') {
                    $script:SapInstanceNumbers[$Matches[1]] = $true
                }
            }
            Add-Coverage 'Services' 'complete' 'Win32_Service inspected'
        } catch {
            Add-Coverage 'Services' 'unavailable' $_.Exception.Message
        }
    } else {
        try {
            $found = 0
            if (Get-Command systemctl -ErrorAction SilentlyContinue) {
                foreach ($line in @(& systemctl list-units --type=service --all --no-legend --no-pager 2>$null)) {
                    if ($line -notmatch '^\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$') { continue }
                    $unit = $Matches[1]; $active = $Matches[3]; $sub = $Matches[4]; $description = $Matches[5]
                    $fragment = ''
                    try { $fragment = (& systemctl show $unit -p FragmentPath --value 2>$null) } catch {}
                    if (-not (Test-SapServiceEvidence $unit $description $fragment)) { continue }
                    Add-TableRow Services ([ordered]@{
                        name = $unit; state = "$active/$sub"; start_mode = 'systemd'
                        account = ''; path = $fragment; description = $description
                    })
                    if ($fragment) { Add-PathEvidence $fragment 'Service definition' "Unit $unit" }
                    $found++; $script:SapEvidenceCount++
                    if (Test-SapServerServiceEvidence $unit $fragment) {
                        $script:SapServerEvidenceCount++
                    }
                    if ($unit -match '^(?i)SAP[A-Z0-9]{3}_(\d{2})(\.service)?$') {
                        $script:SapInstanceNumbers[$Matches[1]] = $true
                    }
                }
            }
            Add-Coverage 'Services' 'complete' "$found SAP-named service definitions observed"
        } catch {
            Add-Coverage 'Services' 'partial' $_.Exception.Message
        }
    }
}

function Split-EndPoint {
    param([string]$Endpoint)
    $address = $Endpoint
    $port = ''
    if ($Endpoint -match '^\[(.*)\]:(\d+)$') {
        $address = $Matches[1]; $port = $Matches[2]
    } elseif ($Endpoint -match '^(.*):(\d+)$') {
        $address = $Matches[1]; $port = $Matches[2]
    }
    [pscustomobject]@{ Address = $address.Trim('[', ']'); Port = $port }
}

function Get-PortClassification {
    param([string]$Port)
    if ($Port -notmatch '^\d+$') { return $null }
    $number = [int]$Port
    $result = $null
    switch -Regex ($Port) {
        '^3298$' { $result = @('SAP NI ping', 'NI', 'business'); break }
        '^3299$' { $result = @('SAProuter', 'NI/Router', 'gateway'); break }
        '^32\d{2}$' { $result = @('SAP Dispatcher / SAP DIAG or Enqueue', 'NI/DIAG', 'business'); break }
        '^33\d{2}$' { $result = @('SAP RFC Gateway', 'RFC/NI (typically unencrypted)', 'admin'); break }
        '^48\d{2}$' { $result = @('SAP RFC Gateway with SNC', 'RFC/NI/SNC', 'admin'); break }
        '^36\d{2}$' { $result = @('SAP Message Server external', 'SAP MS', 'business'); break }
        '^39\d{2}$' { $result = @('SAP Message Server internal', 'SAP MS', 'critical-internal'); break }
        '^80\d{2}$' { $result = @('SAP ICM HTTP', 'HTTP', 'cleartext'); break }
        '^443\d{2}$' { $result = @('SAP ICM HTTPS', 'HTTPS', 'business'); break }
        '^81\d{2}$' { $result = @('SAP Message Server HTTP', 'HTTP', 'cleartext'); break }
        '^444\d{2}$' { $result = @('SAP Message Server HTTPS', 'HTTPS', 'business'); break }
        '^5\d{2}00$' { $result = @('SAP NetWeaver Java HTTP', 'HTTP', 'cleartext'); break }
        '^5\d{2}01$' { $result = @('SAP NetWeaver Java HTTPS', 'HTTPS', 'business'); break }
        '^5\d{2}02$' { $result = @('SAP NetWeaver Java IIOP initial', 'IIOP', 'business'); break }
        '^5\d{2}03$' { $result = @('SAP NetWeaver Java IIOP over TLS', 'IIOP/TLS', 'business'); break }
        '^5\d{2}04$' { $result = @('SAP NetWeaver Java P4', 'P4', 'admin'); break }
        '^5\d{2}05$' { $result = @('SAP NetWeaver Java P4 over HTTP', 'P4/HTTP', 'admin'); break }
        '^5\d{2}06$' { $result = @('SAP NetWeaver Java P4 over TLS', 'P4/TLS', 'admin'); break }
        '^5\d{2}07$' { $result = @('SAP NetWeaver Java IIOP', 'IIOP', 'business'); break }
        '^5\d{2}08$' { $result = @('SAP NetWeaver Java shell/telnet', 'Telnet', 'critical-admin'); break }
        '^5\d{2}10$' { $result = @('SAP NetWeaver Java JMS', 'JMS', 'business'); break }
        '^5\d{2}13$' { $result = @('SAP Start Service HTTP', 'HTTP/SOAP', 'admin-cleartext'); break }
        '^5\d{2}14$' { $result = @('SAP Start Service HTTPS', 'HTTPS/SOAP', 'admin'); break }
        '^5\d{2}1[789]$' { $result = @('SAP Java SDM administration', 'administration', 'critical-admin'); break }
        '^4901$' { $result = @('SAP ASE Data Server', 'TDS/ASE', 'database'); break }
        '^4902$' { $result = @('SAP ASE Backup Server', 'TDS/ASE backup', 'database'); break }
        '^4903$' { $result = @('SAP ASE Job Scheduler', 'ASE internal', 'critical-internal'); break }
        '^49\d{2}$' { $result = @('SAP ASE configurable service', 'TDS/ASE', 'database'); break }
        '^4\d{2}00$' { $result = @('SAP IGS multiplexer', 'IGS', 'business'); break }
        '^4\d{2}(0[1-9]|[1-7]\d)$' { $result = @('SAP IGS portwatcher', 'IGS', 'business'); break }
        '^4\d{2}[89]\d$' { $result = @('SAP IGS HTTP', 'HTTP', 'admin-cleartext'); break }
        '^3\d{2}00$' { $result = @('SAP HANA daemon', 'HANA internal', 'critical-internal'); break }
        '^3\d{2}01$' { $result = @('SAP HANA nameserver internal', 'HANA internal', 'critical-internal'); break }
        '^3\d{2}02$' { $result = @('SAP HANA preprocessor internal', 'HANA internal', 'critical-internal'); break }
        '^3\d{2}03$' { $result = @('SAP HANA indexserver internal', 'HANA internal', 'critical-internal'); break }
        '^3\d{2}04$' { $result = @('SAP HANA scriptserver internal', 'HANA internal', 'critical-internal'); break }
        '^3\d{2}05$' { $result = @('SAP HANA statisticsserver internal', 'HANA internal', 'critical-internal'); break }
        '^3\d{2}13$' { $result = @('SAP HANA SystemDB SQL/MDX', 'HDB', 'database'); break }
        '^3\d{2}15$' { $result = @('SAP HANA first tenant SQL/MDX', 'HDB', 'database'); break }
        '^3\d{2}17$' { $result = @('SAP HANA internal SQL', 'HDB', 'critical-internal'); break }
        '^3\d{2}2[6-9]$' { $result = @('SAP HANA optional service', 'HANA', 'business'); break }
        '^3\d{2}[4-9]\d$' { $result = @('SAP HANA tenant/internal dynamic service', 'HANA', 'database'); break }
        '^1128$' { $result = @('SAP Host Agent HTTP', 'HTTP/SOAP', 'admin-cleartext'); break }
        '^1129$' { $result = @('SAP Host Agent HTTPS', 'HTTPS/SOAP', 'admin'); break }
        '^21212$' { $result = @('SAPinst web interface HTTP', 'HTTP', 'critical-admin'); break }
        '^21213$' { $result = @('SAPinst web interface HTTPS', 'HTTPS', 'critical-admin'); break }
        '^(4238|4239|4240|4241|59975|59976)$' { $result = @('SAP install/update administration', 'administration', 'critical-admin'); break }
    }
    if ($null -eq $result) { return $null }
    $context = 'product'
    $instance = ''
    $product = ''
    switch -Regex ($Port) {
        '^(1128|1129|3298|3299)$' { $context = 'dedicated'; break }
        '^(32|33|36|39|48|80|81)(\d{2})$' { $context = 'instance'; $instance = $Matches[2]; break }
        '^(443|444)(\d{2})$' { $context = 'instance'; $instance = $Matches[2]; break }
        '^[345](\d{2})\d{2}$' { $context = 'instance'; $instance = $Matches[1]; break }
    }
    switch -Regex ($Port) {
        '^49\d{2}$' { $product = 'ase'; break }
        '^(21212|21213|59975|59976)$' { $product = 'installer'; break }
        '^(4238|4239|4240|4241)$' { $product = 'upgrade'; break }
    }
    [pscustomobject]@{
        Name = $result[0]; Transport = $result[1]; Sensitivity = $result[2]
        Context = $context; Instance = $instance; Product = $product
    }
}

function Test-LoopbackAddress {
    param([string]$Address)
    return ($Address -match '^(?i)(localhost|::1|127\.)')
}

function Test-WildcardAddress {
    param([string]$Address)
    return ([string]::IsNullOrWhiteSpace($Address) -or $Address -match '^(\*|0\.0\.0\.0|::|0:0:0:0:0:0:0:0)$')
}

function Get-SapPortCorrelationBasis {
    param([object]$Classification)
    switch ($Classification.Context) {
        'dedicated' { return 'Dedicated SAP service port with no contradictory process owner' }
        'instance' {
            if ($Classification.Instance -and $script:SapInstanceNumbers.ContainsKey([string]$Classification.Instance)) {
                return "Port instance $($Classification.Instance) matches a discovered SAP instance"
            }
        }
        'product' {
            if ($Classification.Product -and $script:SapProductContext.ContainsKey([string]$Classification.Product)) {
                return "SAP product port corroborated by matching $($Classification.Product) runtime evidence"
            }
        }
    }
    return $null
}

function Add-SocketCandidate {
    param(
        [object]$Classification, [string]$Protocol, [string]$State,
        [string]$LocalEndpoint, [string]$RemoteEndpoint, [string]$ProcessId,
        [string]$Process, [string]$Reason
    )
    Add-TableRow SocketCandidates ([ordered]@{
        classification = $Classification.Name; transport = $Classification.Transport
        protocol = $Protocol; state = $State; local = $LocalEndpoint; remote = $RemoteEndpoint
        pid = $ProcessId; process = $Process; reason = $Reason
    })
    $script:SocketCandidateCount++
}

function Add-SocketEvidence {
    param(
        [string]$Protocol, [string]$State, [string]$LocalEndpoint,
        [string]$RemoteEndpoint, [string]$ProcessId = '',
        [string]$Process = '', [string]$Service = ''
    )
    $local = Split-EndPoint $LocalEndpoint
    $remote = Split-EndPoint $RemoteEndpoint
    $isListener = $State -match '^(?i)(LISTEN|LISTENING|UNCONN|UDP|Bound)$'
    $sapOwned = $false
    $confidence = ''
    $basis = ''
    if ($ProcessId -and $script:SapPids.ContainsKey([string]$ProcessId)) {
        $sapOwned = $true
        if ([string]::IsNullOrWhiteSpace($Process)) { $Process = $script:SapProcessByPid[[string]$ProcessId] }
        $confidence = 'high'
        $basis = "Socket owned by collected SAP process PID $ProcessId"
    } elseif (Test-SapProcessText "$Process $Service") {
        $sapOwned = $true
        $confidence = 'high'
        $basis = 'Socket owner matches an SAP-specific runtime identity'
    }
    if ($isListener) {
        $classification = Get-PortClassification $local.Port
        if ($null -eq $classification) { $classification = Get-PortClassification $remote.Port }
    } else {
        # Connected sockets normally use an ephemeral local port. Prefer the
        # peer port, but allow a correlated local SAP service port to replace
        # an unrelated ephemeral peer match on the server side.
        $classification = Get-PortClassification $remote.Port
        if ($null -ne $classification -and
            -not (Get-SapPortCorrelationBasis $classification)) {
            $localClassification = Get-PortClassification $local.Port
            if ($null -ne $localClassification -and
                (Get-SapPortCorrelationBasis $localClassification)) {
                $classification = $localClassification
            }
        } elseif ($null -eq $classification -and
            ($sapOwned -or [string]::IsNullOrWhiteSpace("$Process$Service"))) {
            $classification = Get-PortClassification $local.Port
        }
    }
    if ($null -ne $classification -and -not $sapOwned) {
        if (-not [string]::IsNullOrWhiteSpace("$Process$Service")) {
            # A visible non-SAP owner disproves local SAP ownership. Keeping
            # these ubiquitous ephemeral matches would only create noise.
            return
        }
        $correlationBasis = Get-SapPortCorrelationBasis $classification
        if ($correlationBasis) {
            $confidence = 'medium'
            $basis = $correlationBasis
        } else {
            Add-SocketCandidate $classification $Protocol $State $LocalEndpoint $RemoteEndpoint $ProcessId $Process `
                'No SAP owner, discovered instance-number match, or independent product context'
            return
        }
    } elseif ($null -eq $classification) {
        if (-not $sapOwned) { return }
        $classification = [pscustomobject]@{
            Name = (Get-SapComponent "$Process $Service")
            Transport = 'unclassified'; Sensitivity = 'unknown'
            Context = 'owned'; Instance = ''
            Product = ''
        }
        if ($classification.Name -eq 'SAP Cloud Connector') { $classification.Sensitivity = 'admin' }
    }
    if ("$Process $Service" -match '(?i)(^|[\s/\\])(enserver|enrepserver)([\s/\\]|$)') {
        $classification = [pscustomobject]@{
            Name = 'SAP Enqueue Server'
            Transport = 'SAP Enqueue/NI'
            Sensitivity = 'critical-internal'
        }
    }
    $exposure = 'connected'
    if ($isListener) {
        if (Test-LoopbackAddress $local.Address) { $exposure = 'loopback' }
        elseif (Test-WildcardAddress $local.Address) { $exposure = 'all-interfaces' }
        else { $exposure = 'network-interface' }
    }
    Add-TableRow Sockets ([ordered]@{
        classification = $classification.Name; transport = $classification.Transport
        protocol = $Protocol; state = $State; local = $LocalEndpoint
        remote = $RemoteEndpoint; exposure = $exposure; pid = $ProcessId
        process = $Process; service = $Service; confidence = $confidence; basis = $basis
    })
    $script:SapEvidenceCount++

    if ($exposure -eq 'all-interfaces' -or $exposure -eq 'network-interface') {
        switch ($classification.Sensitivity) {
            'critical-admin' {
                Add-Finding 'NET-001' 'High' 'High-impact SAP administration service is network-reachable' "$($classification.Name) at $LocalEndpoint" `
                    "A listening $($classification.Transport) endpoint is bound to $($local.Address). Reachability is not proof of exploitability." `
                    'Bind to a dedicated administration interface or loopback where supported, restrict with host/network firewalls, require strong authentication, and confirm patching.' `
                    'OWASP SAP Pentest Playbook service exposure'
            }
            'critical-internal' {
                Add-Finding 'NET-002' 'High' 'Internal SAP service is bound beyond loopback' "$($classification.Name) at $LocalEndpoint" `
                    "The internal service is listening on $($local.Address)." `
                    'Restrict binding and firewall paths to explicitly required cluster hosts; use SAP-supported internal communication encryption where available.' `
                    'SAP internal-service network separation guidance'
            }
            'admin-cleartext' {
                Add-Finding 'NET-003' 'High' 'Cleartext SAP management endpoint is network-reachable' "$($classification.Name) at $LocalEndpoint" `
                    "The HTTP/administration endpoint is listening on $($local.Address) without transport encryption." `
                    'Prefer the TLS endpoint, bind required cleartext management to loopback, and restrict all remote access.' `
                    'SAP Host Agent and SAP Start Service security guidance'
            }
            'cleartext' {
                Add-Finding 'NET-004' 'Medium' 'SAP HTTP endpoint is network-reachable' "$($classification.Name) at $LocalEndpoint" `
                    'The endpoint uses cleartext HTTP on a non-loopback binding.' `
                    'Confirm no sensitive workflow uses it, redirect to HTTPS, disable unnecessary HTTP ports, and enforce TLS at ICM/Web Dispatcher.' `
                    'OWASP SAP ICM attack-surface guidance'
            }
            'gateway' {
                Add-Finding 'NET-005' 'Medium' 'SAProuter is network-reachable' "$($classification.Name) at $LocalEndpoint" `
                    'Reachability makes route-table scope, SNC use, and patching security-critical.' `
                    'Review saprouttab for least-privilege routes, require SNC where appropriate, restrict management access, and patch SAProuter.' `
                    'OWASP SAP Pentest Playbook: SAProuter'
            }
            'admin' {
                Add-Finding 'NET-006' 'Medium' 'SAP administration endpoint is network-reachable' "$($classification.Name) at $LocalEndpoint" `
                    'An SAP administrative service is listening beyond loopback. Encryption alone does not provide network isolation or strong administrative authorization.' `
                    'Restrict listener/firewall paths to approved administration networks, require strong authentication, and review TLS trust and patch level.' `
                    'SAP component security guidance; OWASP CBAS attack-surface research'
            }
            'database' {
                Add-Finding 'NET-007' 'Medium' 'SAP database endpoint is network-reachable' "$($classification.Name) at $LocalEndpoint" `
                    'A database client endpoint is listening beyond loopback. This proves a local bind, not reachability from an untrusted zone or weak authentication.' `
                    'Restrict the host/network path to approved application and administration systems, require product-supported TLS with certificate and hostname validation, and review database authentication and audit policy.' `
                    'SecuritySilverbacks SAP HANA/ASE service discovery; PySAP HDB documentation'
            }
        }
        if ($classification.Name -eq 'SAP NetWeaver Java shell/telnet') {
            Add-Finding 'JAVA-001' 'High' 'SAP Java shell/telnet is exposed beyond loopback' $LocalEndpoint `
                'The administrative shell port is listening on a non-loopback interface.' `
                'Bind TELNET to localhost, restrict the telnet_login role, or disable it if not operationally required.' `
                'SAP AS Java shell console guidance'
        }
        if ($classification.Name -eq 'SAP Message Server internal') {
            Add-Finding 'MS-001' 'High' 'SAP Message Server internal port is broadly bound' $LocalEndpoint `
                'The 39NN internal cluster-management port is reachable on a non-loopback interface.' `
                'Permit only required application-server hosts at host/network firewalls and validate message-server ACLs.' `
                'OWASP SAP Pentest Playbook: Message Server internal port'
        }
        if ($classification.Name -eq 'SAP Dispatcher / SAP DIAG or Enqueue') {
            Add-Finding 'DIAG-001' 'Medium' 'SAP Dispatcher/DIAG endpoint requires SNC and boundary validation' $LocalEndpoint `
                'The 32NN endpoint is listening beyond loopback; classic DIAG lacks confidentiality unless SNC is negotiated.' `
                'Restrict network paths to approved clients, require SNC privacy where feasible, and validate enforcement from an authorized client.' `
                'OWASP SAP Pentest Playbook: Dispatcher; OWASP sncscan'
        }
        if ($classification.Name -eq 'SAP Message Server external') {
            Add-Finding 'MS-003' 'Medium' 'SAP Message Server external endpoint is network-reachable' $LocalEndpoint `
                'The 36NN service is listening beyond loopback and may expose landscape/service metadata if network boundaries or ACLs are weak.' `
                'Limit access to required SAP clients/servers, maintain message-server ACLs, and validate external reachability separately.' `
                'OWASP SAP Pentest Playbook: Message Server'
        }
        if ($classification.Name -eq 'SAP Enqueue Server') {
            Add-Finding 'ENQ-001' 'High' 'SAP Enqueue service is bound beyond loopback' $LocalEndpoint `
                'The Enqueue or Enqueue Replication listener is reachable on a non-loopback interface and exposes a high-impact internal coordination service.' `
                'Permit only explicitly required SAP cluster peers at host and network firewalls, restrict monitor/administrative access, and verify the current kernel and Enqueue patch posture.' `
                'OWASP PySAP Enqueue documentation; SAP Pentest Playbook internal-service isolation'
        }
    }
    if ($classification.Name -eq 'SAP RFC Gateway' -and $exposure -ne 'loopback') {
        Add-Finding 'GW-001' 'Medium' 'Unencrypted RFC Gateway endpoint is reachable' $LocalEndpoint `
            'Port family 33NN is normally RFC/NI without SNC; this does not prove individual sessions lack controls.' `
            'Use SNC for sensitive RFC paths, restrict gateway reachability, and enforce restrictive secinfo/reginfo rules.' `
            'OWASP SAP Pentest Playbook: RFC Gateway'
    }
}

function Complete-SocketCorrelationCoverage {
    if ($script:SocketCandidateCount -gt 0) {
        Add-Coverage 'Socket correlation' 'filtered' "$($script:SocketCandidateCount) SAP-port candidate(s) retained separately because ownership or host-instance correlation was insufficient"
    } else {
        Add-Coverage 'Socket correlation' 'complete' 'Every recorded SAP socket was supported by process ownership, a discovered instance, or a dedicated SAP service port'
    }
}

function Collect-Sockets {
    Write-AuditLog 'Collecting listening and connected SAP sockets'
    if ($script:IsWindowsHost -and (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        $processMap = @{}
        try { Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $processMap[[string]$_.Id] = $_.ProcessName } } catch {}
        try {
            foreach ($socket in @(Get-NetTCPConnection -ErrorAction Stop)) {
                $local = if ($socket.LocalAddress -match ':') { "[$($socket.LocalAddress)]:$($socket.LocalPort)" } else { "$($socket.LocalAddress):$($socket.LocalPort)" }
                $remote = if ($socket.RemoteAddress -match ':') { "[$($socket.RemoteAddress)]:$($socket.RemotePort)" } else { "$($socket.RemoteAddress):$($socket.RemotePort)" }
                $name = $processMap[[string]$socket.OwningProcess]
                Add-SocketEvidence 'TCP' ([string]$socket.State) $local $remote ([string]$socket.OwningProcess) $name ''
            }
            foreach ($socket in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
                $local = if ($socket.LocalAddress -match ':') { "[$($socket.LocalAddress)]:$($socket.LocalPort)" } else { "$($socket.LocalAddress):$($socket.LocalPort)" }
                $name = $processMap[[string]$socket.OwningProcess]
                Add-SocketEvidence 'UDP' 'UDP' $local '*:*' ([string]$socket.OwningProcess) $name ''
            }
            Add-Coverage 'Sockets' 'complete' 'Get-NetTCPConnection/Get-NetUDPEndpoint; attribution depends on elevation'
        } catch {
            Add-Coverage 'Sockets' 'partial' $_.Exception.Message
        }
        Complete-SocketCorrelationCoverage
        return
    }
    if (Get-Command ss -ErrorAction SilentlyContinue) {
        try {
            foreach ($line in @(& ss -H -tunap 2>$null)) {
                if ($line -notmatch '^(\S+)\s+(\S+)\s+\S+\s+\S+\s+(\S+)\s+(\S+)\s*(.*)$') { continue }
                $pidValue = ''; $name = ''
                if ($Matches[5] -match '"([^"]+)".*pid=(\d+)') { $name = $Matches[1]; $pidValue = $Matches[2] }
                Add-SocketEvidence $Matches[1].ToUpperInvariant() $Matches[2] $Matches[3] $Matches[4] $pidValue $name ''
            }
            Add-Coverage 'Sockets' 'complete' 'ss -tunap; attribution depends on elevation'
        } catch {
            Add-Coverage 'Sockets' 'partial' $_.Exception.Message
        }
    } else {
        Add-Coverage 'Sockets' 'unavailable' 'No Windows network cmdlets or ss command available'
        Write-AuditWarning 'No socket inventory provider found; the report will mark this coverage gap'
    }
    Complete-SocketCorrelationCoverage
}

function Get-SapRoots {
    $roots = New-Object System.Collections.Generic.List[string]
    if ($script:CustomRoot) {
        foreach ($logical in @('/usr/sap', '/sapmnt', '/opt/sap', '/var/lib/sap', '/hana/shared')) {
            $candidate = ConvertTo-PhysicalPath $logical
            if (Test-Path -LiteralPath $candidate -PathType Container) { [void]$roots.Add($candidate) }
        }
    } elseif ($script:IsWindowsHost) {
        foreach ($drive in @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) {
            $relatives = @('usr\sap', 'sapmnt')
            if ($script:SapServerEvidenceCount -gt 0) { $relatives += @('sybase', 'oracle') }
            foreach ($relative in $relatives) {
                $candidate = Join-Path $drive.Root $relative
                if (Test-Path -LiteralPath $candidate -PathType Container) { [void]$roots.Add($candidate) }
            }
        }
        foreach ($candidate in @(
            (Join-Path ${env:ProgramFiles} 'SAP'),
            (Join-Path ${env:ProgramFiles} 'SAP\hostctrl'),
            (Join-Path ${env:ProgramData} 'SAP')
        )) {
            if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Container)) { [void]$roots.Add($candidate) }
        }
        $programX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
        if ($programX86) {
            $candidate = Join-Path $programX86 'SAP'
            if (Test-Path -LiteralPath $candidate -PathType Container) { [void]$roots.Add($candidate) }
        }
    } else {
        foreach ($logical in @('/usr/sap', '/sapmnt', '/opt/sap', '/var/lib/sap', '/hana/shared')) {
            if (Test-Path -LiteralPath $logical -PathType Container) { [void]$roots.Add($logical) }
        }
    }
    return @($roots | Select-Object -Unique)
}

function Get-SensitiveArtifactRoots {
    $roots = New-Object System.Collections.Generic.List[string]
    foreach ($root in Get-SapRoots) { [void]$roots.Add($root) }
    if ($script:IsWindowsHost -and -not $script:CustomRoot) {
        if ($env:ProgramData) {
            $candidate = Join-Path $env:ProgramData '.hdb'
            if (Test-Path -LiteralPath $candidate -PathType Container) { [void]$roots.Add($candidate) }
        }
    } else {
        $homeRoot = ConvertTo-PhysicalPath '/home'
        foreach ($profile in @(Get-ChildItem -LiteralPath $homeRoot -Directory -Force -ErrorAction SilentlyContinue)) {
            $candidate = Join-Path $profile.FullName '.hdb'
            if (Test-Path -LiteralPath $candidate -PathType Container) { [void]$roots.Add($candidate) }
        }
        $candidate = Join-Path (ConvertTo-PhysicalPath '/root') '.hdb'
        if (Test-Path -LiteralPath $candidate -PathType Container) { [void]$roots.Add($candidate) }
        $candidate = ConvertTo-PhysicalPath '/ProgramData/.hdb'
        if (Test-Path -LiteralPath $candidate -PathType Container) { [void]$roots.Add($candidate) }
    }
    return @($roots | Select-Object -Unique)
}

function Get-SapGuiHistoryRoots {
    $roots = New-Object System.Collections.Generic.List[string]
    if ($script:IsWindowsHost -and -not $script:CustomRoot) {
        if ($env:APPDATA) { [void]$roots.Add((Join-Path $env:APPDATA 'SAP\SAP GUI\History')) }
        if ($env:SystemDrive) {
            $usersRoot = Join-Path $env:SystemDrive 'Users'
            foreach ($profile in @(Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue)) {
                [void]$roots.Add((Join-Path $profile.FullName 'AppData\Roaming\SAP\SAP GUI\History'))
            }
        }
        foreach ($entry in @(
            @('HKLM:\SOFTWARE\SAP\SAP Shared', 'SapHistoryDir'),
            @('HKLM:\SOFTWARE\WOW6432Node\SAP\SAP Shared', 'SapHistoryDir'),
            @('HKCU:\Software\SAP\SAPGUI Front\SAP Frontend Server\LocalData', 'DataPath')
        )) {
            try {
                $value = [string](Get-ItemPropertyValue -LiteralPath $entry[0] -Name $entry[1] -ErrorAction Stop)
                if ($value) { [void]$roots.Add([Environment]::ExpandEnvironmentVariables($value)) }
            } catch {}
        }
    } elseif ($script:CustomRoot) {
        $usersRoot = ConvertTo-PhysicalPath '/Users'
        foreach ($profile in @(Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue)) {
            [void]$roots.Add((Join-Path $profile.FullName 'AppData\Roaming\SAP\SAP GUI\History'))
        }
    }
    return @($roots | Where-Object { $_ } | Select-Object -Unique)
}

function Discover-SapSystems {
    Write-AuditLog 'Discovering SAP systems and instances'
    $systemRoots = @()
    if ($script:CustomRoot -or -not $script:IsWindowsHost) {
        $systemRoots += ConvertTo-PhysicalPath '/usr/sap'
        $systemRoots += ConvertTo-PhysicalPath '/sapmnt'
    } else {
        foreach ($drive in @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) {
            $systemRoots += Join-Path $drive.Root 'usr\sap'
            $systemRoots += Join-Path $drive.Root 'sapmnt'
        }
    }
    foreach ($root in $systemRoots | Select-Object -Unique) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        Add-PathEvidence $root 'SAP root' 'Standard SAP installation root'
        foreach ($sidDir in @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue)) {
            $sid = $sidDir.Name.ToUpperInvariant()
            if ($sid -notmatch '^[A-Z][A-Z0-9]{2}$' -or $sid -match '^(SYS|SUM)$') { continue }
            $stack = 'Unknown'
            $hasCharacteristic = $false
            if (Test-Path -LiteralPath (Join-Path $sidDir.FullName 'SYS\global\hdb')) {
                $stack = 'SAP HANA'
                $hasCharacteristic = $true
            }
            if (Test-Path -LiteralPath (Join-Path $sidDir.FullName 'SYS\profile')) {
                if ($stack -eq 'SAP HANA') { $stack = 'SAP HANA / NetWeaver' } else { $stack = 'SAP NetWeaver' }
                $hasCharacteristic = $true
            }
            $instances = New-Object System.Collections.Generic.List[string]
            foreach ($instance in @(Get-ChildItem -LiteralPath $sidDir.FullName -Directory -Force -ErrorAction SilentlyContinue)) {
                if ($instance.Name -match '^(D|J|DVEBMGS|ASCS|SCS|ERS|HDB|PAS|AAS|SMDA|W)\d{2}$') {
                    $hasCharacteristic = $true
                    [void]$instances.Add($instance.Name)
                    Register-SapInstance $sid $instance.Name.Substring($instance.Name.Length - 2)
                    Add-PathEvidence $instance.FullName 'SAP instance' "SID $sid instance $($instance.Name)"
                }
            }
            if (-not $hasCharacteristic) { continue }
            Register-SapInstance $sid
            $key = "$sid|$(ConvertTo-LogicalPath $sidDir.FullName)"
            if (-not $script:SeenSystem.ContainsKey($key)) {
                $script:SeenSystem[$key] = $true
                Add-TableRow Systems ([ordered]@{
                    sid = $sid; stack = $stack; instances = ($instances -join ', ')
                    root = ConvertTo-LogicalPath $sidDir.FullName; source = 'filesystem'
                })
                $script:SapServerEvidenceCount++
            }
            Add-PathEvidence $sidDir.FullName 'SAP system' "SID $sid"
            $script:SapEvidenceCount++
        }
    }
    Add-Coverage 'SAP systems' 'complete' 'Standard SAP roots and instance naming inspected'
}

function Scan-KnownPaths {
    Write-AuditLog 'Inventorying standard SAP paths'
    if ($script:CustomRoot -or -not $script:IsWindowsHost) {
        foreach ($entry in @(
            @('/usr/sap', 'SAP root'), @('/sapmnt', 'SAP root'), @('/hana/shared', 'SAP HANA shared'),
            @('/hana/data', 'SAP HANA data'), @('/hana/log', 'SAP HANA log'),
            @('/usr/sap/hostctrl', 'SAP Host Agent'), @('/usr/sap/trans', 'SAP transport'),
            @('/usr/sap/sapinst_instdir', 'SAP installer'), @('/var/tmp/sapinst_exe', 'SAP installer'),
            @('/opt/sap', 'SAP product'), @('/var/lib/sap', 'SAP product'),
            @('/var/log/sap', 'SAP log'), @('/sybase', 'SAP ASE'), @('/opt/sybase', 'SAP ASE'),
            @('/oracle', 'Oracle for SAP'), @('/sapdb', 'SAP MaxDB'), @('/opt/sapdb', 'SAP MaxDB'),
            @('/var/opt/sapdb', 'SAP MaxDB'), @('/db2', 'IBM Db2 for SAP'),
            @('/usr/sap/SAPBusinessObjects', 'SAP BusinessObjects')
        )) {
            $candidate = ConvertTo-PhysicalPath $entry[0]
            if (Test-Path -LiteralPath $candidate) { Add-PathEvidence $candidate $entry[1] 'Known SAP path' }
        }
    } else {
        foreach ($root in Get-SapRoots) { Add-PathEvidence $root 'SAP root/product' 'Known Windows SAP path' }
    }
}

function Scan-SecurityArtifacts {
    Write-AuditLog 'Inventorying SAP security, audit, transport, and client artifacts'
    $count = 0
    $patterns = @(
        '*.pse', 'cred_v2*', '*.cred', 'SecStore.properties', 'SecStore.key', 'dlmanager.conf',
        '*.jks', '*.keystore', 'cacerts', 'keystore.xml',
        'audit*', '*audit*.log', 'sal*.log', 'dev_w*', 'dev_disp', 'dev_ms', 'dev_rd',
        'dev_icm', 'dev_webdisp', 'dev_jstart', 'dev_server*', 'std_server*', 'prxyinfo',
        'ms_acl_info', '*.acl', '*.sar', '*.car', '*.sca', '*.sda', '*webgui*'
    )
    foreach ($root in Get-SapRoots) {
        try {
            foreach ($item in @(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue)) {
                $matches = $false
                if ($item.PSIsContainer) {
                    $isTransportDirectory = (
                        $item.Name -match '^(?i)(cofiles|data|buffer)$' -and
                        $item.FullName -match '(?i)[/\\]trans[/\\](cofiles|data|buffer)$'
                    )
                    $matches = ($isTransportDirectory -or $item.Name -match '(?i)webgui')
                } else {
                    foreach ($pattern in $patterns) {
                        if ($item.Name -like $pattern) { $matches = $true; break }
                    }
                }
                if (-not $matches) { continue }
                $count++
                if ($count -gt $MaxFiles) { break }

                $category = 'SAP security artifact'
                $note = 'Metadata only; content not collected'
                switch -Regex ($item.Name) {
                    '(?i)webgui' {
                        $category = 'SAP WebGUI artifact'
                        $note = 'Host-side WebGUI-named artifact; active SICF service still requires authenticated confirmation'
                        break
                    }
                    '(?i)(\.pse$|^cred_v2|\.cred$|^secstore\.(properties|key)$|^dlmanager\.conf$)' {
                        $category = 'Credential'; $note = 'PSE, Java secure-store, Download Manager, or credential container; content and private keys not read'; break
                    }
                    '(?i)(\.jks$|\.keystore$|^cacerts$|^keystore\.xml$)' {
                        $category = 'Credential'; $note = 'Java/SCC key store; content, aliases, and passwords not read'; break
                    }
                    '(?i)(^audit|audit.*\.log$|^sal.*\.log$)' {
                        $category = 'Audit log'; $note = 'Security/audit log presence and metadata only'; break
                    }
                    '(?i)(^dev_w|^dev_(disp|ms|rd|icm|webdisp|jstart)$|^dev_server|^std_server)' {
                        $category = 'SAP trace'; $note = 'Runtime trace presence and metadata only'; break
                    }
                    '(?i)(^saprouttab$|^secinfo$|^reginfo$|^prxyinfo$|^ms_acl_info$|\.acl$)' {
                        $category = 'ACL'; $note = 'SAP access-control artifact'; break
                    }
                    '(?i)^(cofiles|data|buffer)$' {
                        $category = 'SAP transport'; $note = 'Transport directory/file metadata'; break
                    }
                    '(?i)\.(sar|car|sca|sda)$' {
                        $category = 'SAP archive'; $note = 'Deployable or transportable SAP archive'; break
                    }
                }
                Add-PathEvidence $item.FullName $category $note
            }
        } catch {}
        if ($count -gt $MaxFiles) { break }
    }
    foreach ($historyRoot in Get-SapGuiHistoryRoots) {
        if (-not (Test-Path -LiteralPath $historyRoot -PathType Container)) { continue }
        foreach ($historyFile in @(Get-ChildItem -LiteralPath $historyRoot -File -Force -ErrorAction SilentlyContinue |
                Where-Object Name -match '^(?i)SAPHistory.*\.db$')) {
            $count++
            if ($count -gt $MaxFiles) { break }
            Add-PathEvidence $historyFile.FullName 'SAP GUI history' 'Documented SAP GUI input-history database; content not read'
            Add-Finding 'GUI-001' 'High' 'SAP GUI input-history data is present' (ConvertTo-LogicalPath $historyFile.FullName) `
                'SAP GUI history can contain business data, identifiers, table names, and other clear-text field input. Older Java clients stored it unencrypted and older Windows clients used reversible XOR-based protection.' `
                'Confirm SAP GUI edition and patch level. Apply the relevant SAP Notes, disable history where risk requires it, exclude sensitive fields, and remove old history through an approved user-data procedure.' `
                'OWASP CBAS research: CVE-2025-0055/CVE-2025-0056'
        }
        if ($count -gt $MaxFiles) { break }
    }
    if ($count -gt $MaxFiles) {
        $script:TruncatedScans++
        Add-Coverage 'Security artifacts' 'partial' "Stopped at MaxFiles=$MaxFiles"
    } else {
        Add-Coverage 'Security artifacts' 'complete' 'Broad artifact names inspected only under SAP roots; user profiles limited to documented or configured SAP GUI history paths'
    }
}

function Test-SensitiveParameterName {
    param([string]$Name)
    return ($Name -match '(?i)(password|passwd|pwd|secret|token|credential|cryptkey|private.?key|signing.?key)')
}

function Add-ProfileParameter {
    param([string]$File, [string]$Name, [string]$Value, [string]$Source = 'filesystem')
    $shown = $Value
    if (Test-SensitiveParameterName $Name) {
        if ([string]::IsNullOrWhiteSpace($Value)) { $shown = '[empty]' } else { $shown = '[REDACTED: non-empty]' }
    }
    Add-TableRow Profiles ([ordered]@{ file = $File; parameter = $Name; value = $shown; source = $Source })
    $compact = ($Value -replace '\s', '')
    $normalized = $Value.Trim().ToUpperInvariant()
    switch ($Name.ToLowerInvariant()) {
        'auth/rfc_authority_check' {
            if ($compact -eq '0') {
                Add-Finding 'AUTH-001' 'High' 'RFC authorization checks are disabled' $File `
                    'auth/rfc_authority_check=0 disables the S_RFC authorization check for incoming RFC function calls.' `
                    'Set a supported non-zero value after tracing and correcting S_RFC roles; evaluate value 9 for function-module-level checks and validate every technical destination.' `
                    'SAP Help: Secure RFCs with Authorizations; SAP Note 931252'
            }
        }
        'login/no_automatic_user_sapstar' {
            if ($compact -eq '0') {
                Add-Finding 'AUTH-002' 'High' 'Automatic SAP* fallback user is enabled' $File `
                    'login/no_automatic_user_sapstar=0 permits the kernel-level SAP* fallback when no SAP* user master record exists in a client.' `
                    'Set the parameter to 1, retain and lock a protected SAP* user master in every client, change default credentials, and verify the control in each client without deleting the account.' `
                    'SAP Security Note 68048; ERPScan default-account guidance; SAP Cloud ALM supported checks'
            }
        }
        'login/show_detailed_errors' {
            if ($normalized -in @('TRUE','YES') -or $compact -eq '1') {
                Add-Finding 'AUTH-003' 'Medium' 'Detailed ABAP logon errors are enabled' $File `
                    "login/show_detailed_errors=$Value can disclose whether a user, client, or password condition caused a failed logon and support account enumeration." `
                    'Set the effective value to FALSE after compatibility testing and use protected server-side audit/trace data for diagnosis.' `
                    'SAP Cloud ALM information-disclosure check; OWASP PySAP DIAG documentation'
            }
        }
        'login/password_compliance_to_current_policy' {
            if ($compact -eq '0') {
                Add-Finding 'AUTH-004' 'Medium' 'Existing passwords are not checked against the current policy' $File `
                    'login/password_compliance_to_current_policy=0 does not force a password change when an interactive user password no longer satisfies the current rules.' `
                    'Set the effective profile parameter or security-policy attribute to 1 after reviewing service/system-user exclusions and the operational reset process.' `
                    'SAP Help: security policy attributes; SAP Cloud ALM supported checks'
            }
        }
        'login/password_downwards_compatibility' {
            if ($compact -match '^[1-5]$') {
                Add-Finding 'AUTH-005' 'Medium' 'Backward-compatible password hashes are retained' $File `
                    "login/password_downwards_compatibility=$compact creates a backward-compatible password hash; values 2 through 5 add progressively weaker compatibility behavior." `
                    'Inventory old kernels and CUA dependencies, migrate them, then use value 0 where supported so only modern password hashes are generated.' `
                    'SAP Help: Parameters for Password Hash; SAP Cloud ALM supported checks'
            }
        }
        'login/min_password_lng' {
            if ($compact -match '^\d+$' -and [int]$compact -lt 12) {
                Add-Finding 'AUTH-006' 'Medium' 'Minimum ABAP password length is below current recommendation' $File `
                    "login/min_password_lng=$compact is below SAP Cloud ALM's current check value of 12. A client-specific security policy can override this profile value." `
                    'Confirm the effective security policy for every user group and raise the minimum to at least 12 where password logon remains enabled.' `
                    'SAP Cloud ALM supported checks; SAP Help security policy attributes'
            }
        }
        'rfc/reject_expired_passwd' {
            if ($compact -eq '0') {
                Add-Finding 'AUTH-007' 'Medium' 'RFC accepts expired passwords' $File `
                    'rfc/reject_expired_passwd=0 does not enforce rejection of expired passwords for RFC communication.' `
                    'Set the effective value to 1 after validating technical destinations and migrate non-interactive integrations to appropriate system users and stronger authentication.' `
                    'SAP Cloud ALM supported checks; HackTricks SAP parameter review'
            }
        }
        'icf/reject_expired_passwd' {
            if ($compact -eq '0') {
                Add-Finding 'AUTH-008' 'Medium' 'ICF accepts expired passwords' $File `
                    'icf/reject_expired_passwd=0 does not enforce rejection of expired passwords for ICF communication.' `
                    'Set the effective value to 1 after application testing and use appropriate non-dialog identities for integrations.' `
                    'SAP Cloud ALM supported checks'
            }
        }
        'rfc/callback_security_method' {
            if ($compact -match '^[0-2]$') {
                Add-Finding 'RFC-001' 'High' 'RFC callback allow-list enforcement is incomplete' $File `
                    "rfc/callback_security_method=$compact is below secure value 3; inactive callback allow-lists may not be enforced and value 0 invalidates all lists." `
                    'Build and test exact callback allow-lists in audit/simulation mode, remove wildcard function entries, then set value 3 and monitor Security Audit Log rejections.' `
                    'SAP Help: Logon and Security; Onapsis RFC callback research'
            }
        }
        'rfc/allowoldticket4tt' {
            if ($normalized -in @('YES','TRUE','ON') -or $compact -eq '1') {
                Add-Finding 'RFC-002' 'High' 'Legacy target-independent trusted RFC tickets are allowed' $File `
                    "rfc/allowoldticket4tt=$Value permits the old trusted/trusting method whose tickets are not bound to a target system." `
                    'Set rfc/allowoldticket4tt=no after validating trust relationships and apply the release-specific correction in SAP Note 3157268.' `
                    'SAP Help ABAP Platform profile changes; SEC Consult RFC research'
            }
        }
        'ucon/rfc/active' {
            if ($compact -and $compact -ne '1') {
                Add-Finding 'UCON-001' 'Medium' 'UCON RFC is not active' $File `
                    "ucon/rfc/active=$Value is not the recommended active value 1, so UCON phase/tool enforcement cannot provide its intended RFC function-module allow-list control." `
                    'Follow the SAP UCON phase procedure on every application server, derive exact function-module allow-lists without wildcards, monitor rejections, and set the effective value to 1.' `
                    'SAP Help: UCON CCMS Monitoring; SEC Consult RFC research'
            }
        }
        'abap/path_normalization' {
            if ($normalized -in @('OFF','FALSE') -or $compact -eq '0') {
                Add-Finding 'ABAP-001' 'High' 'ABAP path normalization is disabled' $File `
                    "abap/path_normalization=$Value disables a cross-platform directory-traversal protection used by ABAP file operations." `
                    'Enable the release-supported path normalization mode, test custom OPEN DATASET integrations, and review logical file/path and S_DATASET authorization design.' `
                    'SAP Cloud ALM directory-traversal check; SecuritySilverbacks filesystem attack paths'
            }
        }
        'gw/acl_mode' {
            if ($compact -eq '0') {
                Add-Finding 'GW-002' 'High' 'RFC Gateway restrictive fallback is disabled' $File `
                    'gw/acl_mode is 0. If secinfo/reginfo are absent or ineffective, external start/registration is unrestricted.' `
                    'Set gw/acl_mode=1 and maintain restrictive secinfo/reginfo; stage and monitor rules to avoid business disruption.' `
                    'SAP RFC Gateway security parameters'
            }
        }
        'gw/sim_mode' {
            if ($compact -eq '1') {
                Add-Finding 'GW-003' 'High' 'RFC Gateway ACL simulation mode is enabled' $File `
                    'gw/sim_mode=1 means gateway rules may be logged rather than enforced.' `
                    'Complete rule tuning, disable simulation mode, reload ACLs, and monitor rejected registrations/starts.' `
                    'SAP Gateway security guidance'
            }
        }
        'gw/acl_mode_proxy' {
            if ($compact -eq '0') {
                Add-Finding 'GW-004' 'High' 'RFC Gateway proxy restrictive fallback is disabled' $File `
                    'gw/acl_mode_proxy=0 disables the restrictive proxy fallback when prxyinfo rules are absent or incomplete.' `
                    'Set gw/acl_mode_proxy=1 and maintain a least-privilege prxyinfo ACL after impact testing.' `
                    'OWASP SSVS PT-I-IP-M01-005; SAP Gateway security settings'
            }
        }
        'gw/reg_no_conn_info' {
            if ($compact -eq '0') {
                Add-Finding 'GW-005' 'High' 'RFC Gateway additional security features are disabled' $File `
                    'gw/reg_no_conn_info=0 disables every security feature controlled by the bitmask.' `
                    'Review the kernel-specific valid bitmask and related SAP Notes; enable applicable protections without treating an arbitrary odd value as universally correct.' `
                    'SAP RFC Gateway security settings; OWASP SSVS PT-I-IP-M01-005'
            }
        }
        'gw/monitor' {
            if ($compact -match '^\d+$' -and [int]$compact -gt 1) {
                Add-Finding 'GW-006' 'High' 'RFC Gateway monitor permits remote access' $File `
                    "gw/monitor=$compact can permit the gateway monitor beyond local access." `
                    'Set gw/monitor=1 for local-only monitoring, then validate operational monitoring paths.' `
                    'OWASP SSVS PT-I-IP-M01-005; CBAS Attack Surface Discovery'
            }
        }
        'gw/rem_start' {
            if ($compact -and $normalized -notin @('DISABLED', 'DISABLE', 'SSH_SHELL')) {
                Add-Finding 'GW-007' 'High' 'RFC Gateway remote program start is enabled' $File `
                    'gw/rem_start is neither DISABLED nor SSH_SHELL. External-program start can become OS command execution when authorization and secinfo controls fail.' `
                    'Set gw/rem_start=DISABLED where possible. For a documented dependency, use the supported SSH_SHELL path and restrictive secinfo rules.' `
                    'OWASP Pentest Playbook: OS command execution; SSVS PT-I-IP-M01-005'
            }
        }
        { $_ -eq 'snc/permit_insecure_comm' -or $_ -eq 'snc/permit_insecure_start' } {
            if ($compact -eq '1') {
                Add-Finding 'SNC-001' 'Medium' 'SNC configuration permits insecure communication' $File `
                    "$Name is enabled, allowing a fallback path without SNC protection." `
                    'Confirm compatibility requirements, then disallow insecure paths and require SNC for sensitive RFC/DIAG traffic.' `
                    'OWASP SAP Pentest Playbook and SAP SNC parameters'
            }
        }
        { $_ -match '^snc/accept_insecure_(gui|rfc|cpic|r3int_rfc)$' } {
            if ($compact -eq '1') {
                Add-Finding 'SNC-002' 'Medium' 'SNC accepts an insecure connection class' $File `
                    "$Name=1 permits this connection class without SNC protection." `
                    'Confirm migration dependencies, then require SNC for sensitive channels and validate destinations before removing compatibility fallback.' `
                    'SAP SNC security parameters; OWASP sncscan research'
            }
        }
        { $_ -match '^snc/data_protection/(min|use|max)$' } {
            if ($compact -match '^\d+$' -and [int]$compact -lt 3) {
                Add-Finding 'SNC-003' 'Medium' 'SNC quality of protection is below privacy' $File `
                    "$Name=$compact permits authentication-only or integrity-only protection rather than data privacy." `
                    'For sensitive traffic, test the SNC chain and configure minimum, default, and maximum values to negotiate privacy (3) consistently.' `
                    'SAP SNC QoP documentation; OWASP sncscan'
            }
        }
        'snc/only_encrypted_gui' {
            if ($compact -eq '0') {
                Add-Finding 'SNC-004' 'Medium' 'Encrypted SAP GUI connections are not enforced' $File `
                    'snc/only_encrypted_gui=0 allows SAP GUI connections without SNC.' `
                    'After confirming every client has working SNC, set snc/only_encrypted_gui=1 and monitor rejected logons.' `
                    'OWASP sncscan; SAP SNC configuration'
            }
        }
        'snc/enable' {
            if ($compact -eq '0') {
                Add-Finding 'SNC-005' 'Medium' 'Secure Network Communications is disabled' $File `
                    'snc/enable=0 means the application server does not initialize SNC. Network isolation alone does not provide DIAG/RFC confidentiality or peer authentication.' `
                    'Plan SNC with the SAP Cryptographic Library or supported security product, provision the PSE/identity first, set snc/enable=1, and validate protection for each client and destination.' `
                    'SAP Help: snc/enable; OWASP PySAP SNC documentation'
            }
        }
        { $_ -eq 'ms/monitor' -or $_ -eq 'ms/admin_port' } {
            if ($compact -match '^[1-9]\d*$') {
                Add-Finding 'MS-002' 'Medium' 'SAP Message Server administration/monitor function is enabled' $File `
                    "$Name has a non-zero value. Reachability and ACLs determine exploitability." `
                    'Disable if unused; otherwise restrict binding/firewalls and maintain the relevant message-server ACL.' `
                    'SAP Message Server security settings'
            }
        }
        'system/secure_communication' {
            if ($compact -and $normalized -ne 'ON') {
                Add-Finding 'MS-004' 'Medium' 'SAP internal server communication is not secured' $File `
                    "system/secure_communication=$Value is not ON, so supported secure communication between application servers and the Message Server is not enabled." `
                    'Follow the release-specific SAP Notes, set the effective value to ON where the kernel supports it, and retain restrictive Message Server ACL and network controls.' `
                    'SAP EarlyWatch Alert security guidance; SAP Note 2040644'
            }
        }
        { $_ -match '^(ms/acl_info|gw/sec_info|gw/reg_info|gw/prxy_info)$' } {
            if ([IO.Path]::IsPathRooted($Value)) {
                $configuredAcl = if ($script:CustomRoot) { ConvertTo-PhysicalPath $Value } else { $Value }
                if (Test-Path -LiteralPath $configuredAcl) {
                    Add-PathEvidence $configuredAcl 'ACL' "Referenced by $Name"
                } else {
                    Add-Finding 'ACL-003' 'High' 'Configured SAP ACL file is missing' $File `
                        "$Name references $Value, but that file was not present in the audited root." `
                        'Confirm profile substitution and instance context, then restore a protected least-privilege ACL before relying on the control.' `
                        'SAP Gateway/Message Server ACL guidance'
                }
            }
        }
        'service/protectedwebmethods' {
            $baseSetting = ($normalized -split '\s+')[0]
            if (-not $compact -or $baseSetting -in @('NONE', 'DEFAULT')) {
                Add-Finding 'START-001' 'High' 'SAP Start Service web methods are not strongly protected' $File `
                    "service/protectedwebmethods is $Value; NONE leaves all methods public and DEFAULT exposes more read/trace methods than SDEFAULT." `
                    'Use SDEFAULT or ALL with narrowly justified exceptions, and restrict HTTP/HTTPS endpoints with supported ACL parameters.' `
                    'SAP Start Service security guidance; OWASP SSVS PT-P-DS-M01-002/PT-P-DS-M01-003'
            }
        }
        'rdisp/call_system' {
            if ($compact -eq '1') {
                Add-Finding 'OSCMD-001' 'High' 'ABAP CALL SYSTEM is enabled' $File `
                    'rdisp/call_system=1 enables a legacy path that executes OS commands in the SAP service-user context.' `
                    'Set rdisp/call_system=0 after dependency testing; use controlled SXPG commands and least-privilege authorization for required integrations.' `
                    'OWASP Pentest Playbook: OS command execution; SAP KBA 2879860'
            }
        }
        'rec/client' {
            if (-not $compact -or $compact -eq '0' -or $normalized -eq 'OFF') {
                Add-Finding 'LOG-001' 'Medium' 'ABAP table-change logging is disabled' $File `
                    "rec/client is $Value, so changes to log-enabled tables may not be captured." `
                    'Define required clients (or ALL where policy requires), confirm critical tables are log-enabled, protect the logs, and monitor retention.' `
                    'OWASP SSVS DT-P-AE-M01-004'
            }
        }
        'rsau/enable' {
            if ($compact -eq '0') {
                Add-Finding 'LOG-002' 'Medium' 'Static Security Audit Log profile is disabled' $File `
                    'rsau/enable=0 disables the static profile switch for the ABAP Security Audit Log. A dynamic configuration can differ, so this is evidence of a profile gap rather than proof that no audit events are recorded.' `
                    'Review the effective configuration and filters in SM19/RSAU_CONFIG on every application server, enable the Security Audit Log where required, and validate protected retention and central monitoring in SM20.' `
                    'SAP Security Audit Log documentation; SAP Cloud ALM supported checks'
            }
        }
        'is/http/show_detailed_errors' {
            if ($normalized -eq 'TRUE' -or $compact -eq '1') {
                Add-Finding 'ICM-001' 'Medium' 'ICM/Web Dispatcher returns detailed errors' $File `
                    "is/HTTP/show_detailed_errors=$Value can disclose host, module, component, and error details." `
                    'Set FALSE for exposed services and use protected local traces for diagnostics.' `
                    'SAP ICM security guidance; OWASP SSVS information-disclosure controls'
            }
        }
        'is/http/show_server_header' {
            if ($normalized -eq 'TRUE' -or $compact -eq '1') {
                Add-Finding 'ICM-002' 'Low' 'ICM/Web Dispatcher server header is enabled' $File `
                    "is/HTTP/show_server_header=$Value exposes service identity/version clues." `
                    'Set FALSE unless a documented dependency requires the header.' `
                    'SAP ICM/Web Dispatcher hardening guidance'
            }
        }
        'icm/http/allow_invalid_host_header' {
            if ($normalized -in @('TRUE','YES') -or $compact -eq '1') {
                Add-Finding 'ICM-004' 'Medium' 'ICM accepts invalid HTTP Host headers' $File `
                    "icm/HTTP/allow_invalid_host_header=$Value accepts invalid or duplicate Host headers contrary to the protocol and weakens request-routing validation." `
                    'Restore the SAP default FALSE, validate reverse-proxy routing, and separately test Web Dispatcher/ICM request handling from authorized zones.' `
                    'SAP Help: icm/HTTP/allow_invalid_host_header; Attack Surface Discovery parameter inventory'
            }
        }
        'icf/set_httponly_flag_on_cookies' {
            if ($compact -match '^[1-3]$') {
                Add-Finding 'ICM-005' 'Medium' 'HttpOnly is disabled for one or more ICF cookie classes' $File `
                    "icf/set_HTTPonly_flag_on_cookies=$compact disables HttpOnly for some or all ICF cookies, allowing client-side code to access affected cookies." `
                    'After application compatibility testing, use value 0 and activate HTTP security session management in SICF_SESSIONS.' `
                    'SAP Help: Session Security Protection'
            }
        }
        'login/ticket_only_by_https' {
            if ($compact -eq '0') {
                Add-Finding 'ICM-006' 'High' 'ABAP logon tickets are not restricted to HTTPS' $File `
                    'login/ticket_only_by_https=0 allows the browser to send logon-ticket and security-session cookies over unencrypted HTTP.' `
                    'Enforce HTTPS for the complete authentication path, set the effective value to 1, and confirm secure cookie/session behavior through the supported ICF configuration.' `
                    'SAP Help: Session Security Protection'
            }
        }
        { $_ -like 'icm/http/file_access_*' -or $_ -like 'icm/http/file_access-*' } {
            if ($Value -match '(?i)DOCROOT\s*=\s*([/\\]|\.\.)') {
                Add-Finding 'ICM-003' 'Critical' 'ICM file alias may expose a broad filesystem path' $File `
                    "$Name maps DOCROOT to a root or parent-relative location; the report does not copy the full value." `
                    'Remove broad aliases, constrain DOCROOT to a dedicated non-sensitive directory, and require an appropriate icm/HTTP/auth rule.' `
                    'OWASP Pentest Playbook: filesystem read'
            }
        }
        { $_ -match '^execute_\d+$' } {
            if ($compact) {
                Add-Finding 'OSCMD-002' 'High' 'Instance profile executes an operating-system command' $File `
                    "$Name is configured and runs in the SAP service-user context at instance startup." `
                    'Verify command, owner, target, quoting, and need; prefer a controlled service unit and remove all user-controlled input.' `
                    'OWASP Pentest Playbook: OS command execution'
            }
        }
        'igs/listener/http' {
            if ($Value -match '(?i)administration') {
                Add-Finding 'IGS-001' 'High' 'IGS HTTP administration commands appear enabled' $File `
                    'igs/listener/http includes administration; older IGS HTTP administration commands may lack authentication.' `
                    'Remove administration unless required, restrict the listener, and verify IGS patch level and SAP Notes.' `
                    'OWASP SAP Pentest Playbook: IGS'
            }
        }
        { $_ -match '^rsec/ssfs_(data|key|lky)path$' } {
            if ([IO.Path]::IsPathRooted($Value)) { [void]$script:ConfiguredSsfsPaths.Add($Value) }
        }
    }
    if ((Test-SensitiveParameterName $Name) -and -not [string]::IsNullOrWhiteSpace($compact) -and
        $compact -notmatch '(\$\(|\$\{|^\*+$)') {
        Add-Finding 'CFG-001' 'High' 'Profile contains a non-empty secret-like parameter' $File `
            "Parameter $Name has a literal-looking value. SAPstract deliberately did not record it." `
            'Move secrets to an SAP-supported secure store, rotate if exposure is possible, and remove them from profiles and backups.' `
            'OWASP CBAS filesystem-read and credential exposure'
    }
}

function Scan-AclFile {
    param([string]$Path)
    $logical = ConvertTo-LogicalPath $Path
    Add-PathEvidence $Path 'ACL' ([IO.Path]::GetFileName($Path))
    try {
        $lines = @(Get-Content -LiteralPath $Path -ErrorAction Stop)
        $active = @($lines | Where-Object { $_ -notmatch '^\s*[#;]' -and $_ -match '\S' })
        if ($active.Count -eq 0) {
            Add-Finding 'ACL-002' 'Medium' 'SAP access-control file is empty' $logical `
                'The ACL exists but contains no active rules.' `
                'Confirm the component empty-file semantics and populate a deny-by-default, least-privilege policy.' `
                'SAP component ACL documentation'
        }
        $activeText = $active -join "`n"
        $broadWildcard = $activeText -match '(?im)(^|[\s,])(P|KT)\s+.*(TP|USER|HOST|SNC|SOURCE|DEST|S)=\*|^\s*P\s+\*\s+\*\s+\*'
        if ([IO.Path]::GetFileName($Path) -ieq 'saprouttab' -and
            $activeText -match '(?im)^\s*[PS]\s+[^#;\s]+\s+\*(\s|$)') {
            $broadWildcard = $true
        }
        if ($broadWildcard) {
            Add-Finding 'ACL-001' 'High' 'SAP access-control file contains a broad wildcard rule' $logical `
                'A permissive wildcard pattern was detected, including positional SAProuter target-host wildcards; rule contents were not copied into the report.' `
                'Replace broad permits with explicit program/user/host or route entries, test safely, and reload through the component-supported method.' `
                'SAP RFC Gateway guidance; SAP Note 1895350; SEC Consult CVE-2022-27668'
        }
    } catch {}
}

function Scan-ProfilesAndAcls {
    Write-AuditLog 'Inspecting SAP profiles and security configuration'
    $candidates = New-Object System.Collections.Generic.List[IO.FileInfo]
    $count = 0
    foreach ($root in Get-SapRoots) {
        try {
            foreach ($file in @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue)) {
                $name = $file.Name
                $full = $file.FullName
                if ($full -match '(?i)[/\\](SYS[/\\]profile|profile)[/\\]' -or
                    $name -match '^(?i)(DEFAULT\.PFL|START_.+|secinfo|reginfo|saprouttab|icmauth\.txt|icm_filter_rules\.txt|host_profile|sapprofile\.ini|global\.ini|nameserver\.ini|indexserver\.ini|xsengine\.ini|daemon\.ini|instance\.properties|local\.properties|config_master)$') {
                    [void]$candidates.Add($file)
                    $count++
                    if ($count -ge $MaxFiles) { break }
                }
            }
        } catch {}
        if ($count -ge $MaxFiles) { break }
    }
    foreach ($file in @($candidates | Sort-Object FullName -Unique)) {
        if ($file.Name -match '^(?i)(secinfo|reginfo|saprouttab|icmauth\.txt|icm_filter_rules\.txt)$') {
            Scan-AclFile $file.FullName
            continue
        }
        Add-PathEvidence $file.FullName 'Profile' 'SAP profile/configuration'
        try {
            foreach ($lineRaw in @(Get-Content -LiteralPath $file.FullName -ErrorAction Stop)) {
                $line = $lineRaw.Trim()
                if (-not $line -or $line.StartsWith('#') -or $line.StartsWith(';') -or -not $line.Contains('=')) { continue }
                $index = $line.IndexOf('=')
                $name = $line.Substring(0, $index).Trim()
                $value = $line.Substring($index + 1).Trim()
                if ($name) { Add-ProfileParameter (ConvertTo-LogicalPath $file.FullName) $name $value }
            }
        } catch {}
    }
    if ($count -ge $MaxFiles) {
        $script:TruncatedScans++
        Add-Coverage 'Profiles and ACLs' 'partial' "Stopped at MaxFiles=$MaxFiles"
    } else {
        Add-Coverage 'Profiles and ACLs' 'complete' 'Known profile/ACL names inspected; secret-like values redacted'
    }
}

function Read-BytesHex {
    param([string]$Path, [int]$Count = 12)
    $stream = $null
    try {
        $stream = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        $buffer = New-Object byte[] $Count
        $read = $stream.Read($buffer, 0, $Count)
        return (($buffer[0..([Math]::Max(0, $read - 1))] | ForEach-Object { $_.ToString('x2') }) -join '')
    } catch { return '' }
    finally { if ($null -ne $stream) { $stream.Dispose() } }
}

function Get-SsfsDataShape {
    param([string]$Path, [long]$Size)
    $stream = $null
    $offset = [long]0
    $count = 0
    $status = 'recognized structure'
    try {
        $stream = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        while (($offset + 176) -le $Size -and $count -lt 10000) {
            [void]$stream.Seek($offset, [IO.SeekOrigin]::Begin)
            $header = New-Object byte[] 16
            if ($stream.Read($header, 0, 16) -ne 16) { $status = "short header at offset $offset"; break }
            $magic = [Text.Encoding]::ASCII.GetString($header, 0, 12)
            if ($magic -ne 'RSecSSFsData') { $status = "trailing or unrecognized bytes at offset $offset"; break }
            $le = [BitConverter]::ToUInt32($header, 12)
            $beBytes = @($header[15], $header[14], $header[13], $header[12])
            $be = [BitConverter]::ToUInt32([byte[]]$beBytes, 0)
            $remaining = $Size - $offset
            if ($le -ge 176 -and $le -le $remaining) { $length = [long]$le }
            elseif ($be -ge 176 -and $be -le $remaining) { $length = [long]$be }
            else { $status = "invalid record length at offset $offset"; break }
            $offset += $length
            $count++
        }
        if ($offset -eq $Size) { $status = 'recognized structure' }
        elseif ($count -eq 0 -and $Size -eq 0) { $status = 'empty data file' }
    } catch {
        $status = "inspection error: $($_.Exception.Message)"
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
    [pscustomobject]@{ Count = $count; Status = $status }
}

function Get-SsfsClassification {
    param([string]$Logical, [string]$Name)
    $upper = $Name.ToUpperInvariant()
    $family = 'Generic SAP SSFS'
    if ($Logical -match '(?i)[/\\]scc_config[/\\]' -or $upper -match '^SSFS_SCC\.') {
        $family = 'SAP Cloud Connector SSFS'
    } elseif ($Logical -match '(?i)[/\\]\.hdb[/\\]' -or ($upper -match '^SSFS_HDB\.' -and $Logical -match '(?i)[/\\](Users|home)[/\\]')) {
        $family = 'SAP HANA client user store'
    } elseif ($Logical -match '(?i)[/\\]global[/\\]hdb[/\\]security[/\\]ssfs[/\\]') {
        $family = 'SAP HANA instance SSFS'
    } elseif ($Logical -match '(?i)[/\\]global[/\\]security[/\\]rsecssfs[/\\]') {
        $family = 'ABAP / HANA System-PKI RSEC SSFS'
    } elseif ($Logical -match '(?i)[/\\]rsecssfs[/\\]') {
        $family = 'RSEC SSFS'
    }
    $sid = ''
    if ($upper -match '^SSFS_([A-Z0-9]{3})\.') { $sid = $Matches[1] }
    elseif ($upper -match '^SSFS_([^.]*)\.') { $sid = $Matches[1] }
    $role = 'SSFS artifact'; $detail = ''
    switch -Regex ($upper) {
        '\.DAT$' { $role = 'SSFS data'; $detail = 'Active secure-store data'; break }
        '\.DA_$' { $role = 'SSFS data backup'; $detail = 'Recovery copy before a non-trivial data change'; break }
        '\.KEY$' { $role = 'SSFS key'; $detail = 'Individual master-key material'; break }
        '\.KE_$' { $role = 'SSFS key backup'; $detail = 'Recovery copy of individual master-key material'; break }
        '\.LCK$' { $role = 'SSFS lock'; $detail = 'Store lock metadata'; break }
        '\.LKY$' { $role = 'SSFS local protection'; $detail = 'Enhanced/key-protection local key material'; break }
    }
    [pscustomobject]@{ Family = $family; Sid = $sid; Role = $role; Detail = $detail }
}

function Add-SsfsEvidence {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $logical = ConvertTo-LogicalPath $Path
    if ($script:SeenSsfs.ContainsKey($logical)) { return }
    $script:SeenSsfs[$logical] = $true
    try { $evidence = Get-PathEvidence $Path } catch { return }
    $name = [IO.Path]::GetFileName($Path)
    $upper = $name.ToUpperInvariant()
    $stem = [IO.Path]::GetFileNameWithoutExtension($upper)
    $class = Get-SsfsClassification $logical $name
    $detail = $class.Detail
    $hex = Read-BytesHex $Path 12
    if ($class.Role -match '^SSFS data') {
        $shape = Get-SsfsDataShape $Path $evidence.Size
        $detail += "; $($shape.Count) record(s); $($shape.Status); values not read"
        if (-not $script:SsfsData.ContainsKey($stem)) { $script:SsfsData[$stem] = New-Object System.Collections.Generic.List[string] }
        [void]$script:SsfsData[$stem].Add($logical)
        $script:SsfsFamily[$stem] = $class.Family
    } elseif ($class.Role -match '^SSFS key') {
        $typeByte = ''
        $stream = $null
        try {
            $stream = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
            [void]$stream.Seek(11, [IO.SeekOrigin]::Begin)
            $typeByte = $stream.ReadByte()
        } catch {} finally { if ($null -ne $stream) { $stream.Dispose() } }
        if ($hex.StartsWith('52536563535346734b6579')) {
            $detail += "; recognized RSecSSFsKey; type $typeByte; $($evidence.Size) bytes; key bytes not read"
        } else { $detail += '; header not recognized; key bytes not read' }
        if (-not $script:SsfsKey.ContainsKey($stem)) { $script:SsfsKey[$stem] = New-Object System.Collections.Generic.List[string] }
        [void]$script:SsfsKey[$stem].Add($logical)
    } elseif ($class.Role -eq 'SSFS local protection' -and $hex.StartsWith('52536563535346734c4b59')) {
        $detail += '; recognized RSecSSFsLKY preamble'
    } elseif ($class.Role -eq 'SSFS lock' -and $hex -eq '52536563535346734c6f636b') {
        $detail += '; recognized RSecSSFsLock preamble'
    }
    Add-TableRow Ssfs ([ordered]@{
        family = $class.Family; sid = $class.Sid; role = $class.Role
        path = $logical; size_bytes = $evidence.Size; owner = $evidence.Owner
        group = $evidence.Group; mode = $evidence.Mode; acl = $evidence.AclSummary
        detail = $detail
    })
    $permissionCategory = $class.Role
    if ($permissionCategory -eq 'SSFS key backup') { $permissionCategory = 'SSFS key' }
    if ($permissionCategory -eq 'SSFS data backup') { $permissionCategory = 'SSFS data' }
    Add-PathEvidence $Path $permissionCategory "$($class.Family); secret-bearing metadata only"
    $script:SapEvidenceCount++
}

function Scan-Ssfs {
    Write-AuditLog 'Discovering all recognized SAP SSFS families'
    $roots = New-Object System.Collections.Generic.List[string]
    foreach ($root in Get-SensitiveArtifactRoots) { [void]$roots.Add($root) }
    foreach ($configured in @(
        [Environment]::GetEnvironmentVariable('RSEC_SSFS_DATAPATH'),
        [Environment]::GetEnvironmentVariable('RSEC_SSFS_KEYPATH'),
        [Environment]::GetEnvironmentVariable('RSEC_SSFS_LKYPATH'),
        [Environment]::GetEnvironmentVariable('HDB_USE_STORE_PATH')
    ) + @($script:ConfiguredSsfsPaths)) {
        if ([string]::IsNullOrWhiteSpace($configured)) { continue }
        $candidate = if ($script:CustomRoot -and [IO.Path]::IsPathRooted($configured)) {
            ConvertTo-PhysicalPath ($configured.Replace('\', '/'))
        } else { $configured }
        if (Test-Path -LiteralPath $candidate -PathType Container) { [void]$roots.Add($candidate) }
    }
    $count = 0
    foreach ($root in @($roots | Select-Object -Unique)) {
        try {
            foreach ($file in @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue)) {
                if ($file.Name -notmatch '^(?i)SSFS_.+\.(DAT|DA_|KEY|KE_|LCK|LKY)$') { continue }
                Add-SsfsEvidence $file.FullName
                $count++
                if ($count -ge $MaxFiles) { break }
            }
        } catch {}
        if ($count -ge $MaxFiles) { break }
    }
    foreach ($stem in @($script:SsfsData.Keys)) {
        if ($script:SsfsKey.ContainsKey($stem)) { continue }
        $data = ($script:SsfsData[$stem] -join '; ')
        $family = [string]$script:SsfsFamily[$stem]
        if ($family -eq 'SAP Cloud Connector SSFS') {
            Add-Finding 'SSFS-005' 'High' 'Cloud Connector SSFS has no individual key file in audited paths' $data `
                'SCC SSFS data was observed without a matching .KEY. This may be the product compatibility/default-key mode, or a separate configured key path.' `
                'Confirm the SCC version and supported key lifecycle with SAP, tightly restrict scc_config, and change key mode only through a supported procedure.' `
                'SAP SSFS key-management guidance; SCC context must be validated'
        } elseif ($family -eq 'SAP HANA client user store') {
            Add-Finding 'SSFS-006' 'High' 'HANA user-store data has no matching host key' $data `
                'SSFS_HDB.DAT was found without SSFS_HDB.KEY in audited paths; the pair is normally host/user bound.' `
                'Run hdbuserstore as the owning account to validate, restore only the matched host-bound key, or recreate entries.' `
                'SAP HANA secure user store guidance'
        } else {
            Add-Finding 'SSFS-007' 'High' 'SSFS data has no matching individual key in audited paths' $data `
                "No matching $stem.KEY was observed. For ABAP SSFS, absence can mean the built-in default key, or the key path may be outside scope." `
                'Use official rsecssfx info/list with the instance profile. SAP recommends an individual key; never replace key files ad hoc.' `
                'SAP SSFS key-management guidance'
        }
    }
    foreach ($stem in @($script:SsfsKey.Keys)) {
        if ($script:SsfsData.ContainsKey($stem)) { continue }
        Add-Finding 'SSFS-008' 'Medium' 'SSFS key has no matching data file in audited paths' ($script:SsfsKey[$stem] -join '; ') `
            'A key artifact was observed without matching data. The data path may be separate or the key may be orphaned.' `
            'Resolve the configured data path and validate with official tooling. Preserve recovery copies before cleanup; never substitute an unrelated key.' `
            'SAP SSFS recovery guidance'
    }
    if ($count -ge $MaxFiles) {
        $script:TruncatedScans++
        Add-Coverage 'SSFS' 'partial' "Stopped at MaxFiles=$MaxFiles"
    } else {
        Add-Coverage 'SSFS' 'complete' 'ABAP/RSEC, HANA instance, HANA System-PKI, hdbuserstore, enhanced LKY, and SCC naming/layouts inspected; values/key bytes not read'
    }
}

function Get-ToolComponent {
    param([string]$Name)
    switch -Regex ($Name) {
        '^(?i)rsecssfx' { 'SSFS administration'; break }
        '^(?i)sapcontrol' { 'SAP Start Service client'; break }
        '^(?i)(saphostctrl|saphostexec)' { 'SAP Host Agent'; break }
        '^(?i)saprouter' { 'SAProuter'; break }
        '^(?i)sapwebdisp' { 'SAP Web Dispatcher'; break }
        '^(?i)sapgenpse' { 'SAP cryptographic/PSE administration'; break }
        '^(?i)sapcar' { 'SAP archive utility'; break }
        '^(?i)niping' { 'SAP NI diagnostic'; break }
        '^(?i)(startrfc|rfcexec)' { 'SAP RFC utility'; break }
        '^(?i)hdbsql' { 'SAP HANA SQL client'; break }
        '^(?i)hdbuserstore' { 'SAP HANA secure user store'; break }
        '^(?i)hdblcm' { 'SAP HANA lifecycle manager'; break }
        '^(?i)(dataserver|backupserver|bcksrvr|jsagent)' { 'SAP ASE database service'; break }
        '^(?i)(disp\+work|dw\.sap)' { 'SAP kernel dispatcher'; break }
        '^(?i)gwrd' { 'SAP RFC Gateway'; break }
        '^(?i)ms\.sap' { 'SAP Message Server'; break }
        '^(?i)icmon' { 'SAP ICM monitor'; break }
        '^(?i)msmon' { 'SAP Message Server monitor'; break }
        '^(?i)r3trans' { 'SAP transport/database utility'; break }
        '^(?i)tp(\.exe)?$' { 'SAP transport control'; break }
        default { 'SAP utility' }
    }
}

function Add-ToolEvidence {
    param([string]$Path, [string]$Source)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    try { $resolved = (Get-Item -LiteralPath $Path -Force).FullName } catch { return }
    $logical = ConvertTo-LogicalPath $resolved
    if ($script:SeenTool.ContainsKey($logical)) { return }
    $script:SeenTool[$logical] = $true
    try { $evidence = Get-PathEvidence $resolved } catch { return }
    $name = [IO.Path]::GetFileName($resolved)
    $component = Get-ToolComponent $name
    $hash = ''
    if ($evidence.Size -le 104857600) {
        try { $hash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() } catch {}
    }
    $version = ''
    try { $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($resolved).FileVersion } catch {}
    $signature = ''
    $signer = ''
    if ($script:IsWindowsHost) {
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $resolved -ErrorAction Stop
            $signature = [string]$sig.Status
            if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
            if ($signature -eq 'HashMismatch' -or $signature -eq 'NotTrusted') {
                Add-Finding 'TOOL-002' 'High' 'SAP executable has an invalid or untrusted Authenticode signature' $logical `
                    "Signature status is $signature." `
                    'Quarantine from service execution, compare the hash with approved SAP media, and restore through the trusted patch/deployment process.' `
                    'Windows code-signing integrity'
            }
        } catch {}
    }
    Add-TableRow Tools ([ordered]@{
        name = $name; component = $component; path = $logical; source = $Source
        version = $version; owner = $evidence.Owner; group = $evidence.Group
        mode = $evidence.Mode; acl = $evidence.AclSummary; size_bytes = $evidence.Size
        sha256 = $hash; signature_status = $signature; signer = $signer
    })
    Add-PathEvidence $resolved 'Executable' $component
    $script:SapEvidenceCount++
    try {
        $parent = Split-Path -Parent $resolved
        if ($script:IsWindowsHost) {
            Test-WeakWindowsAcl $parent 'Executable'
        } else {
            $parentEvidence = Get-PathEvidence $parent
            if ($parentEvidence.Mode.Length -ge 3) {
                $triad = $parentEvidence.Mode.Substring($parentEvidence.Mode.Length - 3)
                $groupDigit = [Convert]::ToInt32($triad.Substring(1, 1), 8)
                $otherDigit = [Convert]::ToInt32($triad.Substring(2, 1), 8)
                if ((($groupDigit -band 2) -ne 0) -or (($otherDigit -band 2) -ne 0)) {
                    Add-Finding 'TOOL-001' 'High' 'SAP tool resides in a writable directory' $logical `
                        "Parent $(ConvertTo-LogicalPath $parent) has mode $($parentEvidence.Mode)." `
                        'Restrict directory writes, verify the tool digest, and inspect service/PATH search order.' `
                        'OWASP CBAS OS command execution and code integrity'
                }
            }
        }
    } catch {}
}

function Scan-Tools {
    Write-AuditLog 'Inventorying SAP administration and runtime tools'
    $names = @('rsecssfx', 'sapcontrol', 'saphostctrl', 'saphostexec', 'saprouter', 'sapwebdisp',
        'sapgenpse', 'SAPCAR', 'sapcar', 'niping', 'startrfc', 'rfcexec', 'hdbsql',
        'hdbuserstore', 'hdblcm', 'dataserver', 'backupserver', 'bcksrvr', 'disp+work', 'gwrd', 'ms.sap', 'icmon', 'msmon',
        'R3trans', 'tp', 'sapstartsrv')
    foreach ($name in $names) {
        $command = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($command) { Add-ToolEvidence $command.Source 'PATH' }
    }
    $pattern = '^(?i)(rsecssfx.*|sapcontrol.*|saphostctrl.*|saphostexec.*|saprouter.*|sapwebdisp.*|sapgenpse.*|sapcar.*|niping.*|startrfc.*|rfcexec.*|hdbsql.*|hdbuserstore.*|hdblcm.*|dataserver.*|backupserver.*|bcksrvr.*|disp\+work|dw\.sap.*|gwrd|ms\.sap.*|icmon.*|msmon.*|r3trans.*|tp(\.exe)?|sapstartsrv.*)$'
    $count = 0
    foreach ($root in Get-SapRoots) {
        try {
            foreach ($file in @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue)) {
                if ($file.Name -notmatch $pattern) { continue }
                Add-ToolEvidence $file.FullName 'SAP filesystem'
                $count++
                if ($count -ge $MaxFiles) { break }
            }
        } catch {}
        if ($count -ge $MaxFiles) { break }
    }
    if ($count -ge $MaxFiles) {
        $script:TruncatedScans++
        Add-Coverage 'Tools' 'partial' "Stopped at MaxFiles=$MaxFiles"
    } else {
        Add-Coverage 'Tools' 'complete' 'PATH and standard SAP roots inspected; binaries were not executed'
    }
}

function Scan-SapRegistry {
    if (-not $script:IsWindowsHost -or $script:CustomRoot) {
        Add-Coverage 'SAP registry' 'not applicable' 'Non-Windows or alternate-root collection'
        return
    }
    Write-AuditLog 'Inspecting SAP registry footprints'
    $found = 0
    foreach ($root in @('HKLM:\SOFTWARE\SAP', 'HKLM:\SOFTWARE\WOW6432Node\SAP')) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($sidKey in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^[A-Za-z][A-Za-z0-9]{2}$' })) {
            $sid = $sidKey.PSChildName.ToUpperInvariant()
            $envKey = Join-Path $sidKey.PSPath 'Environment'
            $properties = $null
            try { $properties = Get-ItemProperty -LiteralPath $envKey -ErrorAction Stop } catch {}
            if (-not (Test-SapRegistrySidEvidence $sid $properties)) { continue }
            $alreadyKnown = $script:SapSids.ContainsKey($sid)
            Register-SapInstance $sid
            if (-not $alreadyKnown) {
                $key = "$sid|registry"
                $script:SeenSystem[$key] = $true
                Add-TableRow Systems ([ordered]@{ sid = $sid; stack = 'SAP (registry)'; instances = ''; root = ''; source = $sidKey.PSPath })
            }
            if ($null -ne $properties) {
                foreach ($name in @('SAPSYSTEMNAME', 'SAPLOCALHOST', 'DBMS_TYPE', 'SAPEXE', 'RSEC_SSFS_DATAPATH', 'RSEC_SSFS_KEYPATH', 'RSEC_SSFS_LKYPATH')) {
                    $property = $properties.PSObject.Properties[$name]
                    $value = if ($null -ne $property) { [string]$property.Value } else { '' }
                    if ($value) {
                        Add-ProfileParameter $envKey $name $value 'registry'
                        if ($name -match '^RSEC_SSFS_' -and [IO.Path]::IsPathRooted($value)) { [void]$script:ConfiguredSsfsPaths.Add($value) }
                    }
                }
            }
            $found++; $script:SapEvidenceCount++; $script:SapServerEvidenceCount++
        }
    }
    Add-Coverage 'SAP registry' 'complete' "$found SID registry footprint(s)"
}

function Build-AssessmentCatalog {
    Add-Assessment 'Host footprint and permissions' 'automated' 'Processes, services, sockets, paths, owners, modes/ACLs, profiles, tools, and hashes' 'Review every finding and repeat with elevation if collection is partial.' 'OWASP SSVS OS controls; PySAP recognition'
    Add-Assessment 'RFC Gateway and Message Server' 'automated + manual' 'Local ports, profiles, secinfo/reginfo/prxyinfo/message ACL metadata' 'Use an authorized segmented-zone test to prove external reachability and effective ACL behavior.' 'OWASP SSVS; Attack Surface Discovery; Pentest Playbook'
    Add-Assessment 'Dispatcher, DIAG, SNC, SAProuter' 'automated + manual' 'Port/profile/SNC/saprouttab evidence' 'Use authorized sncscan/SAP tooling to prove negotiated QoP and external route exposure.' 'OWASP sncscan; HoneySAP; Pentest Playbook'
    Add-Assessment 'ICM, IGS, Start Service, Web Dispatcher' 'automated + manual' 'Listener, error/header, file alias, IGS admin, protected-method, ACL, and port evidence' 'Perform approved HTTP/TLS and authentication validation from each trust zone.' 'Attack Surface Discovery; Pentest Playbook; OWASP SSVS'
    Add-Assessment 'SAP Cloud Connector and BTP' 'footprint + manual' 'SCC service/process/config/SSFS/keystore paths and listener evidence' 'Review SCC patch/JDK, HA, trust, roles, alerts, destinations, identity providers, and BTP controls in authenticated consoles.' 'OWASP SSVS BTP controls; CBAS exposure research'
    Add-Assessment 'SAP HANA and ASE' 'footprint + manual' 'Processes, ports, paths, INI/SSFS/user-store metadata, and permissions' 'Use read-only audit roles to review users, roles, passwords, audit, tenants, TLS, replication, and patch level.' 'OWASP SSVS HANA controls; Attack Surface Discovery'
    Add-Assessment 'ABAP identity and authorization' 'manual/authenticated' 'Not derivable reliably from host files' 'Review standard users, SAP_ALL, S_RFC/S_RFCACL, critical transactions/tables, password/hash policy, RFC destinations, and trust.' 'OWASP SAPKiln; SSVS; Pentest Playbook'
    Add-Assessment 'ABAP code and business data' 'manual/authenticated' 'Host artifacts cannot prove authorization checks, injection resistance, traversal, or data classification' 'Run SCI/ATC/CVA and controlled reviews for filesystem, database, dynamic code, OS commands, RFC modules, and sensitive data.' 'OWASP SSVS IY controls; Pentest Playbook'
    Add-Assessment 'Logging and detection' 'partial + manual' 'Local audit/system/trace presence and selected logging profiles' 'Validate SAL, SM21, table logging, RAL, workload/user reports, HANA/Java/BTP audit, central forwarding, alerts, integrity, and retention.' 'OWASP SSVS DT controls'
    Add-Assessment 'Transports and software supply chain' 'automated + manual' 'Transport/archive/tool paths, permissions, signatures, and hashes' 'Review transport authorization, approvals, signatures, routes, client libraries, and patch/Security Note posture.' 'Pentest Playbook; OWASP SSVS'
    Add-Assessment 'SSFS, PSE, credentials, and key lifecycle' 'metadata + manual' 'Known SSFS families plus PSE/credential/keystore and permission metadata' 'Validate with official tools; review generation, rotation, backup, recovery, separation, expiry, and supported SCC key mode.' 'SAP SSFS/HANA guidance; OWASP SSVS crypto; PySAP formats'
    Add-Assessment 'SAP GUI clients and input history' 'automated footprint + manual' 'Known local history paths and metadata; no content read' 'Patch SAP GUI, apply SAP Notes for CVE-2025-0055/0056, disable/minimize history, and exclude sensitive fields.' 'OWASP CBAS SAP GUI history research'
    Add-Assessment 'External attack surface' 'not performed' 'A local listener is not proof of Internet or cross-zone reachability' 'Run a separately authorized external inventory for SAProuter, Dispatcher, Gateway, Message Server, SCC, Java, HANA, ASE, ICM/IGS, Start Service, and Web Dispatcher.' 'CBAS Internet Scan 2025/2026; Attack Surface Discovery'
    Add-Assessment 'Resilience and recovery' 'manual' 'Footprints may show replication components but cannot prove failover, backups, or objectives' 'Validate enqueue replication, SCC HA, HANA replication, backup protection, restore tests, and incident procedures.' 'OWASP SSVS availability; Security Matrix'
    Add-Assessment 'Governance and response' 'manual' 'Policies, ownership, acceptance, detection workflows, and recovery exercises are organizational evidence' 'Assess Integration, Platform, Access, and Customization across Identify, Protect, Detect, Respond, and Recover.' 'CBAS Security Matrix'
    Add-Assessment 'RFC callbacks, UCON, and trusted relationships' 'profile evidence + authenticated' 'Observed callback, UCON, authorization-check, legacy-ticket, and SNC parameters' 'Review SM59 callback allow-lists, S_RFC/S_RFCACL, UCON phase/function allow-lists, trusted-system relationships, technical users, and Security Audit Log events. Remove wildcard functions.' 'SAP RFC documentation; Onapsis callback research; SEC Consult RFC research'
    Add-Assessment 'Standard users and password policy' 'profile evidence + authenticated' 'Observed SAP* fallback and password-policy parameters; no password values or login attempts' 'For every client, review SAP*, DDIC, SAPCPIC, TMSADM, EARLYWATCH and solution-specific users; lock/retain required accounts, change defaults, remove excess profiles, and confirm effective security policies.' 'ERPScan default-account guide; HackTricks references; SAP Cloud ALM'
    Add-Assessment 'SAP HTTP endpoints and information disclosure' 'not actively tested' 'ICM/Java/IGS/Start Service/Web Dispatcher process, listener, artifact, and profile evidence' 'From each approved trust zone, validate /sap/public/info, WebGUI, Fiori, NWA, IGS status/admin, Dispatcher login info, SOAP/WebSocket RFC, Start Service methods, headers, TLS, and authentication without brute force.' 'SecuritySilverbacks Attack Surface Discovery templates'
    Add-Assessment 'SAP Security Notes and protocol CVEs' 'manual/authenticated' 'Host-local filenames and banners are not treated as patch proof' 'Use SAP for Me/System Recommendations and component inventory to verify applicable Notes, including 3158375, 3007182, 3044754, 3032624, 3089413 and current corrections for CVE-2018-2392, CVE-2021-40495, CVE-2022-27668, and CVE-2025-31324.' 'SecuritySilverbacks templates; SEC Consult; SAP Security Notes'
    Add-Assessment 'Java secure store, descriptors, and Download Manager' 'metadata + manual' 'SecStore.properties/SecStore.key, dlmanager.conf, PSE/keystore, archive, and Java host artifact metadata when present' 'Verify strict pair permissions, supported credential protection and fixed Download Manager release; review web.xml, webdynpro.xml and portalapp.xml authorization, upload, XXE/SSRF, invoker, and logging controls.' 'Breaking SAP Portal; Hardcore SAP Pentesting; OWASP PySAP Download Manager'
    Add-Assessment 'SAProuter routing and administration' 'automated + active/manual' 'Process flags, 3299 listener, saprouttab metadata/wildcards, and local tool version/hash' 'Remove -X and target wildcards, restrict 3299 to required peers, require SNC where appropriate, inspect dev_rout, verify Note 3158375/current kernel, and perform an authorized route/admin test.' 'Rapid7 Piercing SAProuter; SEC Consult CVE-2022-27668'
    Add-Assessment 'Enqueue and cluster coordination' 'automated + manual' 'Enqueue/replication process and listener evidence' 'Restrict Enqueue and replication listeners to explicit cluster peers, validate monitor authorization and current patches, and test failover without exposing administrative operations.' 'OWASP PySAP Enqueue; SAP availability guidance'
    Add-Coverage 'OWASP CBAS and SAP reference corpus' 'cataloged' 'Root page; 9 linked projects/resources; 74 playbook pages; 35 active Attack Surface checks plus 11 workflows; PySAP docs/notebooks/examples; every HackTricks SAP/SAProuter reference; SSVS, SAPKiln, HoneySAP, sncscan, Security Matrix, and research papers mapped in docs'
}

function ConvertTo-TopologySlug {
    param([string]$Value)
    $slug = ($Value.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
    if (-not $slug) { return 'item' }
    return $slug
}

function Get-ServiceCategory {
    param([string]$Text)
    switch -Regex ($Text) {
        '(?i)(hana|database|oracle|db2|maxdb|sql server|\base\b)' { return 'Database services' }
        '(?i)(cloud connector|saprouter|web dispatcher)' { return 'Boundary & cloud connectors' }
        '(?i)(start service|host agent|sapinst|administration|sdm|update|upgrade)' { return 'Management services' }
        '(?i)(rfc|gateway|p4|iiop|jms)' { return 'Integration services' }
        '(?i)(http|https|icm|webgui|igs)' { return 'Web & UI services' }
        '(?i)java' { return 'Java application services' }
        '(?i)(dispatcher|message server|abap|sap dev instance)' { return 'ABAP core services' }
        '(?i)(internal|enqueue)' { return 'Internal cluster services' }
        default { return 'Other SAP services' }
    }
}

function Get-DatabaseEngineForPort {
    param([string]$Port)
    switch -Regex ($Port) {
        '^3\d{2}(13|15|17|[4-9]\d)$' { return 'SAP HANA' }
        '^(1521|1522|2484)$' { return 'Oracle Database' }
        '^(1433|1434)$' { return 'Microsoft SQL Server' }
        '^446$' { return 'IBM Db2' }
        '^(7200|7210)$' { return 'SAP MaxDB' }
        '^(49\d{2}|5000)$' { return 'SAP ASE' }
        '^2638$' { return 'SAP IQ' }
        default { return '' }
    }
}

function Get-DatabaseEngineForText {
    param([string]$Text)
    switch -Regex ($Text) {
        '(?i)(hana|hdbdaemon|hdbnameserver|hdbindexserver|hdbsql)' { return 'SAP HANA' }
        '(?i)(sybase|sap ase|dataserver|backupserver|bcksrvr)' { return 'SAP ASE' }
        '(?i)(oracle|ora_pmon|tnslsnr)' { return 'Oracle Database' }
        '(?i)(db2sysc|db2wdog|ibm db2|[/\\]db2[/\\])' { return 'IBM Db2' }
        '(?i)(sqlservr|mssql|microsoft sql)' { return 'Microsoft SQL Server' }
        '(?i)(maxdb|sapdb|dbmsrv|x_server)' { return 'SAP MaxDB' }
        '(?i)(sap iq|iqsrv)' { return 'SAP IQ' }
        default { return '' }
    }
}

function Add-ServiceMapEntry {
    param(
        [string]$Category, [string]$Component, [string]$Status, [string]$Endpoint,
        [string]$Scope, [string]$Transport, [string]$Process, [string]$Source
    )
    $key = "$Category|$Component|$Status|$Endpoint|$Process|$Source"
    if ($script:SeenServiceMap.ContainsKey($key)) { return }
    $script:SeenServiceMap[$key] = $true
    Add-TableRow ServiceMap ([ordered]@{
        category = $Category; component = $Component; status = $Status; endpoint = $Endpoint
        scope = $Scope; transport = $Transport; process = $Process; source = $Source
    })
}

function Add-TopologyNode {
    param([string]$Id, [string]$Label, [string]$Kind, [string]$Scope, [string]$Status, [string]$Detail)
    if ($script:SeenTopologyNode.ContainsKey($Id)) { return }
    $script:SeenTopologyNode[$Id] = $true
    Add-TableRow TopologyNodes ([ordered]@{
        id = $Id; label = $Label; kind = $Kind; scope = $Scope; status = $Status; detail = $Detail
    })
}

function Add-TopologyEdge {
    param(
        [string]$Source, [string]$Target, [string]$Relation, [string]$State,
        [string]$Confidence, [string]$Evidence
    )
    $key = "$Source|$Target|$Relation|$Evidence"
    if ($script:SeenTopologyEdge.ContainsKey($key)) { return }
    $script:SeenTopologyEdge[$key] = $true
    Add-TableRow TopologyEdges ([ordered]@{
        source = $Source; target = $Target; relation = $Relation; state = $State
        confidence = $Confidence; evidence = $Evidence
    })
}

function Add-DatabaseEvidence {
    param(
        [string]$Engine, [string]$Placement, [string]$Endpoint, [string]$State,
        [string]$Confidence, [string]$Evidence
    )
    $key = "$Engine|$Placement|$Endpoint|$State|$Evidence"
    if ($script:SeenDatabase.ContainsKey($key)) { return }
    $script:SeenDatabase[$key] = $true
    Add-TableRow Databases ([ordered]@{
        engine = $Engine; placement = $Placement; endpoint = $Endpoint; state = $State
        confidence = $Confidence; evidence = $Evidence
    })
    switch ($Placement) {
        'remote' {
            $nodeId = 'db-remote-' + (ConvertTo-TopologySlug $Endpoint)
            $relation = 'observed database connection'
        }
        'local' {
            $nodeId = 'db-local-' + (ConvertTo-TopologySlug $Engine)
            $relation = 'local database evidence'
        }
        'configured' {
            $nodeId = 'db-configured-' + (ConvertTo-TopologySlug "$Engine-$Endpoint")
            $relation = 'configured database target'
        }
        default {
            $nodeId = 'db-undetermined'
            $relation = 'database placement undetermined'
        }
    }
    Add-TopologyNode $nodeId $Engine 'database' $Placement $State "$Endpoint — $Evidence"
    Add-TopologyEdge 'host' $nodeId $relation $State $Confidence $Evidence
}

function Add-CapabilityEvidence {
    param(
        [string]$Key, [string]$Category, [string]$Title, [string]$Status,
        [string]$Confidence, [string]$Evidence, [string]$Validation
    )
    if ($script:SeenCapability.ContainsKey($Key)) { return }
    $script:SeenCapability[$Key] = $true
    Add-TableRow Capabilities ([ordered]@{
        key = $Key; category = $Category; title = $Title; status = $Status
        confidence = $Confidence; evidence = $Evidence; validation = $Validation
    })
}

function Build-TopologyModel {
    Write-AuditLog 'Building evidence-backed SAP service topology'
    foreach ($name in @('ServiceMap','Capabilities','Databases','TopologyNodes','TopologyEdges')) {
        $script:Tables[$name].Clear()
    }
    $script:SeenServiceMap = @{}
    $script:SeenDatabase = @{}
    $script:SeenTopologyNode = @{}
    $script:SeenTopologyEdge = @{}
    $script:SeenCapability = @{}
    Add-TopologyNode 'host' $script:HostName 'sap-host' 'local' 'observed' 'Audited host; relationships are derived only from local evidence.'

    $localAddresses = @{}
    foreach ($socket in $script:Tables.Sockets.ToArray()) {
        $local = Split-EndPoint $socket.local
        if ($local.Address -and -not (Test-WildcardAddress $local.Address)) {
            $localAddresses[$local.Address.ToLowerInvariant()] = $true
        }
    }

    foreach ($socket in $script:Tables.Sockets.ToArray()) {
        $category = Get-ServiceCategory "$($socket.classification) $($socket.transport) $($socket.process) $($socket.service)"
        $endpoint = [string]$socket.local
        if ($socket.exposure -eq 'connected' -and $socket.remote) { $endpoint = "$($socket.local) → $($socket.remote)" }
        $owner = if ($socket.process) { [string]$socket.process } else { [string]$socket.service }
        Add-ServiceMapEntry $category $socket.classification $socket.state $endpoint $socket.exposure $socket.transport $owner 'socket'
        $socketConfidence = if ($socket.confidence) { [string]$socket.confidence } else { 'medium' }

        $local = Split-EndPoint $socket.local
        if ($socket.state -match '^(?i)(LISTEN|LISTENING|UNCONN|UDP|Bound)$') {
            $engine = Get-DatabaseEngineForText "$($socket.classification) $($socket.transport) $($socket.process)"
            if (-not $engine -and ($socket.classification -match '(?i)(database|hana)')) {
                $engine = Get-DatabaseEngineForPort $local.Port
            }
            if ($engine) {
                Add-ServiceMapEntry 'Database services' "$engine listener" $socket.state $socket.local $socket.exposure $socket.transport $owner 'socket/database inference'
                Add-DatabaseEvidence $engine 'local' $socket.local 'listening' $socketConfidence "$($socket.classification) listener owned by $(if($owner){$owner}else{'unknown process'})"
            }
        }

        if ($socket.exposure -eq 'connected' -and $socket.remote -and $socket.remote -notin @('*:*','0.0.0.0:*')) {
            $remote = Split-EndPoint $socket.remote
            if (-not $remote.Address) { continue }
            $engine = Get-DatabaseEngineForPort $remote.Port
            if (-not $engine -and "$($socket.classification) $($socket.transport)" -match '(?i)(database|hana)') {
                $engine = Get-DatabaseEngineForText "$($socket.classification) $($socket.transport)"
            }
            $evidence = "$(if($socket.process){$socket.process}else{'SAP process'}) $($socket.state): $($socket.local) → $($socket.remote)"
            if ($engine) {
                $remoteKey = $remote.Address.ToLowerInvariant()
                $placement = if ((Test-LoopbackAddress $remote.Address) -or $localAddresses.ContainsKey($remoteKey)) { 'local' } else { 'remote' }
                Add-ServiceMapEntry 'Database services' "$engine database connection" $socket.state "$($socket.local) → $($socket.remote)" $placement $socket.transport $owner 'socket/database inference'
                Add-DatabaseEvidence $engine $placement $socket.remote $socket.state $socketConfidence $evidence
            } else {
                $remoteId = 'remote-' + (ConvertTo-TopologySlug $socket.remote)
                Add-TopologyNode $remoteId $socket.remote 'remote-peer' 'remote' $socket.state "Peer observed from $(if($socket.process){$socket.process}else{'SAP-owned socket'})"
                Add-TopologyEdge 'host' $remoteId 'observed SAP connection' $socket.state $socketConfidence $evidence
            }
        }
    }

    foreach ($service in $script:Tables.Services.ToArray()) {
        $component = Get-SapComponent "$($service.name) $($service.description) $($service.path)"
        $category = Get-ServiceCategory "$component $($service.name) $($service.description)"
        Add-ServiceMapEntry $category $component $service.state 'not attributed' 'local' 'service manager' $service.account 'service'
        $engine = Get-DatabaseEngineForText "$component $($service.name) $($service.description) $($service.path)"
        if ($engine) {
            $serviceEndpoint = if ($service.path) { [string]$service.path } else { "service $($service.name)" }
            Add-DatabaseEvidence $engine 'local' $serviceEndpoint $service.state 'medium' "Local service definition: $($service.name)"
        }
    }

    foreach ($process in $script:Tables.Processes.ToArray()) {
        $category = Get-ServiceCategory "$($process.component) $($process.name) $($process.command)"
        $component = if ($process.component) { [string]$process.component } else { Get-SapComponent "$($process.name) $($process.command)" }
        Add-ServiceMapEntry $category $component 'running' 'not attributed' 'local' 'process' "$($process.name) (PID $($process.pid))" 'process'
        $engine = Get-DatabaseEngineForText "$component $($process.name) $($process.executable) $($process.command)"
        if ($engine) {
            $processEndpoint = if ($process.executable) { [string]$process.executable } else { [string]$process.name }
            Add-DatabaseEvidence $engine 'local' $processEndpoint 'running' 'high' "Local database process $($process.name) (PID $($process.pid))"
        }
    }

    foreach ($pathRow in $script:Tables.Paths.ToArray()) {
        $engine = Get-DatabaseEngineForText "$($pathRow.category) $($pathRow.path)"
        if ($engine) {
            Add-DatabaseEvidence $engine 'local' $pathRow.path 'filesystem footprint' 'medium' "$($pathRow.category) path observed"
        }
    }

    foreach ($profile in $script:Tables.Profiles.ToArray()) {
        $parameter = ([string]$profile.parameter).ToLowerInvariant()
        $value = [string]$profile.value
        if ($value.StartsWith('[REDACTED', [StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($parameter -match '^(sapdbhost|db/(host|server)|dbms/host|dbs/.+/(host|server))$') {
            $engine = Get-DatabaseEngineForText "$parameter $value"
            if (-not $engine) { $engine = 'Configured SAP database' }
            $placement = if ((Test-LoopbackAddress $value) -or $value -eq $script:HostName) { 'local' } else { 'configured' }
            Add-DatabaseEvidence $engine $placement $value 'configured' 'medium' "$($profile.parameter) in $($profile.file)"
        } elseif ($parameter -match '^(dbms/type|db/type|dbs/type)$') {
            $engine = Get-DatabaseEngineForText $value
            if ($engine) { Add-DatabaseEvidence $engine 'configured' $value 'configured engine' 'medium' "$($profile.parameter) in $($profile.file)" }
        }
    }

    foreach ($group in @($script:Tables.ServiceMap.ToArray() | Group-Object category)) {
        $listenerCount = @($group.Group | Where-Object status -match '^(?i)(LISTEN|LISTENING|UNCONN|UDP|Bound)$').Count
        $categoryId = 'service-' + (ConvertTo-TopologySlug $group.Name)
        Add-TopologyNode $categoryId $group.Name 'service-group' 'local' 'observed' "$($group.Count) evidence record(s); $listenerCount listener(s)"
        Add-TopologyEdge 'host' $categoryId 'runs or exposes' 'observed' 'high' "$($group.Count) process/service/socket record(s)"
    }

    $remoteCount = @($script:Tables.Databases | Where-Object placement -eq 'remote').Count
    $localCount = @($script:Tables.Databases | Where-Object placement -eq 'local').Count
    $configuredCount = @($script:Tables.Databases | Where-Object placement -eq 'configured').Count
    if ($remoteCount -gt 0 -and $localCount -gt 0) {
        $mixedConfidence = if (@($script:Tables.Databases | Where-Object {
            $_.placement -in @('local','remote') -and $_.confidence -eq 'high'
        }).Count -gt 0) { 'high' } else { 'medium' }
        $script:DatabasePosture = [ordered]@{ status='mixed'; summary='Both local database footprint and remote/non-loopback database connections were observed.'; confidence=$mixedConfidence }
    } elseif ($remoteCount -gt 0) {
        $remoteConfidence = if (@($script:Tables.Databases | Where-Object {
            $_.placement -eq 'remote' -and $_.confidence -eq 'high'
        }).Count -gt 0) { 'high' } else { 'medium' }
        $script:DatabasePosture = [ordered]@{ status='remote-observed'; summary='A remote/non-loopback database connection was observed from a recognized local socket.'; confidence=$remoteConfidence }
    } elseif ($localCount -gt 0) {
        $localConfidence = if (@($script:Tables.Databases | Where-Object {
            $_.placement -eq 'local' -and $_.confidence -eq 'high'
        }).Count -gt 0) { 'high' } else { 'medium' }
        $script:DatabasePosture = [ordered]@{ status='local-observed'; summary='Local database process, listener, or filesystem evidence was observed.'; confidence=$localConfidence }
    } elseif ($configuredCount -gt 0) {
        $script:DatabasePosture = [ordered]@{ status='configured'; summary='Database configuration evidence was found, but no active local or remote connection was observed.'; confidence='medium' }
    } else {
        $script:DatabasePosture = [ordered]@{ status='undetermined'; summary='No database placement evidence was observed in the collected process, socket, path, or profile data.'; confidence='low' }
        Add-DatabaseEvidence 'Unknown' 'undetermined' 'not observed' 'undetermined' 'low' 'Active database placement requires authenticated or runtime follow-up.'
    }

    $abapObserved = @($script:Tables.Systems | Where-Object stack -match '(?i)NetWeaver').Count -gt 0 -or
        @($script:Tables.Processes | Where-Object component -match '(?i)Dispatcher/Work').Count -gt 0 -or
        @($script:Tables.Sockets | Where-Object classification -match '(?i)Dispatcher').Count -gt 0
    if ($abapObserved) {
        Add-CapabilityEvidence 'abap' 'Application stack' 'ABAP application server' 'Observed' 'high' 'NetWeaver system, dispatcher process, or DIAG listener observed.' 'Confirm active instances and roles with SAPControl and authenticated SAP administration.'
    } else {
        Add-CapabilityEvidence 'abap' 'Application stack' 'ABAP application server' 'Not observed' 'low' 'No ABAP dispatcher/system footprint observed.' 'Confirm active instances and roles with SAPControl and authenticated SAP administration.'
    }

    $webguiObserved = @($script:Tables.Paths | Where-Object category -eq 'SAP WebGUI artifact').Count -gt 0
    $icmObserved = @($script:Tables.Sockets | Where-Object {
        $_.classification -match '^SAP ICM HTTP' -and $_.state -match '^(?i)(LISTEN|LISTENING|UNCONN|UDP|Bound)$'
    }).Count -gt 0
    if ($webguiObserved) {
        Add-CapabilityEvidence 'webgui' 'Web & UI' 'SAP WebGUI for ABAP' 'Enabled (host artifact observed)' 'medium' "A WebGUI-named host artifact exists and an ABAP footprint is $(if($abapObserved){'observed'}else{'not observed'})." 'Confirm that /sap/bc/gui/sap/its/webgui is active and appropriately authenticated in SICF; a host artifact alone cannot prove runtime activation.'
    } elseif ($abapObserved -and $icmObserved) {
        Add-CapabilityEvidence 'webgui' 'Web & UI' 'SAP WebGUI for ABAP' 'Possible; not confirmed' 'low' 'ABAP and ICM HTTP(S) evidence exists, but no WebGUI-named host artifact was observed.' 'Check the WebGUI ICF service in SICF using an authorized SAP account.'
    } else {
        Add-CapabilityEvidence 'webgui' 'Web & UI' 'SAP WebGUI for ABAP' 'Not observed' 'low' 'No WebGUI-named host artifact was observed; this is not proof that the database-backed ICF service is disabled.' 'Confirm /sap/bc/gui/sap/its/webgui status in SICF.'
    }

    $httpObserved = @($script:Tables.Sockets | Where-Object {
        $_.classification -match '^SAP (ICM|NetWeaver Java) HTTP' -and $_.state -match '^(?i)(LISTEN|LISTENING|UNCONN|UDP|Bound)$'
    }).Count -gt 0
    if ($httpObserved) {
        Add-CapabilityEvidence 'http' 'Web & UI' 'SAP HTTP(S) application surface' 'Listening' 'high' 'ICM or Java HTTP(S) listener observed.' 'Validate virtual hosts, TLS, authentication, and exposed ICF/Java applications from approved network zones.'
    } else {
        Add-CapabilityEvidence 'http' 'Web & UI' 'SAP HTTP(S) application surface' 'Not observed' 'medium' 'No recognized application HTTP(S) listener was recorded.' 'A clean host result is not proof of firewall or proxy absence.'
    }
    $rfcObserved = @($script:Tables.Sockets | Where-Object {
        $_.classification -match '^SAP RFC Gateway' -and $_.state -match '^(?i)(LISTEN|LISTENING|UNCONN|UDP|Bound)$'
    }).Count -gt 0
    if ($rfcObserved) {
        Add-CapabilityEvidence 'rfc' 'Integration' 'RFC Gateway' 'Listening' 'high' 'RFC Gateway listener observed.' 'Validate effective secinfo/reginfo/prxyinfo and SNC with authorized SAP tooling.'
    } else {
        Add-CapabilityEvidence 'rfc' 'Integration' 'RFC Gateway' 'Not observed' 'medium' 'No recognized RFC Gateway listener was recorded.' 'Confirm instance state and collection privilege.'
    }
    $sncObserved = @($script:Tables.Profiles | Where-Object parameter -match '^(?i)snc/').Count -gt 0
    if ($sncObserved) {
        Add-CapabilityEvidence 'snc' 'Transport security' 'Secure Network Communications (SNC)' 'Configured' 'medium' 'One or more snc/* profile parameters were observed.' 'Validate effective runtime values and negotiated QoP per connection; configuration presence is not proof of enforcement.'
    } else {
        Add-CapabilityEvidence 'snc' 'Transport security' 'Secure Network Communications (SNC)' 'Not observed' 'low' 'No snc/* profile parameter was collected.' 'Check effective instance profiles and client/destination settings.'
    }

    $runtimeText = @(
        $script:Tables.Services | ForEach-Object { "$($_.name) $($_.description) $($_.path)" }
        $script:Tables.Processes | ForEach-Object { "$($_.name) $($_.component) $($_.command)" }
        $script:Tables.Sockets | ForEach-Object { "$($_.classification) $($_.process) $($_.service)" }
        $script:Tables.Profiles | ForEach-Object { "$($_.parameter) $($_.value)" }
    ) -join "`n"
    foreach ($definition in @(
        @('java','Application stack','SAP NetWeaver Java','NetWeaver Java|jstart|jlaunch'),
        @('scc','Boundary & cloud','SAP Cloud Connector','Cloud Connector|scc_daemon'),
        @('saprouter','Boundary & cloud','SAProuter','SAProuter|saprouter'),
        @('webdispatcher','Boundary & cloud','SAP Web Dispatcher','Web Dispatcher|sapwebdisp'),
        @('igs','Web & UI','Internet Graphics Server (IGS)','SAP IGS|igswd|igsmux|igs/'),
        @('management','Management','SAP Host Agent / Start Service','Host Agent|Start Service|saphost|sapstartsrv')
    )) {
        if ($runtimeText -match "(?i)$($definition[3])") {
            Add-CapabilityEvidence $definition[0] $definition[1] $definition[2] 'Observed' 'high' 'Matching service, process, profile, or socket evidence was collected.' 'Review the corresponding technical evidence and validate effective configuration.'
        } else {
            Add-CapabilityEvidence $definition[0] $definition[1] $definition[2] 'Not observed' 'medium' 'No matching local runtime evidence was collected.' 'Confirm collection coverage before treating this as disabled.'
        }
    }
    Add-CapabilityEvidence 'database' 'Data tier' 'Database placement' $script:DatabasePosture.status $script:DatabasePosture.confidence $script:DatabasePosture.summary 'Validate the inferred engine and placement with SAP profiles, SAPControl, and the database owner before changing connectivity.'
    Add-Coverage 'Service topology' 'derived' 'Nodes, edges, capabilities, service categories, and database placement were inferred from collected local evidence; no connection was initiated.'
}

function Encode-Html {
    param([AllowNull()][object]$Value)
    return [Net.WebUtility]::HtmlEncode([string]$Value)
}

function Convert-TableRowsToHtml {
    param(
        [AllowEmptyCollection()][object[]]$Rows = @(),
        [string[]]$Columns,
        [int]$SeverityColumn = -1
    )
    $builder = New-Object Text.StringBuilder
    foreach ($row in @($Rows)) {
        if ($null -eq $row) { continue }
        $class = 'search-row'
        if ($SeverityColumn -ge 0) {
            $severityName = $Columns[$SeverityColumn]
            $severityProperty = $row.PSObject.Properties[$severityName]
            $severity = if ($null -ne $severityProperty) {
                ([string]$severityProperty.Value).ToLowerInvariant()
            } else {
                ''
            }
            $class += " severity-$severity"
        }
        [void]$builder.Append("<tr class=`"$class`">")
        foreach ($column in $Columns) {
            $property = $row.PSObject.Properties[$column]
            $value = if ($null -ne $property) { $property.Value } else { '' }
            [void]$builder.Append('<td>' + (Encode-Html $value) + '</td>')
        }
        [void]$builder.AppendLine('</tr>')
    }
    return $builder.ToString()
}

function Get-ScoreClass {
    param([string]$Grade)
    switch ($Grade.ToUpperInvariant()) {
        'A' { 'score-a' }
        'B' { 'score-b' }
        'C' { 'score-c' }
        'D' { 'score-d' }
        default { 'score-f' }
    }
}

function Convert-SectionScoresToHtml {
    $builder = New-Object Text.StringBuilder
    foreach ($section in $script:Tables.SectionScores.ToArray()) {
        $scoreClass = Get-ScoreClass $section.grade
        [void]$builder.Append("<a class=`"score-card $scoreClass`" href=`"#findings-$(Encode-Html $section.key)`"><div class=`"score-card-head`"><h3>")
        [void]$builder.Append((Encode-Html $section.title))
        [void]$builder.Append("</h3><span class=`"grade`">$(Encode-Html $section.grade)</span></div>")
        [void]$builder.Append("<div class=`"score-value`"><strong>$($section.score)</strong><span>/ 100</span></div>")
        [void]$builder.Append("<div class=`"score-meter`" aria-label=`"$($section.score) out of 100`"><span style=`"width:$($section.score)%`"></span></div>")
        [void]$builder.Append("<p>$(Encode-Html $section.label)</p><small>$($section.findings) finding(s) · $($section.critical) critical · $($section.high) high · $($section.medium) medium · $($section.low) low</small></a>")
    }
    return $builder.ToString()
}

function Convert-FindingSectionsToHtml {
    $builder = New-Object Text.StringBuilder
    foreach ($section in $script:Tables.SectionScores.ToArray()) {
        $sectionKey = Encode-Html $section.key
        $sectionTitle = Encode-Html $section.title
        [void]$builder.Append("<details id=`"findings-$sectionKey`" class=`"report-section finding-section`"><summary><h2>$sectionTitle findings</h2><span class=`"count-badge`">$($section.findings) finding(s) · $($section.score)/100 · grade $(Encode-Html $section.grade)</span></summary><div class=`"section-body`">")
        [void]$builder.Append("<div class=`"section-head`"><div><strong>$(Encode-Html $section.label)</strong><div class=`"muted`">$($section.critical) critical · $($section.high) high · $($section.medium) medium · $($section.low) low</div></div><input class=`"filter`" placeholder=`"Filter $sectionTitle findings…`" data-target=`"finding-list-$sectionKey`"></div><div class=`"finding-list`" id=`"finding-list-$sectionKey`">")
        $findings = @($script:Tables.Findings | Where-Object { (Get-FindingSection $_.id) -eq $section.key })
        if ($findings.Count -eq 0) {
            [void]$builder.Append('<p class="empty">No findings recorded for this risk section.</p>')
        }
        foreach ($finding in $findings) {
            $severityClass = ([string]$finding.severity).ToLowerInvariant()
            [void]$builder.Append("<details class=`"finding search-item severity-$severityClass`"><summary><span class=`"severity-badge`">$(Encode-Html $finding.severity)</span><code>$(Encode-Html $finding.id)</code><span class=`"finding-title`">$(Encode-Html $finding.title)</span><span class=`"finding-summary-meta`">$(Encode-Html $finding.asset) · +$($finding.points)</span></summary>")
            [void]$builder.Append("<div class=`"finding-body`"><dl><div><dt>Affected asset</dt><dd>$(Encode-Html $finding.asset)</dd></div><div><dt>Evidence and impact</dt><dd>$(Encode-Html $finding.evidence)</dd></div><div><dt>Recommended change</dt><dd>$(Encode-Html $finding.recommendation)</dd></div><div><dt>Reference</dt><dd>$(Encode-Html $finding.reference)</dd></div></dl></div></details>")
        }
        [void]$builder.Append('</div></div></details>')
    }
    return $builder.ToString()
}

function Convert-TopologyGraphToHtml {
    $builder = New-Object Text.StringBuilder
    [void]$builder.Append('<div class="topology-graph" role="img" aria-label="Observed SAP services connect through the audited host to database and remote peers"><div class="graph-lane"><h3>Enabled and observed service groups</h3>')
    $serviceNodes = @($script:Tables.TopologyNodes | Where-Object kind -eq 'service-group')
    if ($serviceNodes.Count -eq 0) {
        [void]$builder.Append('<div class="graph-node muted">No service group observed</div>')
    } else {
        foreach ($node in $serviceNodes) {
            [void]$builder.Append("<div class=`"graph-node service-node`"><strong>$(Encode-Html $node.label)</strong><small>$(Encode-Html $node.detail)</small></div>")
        }
    }
    [void]$builder.Append("</div><div class=`"graph-connector`"><span>runs / listens</span><b>→</b></div><div class=`"graph-host`"><span>SAP host</span><strong>$(Encode-Html $script:HostName)</strong><small>$($script:Tables.Systems.Count) system(s) · $($script:Tables.Sockets.Count) socket(s)</small></div><div class=`"graph-connector`"><span>connects to</span><b>→</b></div><div class=`"graph-lane`"><h3>Database and remote peers</h3>")
    $peerNodes = @($script:Tables.TopologyNodes | Where-Object { $_.kind -eq 'database' -or $_.kind -eq 'remote-peer' })
    if ($peerNodes.Count -eq 0) {
        [void]$builder.Append('<div class="graph-node muted">No connected peer observed</div>')
    } else {
        foreach ($node in $peerNodes) {
            [void]$builder.Append("<div class=`"graph-node $(Encode-Html $node.kind)-node`"><strong>$(Encode-Html $node.label)</strong><span class=`"node-scope`">$(Encode-Html $node.scope)</span><small>$(Encode-Html $node.detail)</small></div>")
        }
    }
    [void]$builder.Append('</div></div>')
    return $builder.ToString()
}

function Convert-ServiceMapGroupsToHtml {
    $builder = New-Object Text.StringBuilder
    foreach ($group in @($script:Tables.ServiceMap.ToArray() | Group-Object category | Sort-Object Name)) {
        [void]$builder.Append("<details class=`"technical-group service-category`"><summary><span>$(Encode-Html $group.Name)</span><span class=`"summary-meta`">$($group.Count) evidence record(s)</span></summary><div class=`"technical-group-body`"><div class=`"scroll-hint`">Scroll horizontally to see all columns →</div><div class=`"table-wrap`"><table><thead><tr><th>Component</th><th>Status</th><th>Endpoint</th><th>Scope</th><th>Transport</th><th>Process/account</th><th>Source</th></tr></thead><tbody>")
        [void]$builder.Append((Convert-TableRowsToHtml $group.Group @('component','status','endpoint','scope','transport','process','source')))
        [void]$builder.Append('</tbody></table></div></div></details>')
    }
    return $builder.ToString()
}

function Convert-CapabilitiesToHtml {
    $builder = New-Object Text.StringBuilder
    foreach ($row in $script:Tables.Capabilities.ToArray()) {
        $status = [string]$row.status
        $statusClass = switch -Regex ($status) {
            '^Enabled' { 'enabled'; break }
            '^Observed' { 'observed'; break }
            '^Listening' { 'listening'; break }
            '^Configured' { 'configured'; break }
            '^Possible' { 'possible'; break }
            '^Not observed' { 'not-observed'; break }
            default { ConvertTo-TopologySlug $status }
        }
        [void]$builder.Append("<tr class=`"search-row`"><td>$(Encode-Html $row.category)</td><td>$(Encode-Html $row.title)</td><td><span class=`"status-badge status-$(Encode-Html $statusClass)`">$(Encode-Html $status)</span></td><td>$(Encode-Html $row.confidence)</td><td>$(Encode-Html $row.evidence)</td><td>$(Encode-Html $row.validation)</td></tr>")
    }
    return $builder.ToString()
}

function Convert-SocketRowsToHtml {
    param([ValidateSet('listening','connected')][string]$Mode)
    $rows = if ($Mode -eq 'connected') {
        @($script:Tables.Sockets | Where-Object exposure -eq 'connected')
    } else {
        @($script:Tables.Sockets | Where-Object exposure -ne 'connected')
    }
    return Convert-TableRowsToHtml -Rows $rows -Columns @('classification','transport','protocol','state','local','remote','exposure','pid','process','service','confidence','basis')
}

function Convert-PathGroupsToHtml {
    $builder = New-Object Text.StringBuilder
    foreach ($group in @($script:Tables.Paths.ToArray() | Group-Object category | Sort-Object Name)) {
        [void]$builder.Append("<details class=`"technical-group path-category`"><summary><span>$(Encode-Html $group.Name)</span><span class=`"summary-meta`">$($group.Count) path(s)</span></summary><div class=`"technical-group-body`"><div class=`"scroll-hint`">Scroll horizontally to see all columns →</div><div class=`"table-wrap`"><table><thead><tr><th>Path</th><th>Type</th><th>Owner</th><th>Group</th><th>Mode</th><th>ACL</th><th>Bytes</th><th>Modified</th><th>Note</th></tr></thead><tbody>")
        [void]$builder.Append((Convert-TableRowsToHtml $group.Group @('path','type','owner','group','mode','acl','size_bytes','modified','note')))
        [void]$builder.Append('</tbody></table></div></div></details>')
    }
    return $builder.ToString()
}

function Get-Grade {
    param([int]$Score = $script:RiskScore)
    if ($Score -lt 10) { return @('A', 'Low observed risk') }
    if ($Score -lt 25) { return @('B', 'Limited hardening gaps') }
    if ($Score -lt 50) { return @('C', 'Material hardening gaps') }
    if ($Score -lt 75) { return @('D', 'High observed risk') }
    return @('F', 'Critical remediation priority')
}

function Get-FindingSection {
    param([string]$RuleId)
    if ($RuleId -match '^(NET|DIAG|JAVA|ENQ)-' -or $RuleId -in @('GW-001','MS-001','MS-003')) { return 'network' }
    if ($RuleId -match '^(ABAP|ACL|AUTH|CFG|GW|ICM|IGS|MS|RFC|SNC|START|UCON)-') { return 'configuration' }
    if ($RuleId -match '^(FILE|TOOL)-') { return 'filesystem' }
    if ($RuleId -match '^(SSFS|GUI)-') { return 'secrets' }
    return 'operations'
}

function Build-SectionScores {
    $definitions = @(
        @('network', 'Network & exposed services'),
        @('configuration', 'Configuration & access controls'),
        @('filesystem', 'Files & executable integrity'),
        @('secrets', 'SSFS, credentials & client data'),
        @('operations', 'Operations, logging & command execution')
    )
    $script:Tables.SectionScores.Clear()
    foreach ($definition in $definitions) {
        $key = $definition[0]
        $rows = @($script:Tables.Findings | Where-Object { (Get-FindingSection $_.id) -eq $key })
        $rawScore = 0
        foreach ($row in $rows) { $rawScore += [int]$row.points }
        $score = [Math]::Min(100, $rawScore)
        $grade = Get-Grade -Score $score
        Add-TableRow 'SectionScores' @{
            key = $key
            title = $definition[1]
            score = $score
            grade = $grade[0]
            label = $grade[1]
            findings = $rows.Count
            critical = @($rows | Where-Object severity -eq 'Critical').Count
            high = @($rows | Where-Object severity -eq 'High').Count
            medium = @($rows | Where-Object severity -eq 'Medium').Count
            low = @($rows | Where-Object severity -eq 'Low').Count
        }
    }
}

function Write-JsonReport {
    Write-AuditLog 'Writing JSON evidence report'
    $grade = Get-Grade
    $critical = @($script:Tables.Findings | Where-Object severity -eq 'Critical').Count
    $high = @($script:Tables.Findings | Where-Object severity -eq 'High').Count
    $medium = @($script:Tables.Findings | Where-Object severity -eq 'Medium').Count
    $low = @($script:Tables.Findings | Where-Object severity -eq 'Low').Count
    $report = [ordered]@{
        schema = $script:Schema
        tool_version = $script:Version
        generated_at = $script:CollectedAt
        host = $script:HostName
        audit_root = $(if ($script:CustomRoot) { $RootPath } else { '<live>' })
        report_note = $ReportNote
        risk_score = $script:RiskScore
        risk_grade = $grade[0]
        risk_label = $grade[1]
        section_scores = $script:Tables.SectionScores.ToArray()
        topology = [ordered]@{
            database_posture = $script:DatabasePosture
            nodes = $script:Tables.TopologyNodes.ToArray()
            edges = $script:Tables.TopologyEdges.ToArray()
            services = $script:Tables.ServiceMap.ToArray()
            capabilities = $script:Tables.Capabilities.ToArray()
            databases = $script:Tables.Databases.ToArray()
        }
        summary = [ordered]@{
            findings = $script:Tables.Findings.Count
            critical = $critical
            high = $high
            medium = $medium
            low = $low
            systems = $script:Tables.Systems.Count
            services = $script:Tables.Services.Count
            processes = $script:Tables.Processes.Count
            sockets = $script:Tables.Sockets.Count
            socket_candidates = $script:Tables.SocketCandidates.Count
            ssfs = $script:Tables.Ssfs.Count
            tools = $script:Tables.Tools.Count
        }
        findings = $script:Tables.Findings.ToArray()
        systems = $script:Tables.Systems.ToArray()
        services = $script:Tables.Services.ToArray()
        processes = $script:Tables.Processes.ToArray()
        sockets = $script:Tables.Sockets.ToArray()
        socket_candidates = $script:Tables.SocketCandidates.ToArray()
        paths = $script:Tables.Paths.ToArray()
        ssfs = $script:Tables.Ssfs.ToArray()
        tools = $script:Tables.Tools.ToArray()
        profiles = $script:Tables.Profiles.ToArray()
        coverage = $script:Tables.Coverage.ToArray()
        assessment_catalog = $script:Tables.Assessment.ToArray()
    }
    $json = $report | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText($JsonPath, $json + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
}

function Write-HtmlReport {
    Write-AuditLog 'Writing self-contained HTML report'
    $grade = Get-Grade
    $critical = @($script:Tables.Findings | Where-Object severity -eq 'Critical').Count
    $high = @($script:Tables.Findings | Where-Object severity -eq 'High').Count
    $medium = @($script:Tables.Findings | Where-Object severity -eq 'Medium').Count
    $low = @($script:Tables.Findings | Where-Object severity -eq 'Low').Count
    $findingSectionsHtml = Convert-FindingSectionsToHtml
    $sectionScoresHtml = Convert-SectionScoresToHtml
    $topologyGraphHtml = Convert-TopologyGraphToHtml
    $topologyEdgesHtml = Convert-TableRowsToHtml $script:Tables.TopologyEdges @('source','target','relation','state','confidence','evidence')
    $serviceMapGroupsHtml = Convert-ServiceMapGroupsToHtml
    $capabilitiesHtml = Convert-CapabilitiesToHtml
    $databasesHtml = Convert-TableRowsToHtml $script:Tables.Databases @('engine','placement','endpoint','state','confidence','evidence')
    $systemsHtml = Convert-TableRowsToHtml $script:Tables.Systems @('sid','stack','instances','root','source')
    $servicesHtml = Convert-TableRowsToHtml $script:Tables.Services @('name','state','start_mode','account','path','description')
    $processesHtml = Convert-TableRowsToHtml $script:Tables.Processes @('pid','user','group','name','executable','command','component')
    $listeningSocketsHtml = Convert-SocketRowsToHtml -Mode listening
    $connectedSocketsHtml = Convert-SocketRowsToHtml -Mode connected
    $socketCandidatesHtml = Convert-TableRowsToHtml $script:Tables.SocketCandidates @('classification','transport','protocol','state','local','remote','pid','process','reason')
    $ssfsHtml = Convert-TableRowsToHtml $script:Tables.Ssfs @('family','sid','role','path','size_bytes','owner','group','mode','acl','detail')
    $toolsHtml = Convert-TableRowsToHtml $script:Tables.Tools @('name','component','path','source','version','owner','group','mode','acl','size_bytes','sha256','signature_status','signer')
    $profilesHtml = Convert-TableRowsToHtml $script:Tables.Profiles @('file','parameter','value','source')
    $pathGroupsHtml = Convert-PathGroupsToHtml
    $coverageHtml = Convert-TableRowsToHtml $script:Tables.Coverage @('check','status','detail')
    $assessmentHtml = Convert-TableRowsToHtml $script:Tables.Assessment @('area','status','evidence','next_step','source')
    $auditRootLabel = if ($script:CustomRoot) { $RootPath } else { '<live host>' }
    $reportNoteHtml = if ([string]::IsNullOrWhiteSpace($ReportNote)) { '' } else {
        '<p class="notice"><strong>Report context:</strong> ' + (Encode-Html $ReportNote) + '</p>'
    }
    $jsonName = [IO.Path]::GetFileName($JsonPath)
    $listenerCount = @($script:Tables.Sockets | Where-Object exposure -ne 'connected').Count
    $connectedCount = @($script:Tables.Sockets | Where-Object exposure -eq 'connected').Count
    $socketCandidateCount = $script:Tables.SocketCandidates.Count
    $html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="generator" content="SAPstract $($script:Version)"><title>SAPstract audit — $(Encode-Html $script:HostName)</title>
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
</style></head><body><div class="wrap">
<header class="hero"><div><div class="brand">SAPstract · Host posture</div><h1>$(Encode-Html $script:HostName)</h1><p class="muted">Generated $(Encode-Html $script:CollectedAt) · Schema $($script:Schema) · Audit root $(Encode-Html $auditRootLabel)</p>$reportNoteHtml<p>Review the section scores below to see where risk is concentrated. Scores reflect observed local evidence, not proof of exploitability or an SAP application-layer certification.</p></div><div class="hero-actions"><button class="theme-toggle" id="theme-toggle" type="button" aria-label="Switch color theme">Dark theme</button><div class="overall-index"><span class="muted">Aggregate index</span><br><strong>$($script:RiskScore)/100 · $($grade[0])</strong><br><small>$($grade[1])</small></div></div></header>
<nav><a href="#summary">Summary</a><a href="#topology">Topology</a><a href="#capabilities">Capabilities</a><a href="#database">Database</a><a href="#service-catalog">Service catalog</a><a href="#findings">Findings</a><a href="#systems">Systems</a><a href="#runtime">Runtime</a><a href="#sockets">Connections</a><a href="#ssfs">SSFS</a><a href="#tools">Tools</a><a href="#profiles">Profiles</a><a href="#paths">Files</a><a href="#assessment">Assessment</a><a href="#coverage">Coverage</a></nav>
<section id="summary"><div class="section-head"><div><h2>Executive summary</h2><div class="muted">Passive evidence collected from this host</div></div><span class="pill">$($script:Tables.Findings.Count) findings</span></div><h3>Risk by section</h3><div class="score-grid">$sectionScoresHtml</div><div class="risk"><div><b class="critical">$critical</b>Critical</div><div><b class="high">$high</b>High</div><div><b class="medium">$medium</b>Medium</div><div><b class="low">$low</b>Low</div></div><div class="cards"><div class="card"><b>$($script:Tables.Systems.Count)</b><small>SAP systems</small></div><div class="card"><b>$($script:Tables.ServiceMap.Count)</b><small>service evidence rows</small></div><div class="card"><b>$listenerCount</b><small>listening endpoints</small></div><div class="card"><b>$connectedCount</b><small>observed connections</small></div><div class="card"><b>$($script:Tables.Capabilities.Count)</b><small>capability checks</small></div><div class="card"><b>$($script:Tables.Databases.Count)</b><small>database evidence rows</small></div><div class="card"><b>$($script:Tables.Ssfs.Count)</b><small>SSFS artifacts</small></div><div class="card"><b>$($script:Tables.Tools.Count)</b><small>SAP tools</small></div></div><div class="posture-card"><strong>Database placement: $(Encode-Html $script:DatabasePosture.status)</strong><br><span>$(Encode-Html $script:DatabasePosture.summary)</span> <small>Confidence: $(Encode-Html $script:DatabasePosture.confidence)</small></div><p class="notice">SAPstract is deliberately read-only: it does not scan another host, call SAP web methods, log in, brute-force, decrypt SSFS, or print secrets. Validate high-impact changes with the responsible SAP Basis, security, database, and infrastructure owners.</p></section>
<details id="topology" class="report-section" open><summary><h2>SAP service and connection topology</h2><span class="count-badge">$($script:Tables.TopologyEdges.Count) relationship(s)</span></summary><div class="section-body"><p class="notice">This graph shows observed local processes, services, listeners, and connections. “Remote” means the peer address was not loopback or another collected local socket address; confirm routing and database ownership before relying on the placement.</p>$topologyGraphHtml<details class="technical-group"><summary><span>Topology relationships and evidence</span><span class="summary-meta">$($script:Tables.TopologyEdges.Count) edge(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table id="topology-edges-table"><thead><tr><th>Source</th><th>Target</th><th>Relationship</th><th>State</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>$topologyEdgesHtml</tbody></table></div></div></details></div></details>
<details id="capabilities" class="report-section" open><summary><h2>SAP capabilities and enabled surfaces</h2><span class="count-badge">$($script:Tables.Capabilities.Count) check(s)</span></summary><div class="section-body"><p class="muted">Observed means local evidence exists. Not observed is never equivalent to disabled. WebGUI host artifacts are marked enabled with medium confidence and still require SICF confirmation.</p><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table id="capabilities-table"><thead><tr><th>Category</th><th>Capability</th><th>Status</th><th>Confidence</th><th>Evidence</th><th>Required validation</th></tr></thead><tbody>$capabilitiesHtml</tbody></table></div></div></details>
<details id="database" class="report-section" open><summary><h2>Database landscape</h2><span class="count-badge">$(Encode-Html $script:DatabasePosture.status) · $($script:Tables.Databases.Count) evidence row(s)</span></summary><div class="section-body"><div class="posture-card"><strong>$(Encode-Html $script:DatabasePosture.summary)</strong><br><small>Confidence: $(Encode-Html $script:DatabasePosture.confidence). A non-loopback peer can still be another address on the same host if socket coverage is incomplete.</small></div><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table id="database-table"><thead><tr><th>Engine</th><th>Placement</th><th>Endpoint/artifact</th><th>State</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>$databasesHtml</tbody></table></div></div></details>
<details id="service-catalog" class="report-section" open><summary><h2>Categorized SAP service catalog</h2><span class="count-badge">$($script:Tables.ServiceMap.Count) evidence row(s)</span></summary><div class="section-body"><div class="section-head"><div class="muted">Processes, service-manager entries, listeners, and established connections grouped by technical purpose</div><input class="filter" placeholder="Filter service evidence…" data-target="service-catalog-groups"></div><div id="service-catalog-groups">$serviceMapGroupsHtml</div></div></details>
<section id="findings"><div class="section-head"><div><h2>Prioritized findings by risk section</h2><div class="muted">Each risk domain has its own report section and filter below.</div></div><span class="pill">$($script:Tables.Findings.Count) total finding(s)</span></div></section>
$findingSectionsHtml
<details id="systems" class="report-section"><summary><h2>SAP systems</h2><span class="count-badge">$($script:Tables.Systems.Count) system(s)</span></summary><div class="section-body"><div class="section-head"><div class="muted">SID and instance footprints</div><input class="filter" placeholder="Filter systems…" data-target="systems-table"></div><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table id="systems-table"><thead><tr><th>SID</th><th>Stack</th><th>Instances</th><th>Root</th><th>Source</th></tr></thead><tbody>$systemsHtml</tbody></table></div></div></details>
<details id="runtime" class="report-section"><summary><h2>Raw services and processes</h2><span class="count-badge">$($script:Tables.Services.Count) service(s) · $($script:Tables.Processes.Count) process(es)</span></summary><div class="section-body"><div class="section-head"><div class="muted">Underlying service-manager and process evidence; use the categorized catalog above for analysis</div><input class="filter" placeholder="Filter services/processes…" data-target="service-tables"></div><div id="service-tables"><details class="technical-group" open><summary><span>Services</span><span class="summary-meta">$($script:Tables.Services.Count) instance(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table><thead><tr><th>Name</th><th>State</th><th>Start mode</th><th>Account</th><th>Definition/path</th><th>Description</th></tr></thead><tbody>$servicesHtml</tbody></table></div></div></details><details class="technical-group"><summary><span>Processes</span><span class="summary-meta">$($script:Tables.Processes.Count) instance(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table><thead><tr><th>PID</th><th>User</th><th>Group</th><th>Name</th><th>Executable</th><th>Command</th><th>Component</th></tr></thead><tbody>$processesHtml</tbody></table></div></div></details></div></div></details>
<details id="sockets" class="report-section"><summary><h2>Listening endpoints and open connections</h2><span class="count-badge">$listenerCount listener(s) · $connectedCount connection(s) · $socketCandidateCount uncorroborated</span></summary><div class="section-body"><div class="section-head"><div class="muted">Only process-owned or host-correlated sockets are promoted as SAP evidence; ambiguous port matches remain separate and cannot create findings.</div><input class="filter" placeholder="Filter network evidence…" data-target="socket-groups"></div><div id="socket-groups"><details class="technical-group" open><summary><span>Listening endpoints</span><span class="summary-meta">$listenerCount observation(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table><thead><tr><th>Classification</th><th>Transport</th><th>Protocol</th><th>State</th><th>Local</th><th>Remote</th><th>Exposure</th><th>PID</th><th>Process</th><th>Service</th><th>Confidence</th><th>Evidence basis</th></tr></thead><tbody>$listeningSocketsHtml</tbody></table></div></div></details><details class="technical-group" open><summary><span>Established and open connections</span><span class="summary-meta">$connectedCount observation(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table><thead><tr><th>Classification</th><th>Transport</th><th>Protocol</th><th>State</th><th>Local</th><th>Remote</th><th>Exposure</th><th>PID</th><th>Process</th><th>Service</th><th>Confidence</th><th>Evidence basis</th></tr></thead><tbody>$connectedSocketsHtml</tbody></table></div></div></details><details class="technical-group"><summary><span>Uncorroborated SAP-port candidates</span><span class="summary-meta">$socketCandidateCount candidate(s), excluded from findings and topology</span></summary><div class="technical-group-body"><p class="muted">These are retained to avoid losing possible evidence when ownership is unavailable, but a port number by itself does not establish SAP.</p><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table><thead><tr><th>Candidate classification</th><th>Transport</th><th>Protocol</th><th>State</th><th>Local</th><th>Remote</th><th>PID</th><th>Process</th><th>Reason not promoted</th></tr></thead><tbody>$socketCandidatesHtml</tbody></table></div></div></details></div></div></details>
<details id="ssfs" class="report-section"><summary><h2>SAP secure stores (SSFS)</h2><span class="count-badge">$($script:Tables.Ssfs.Count) artifact(s)</span></summary><div class="section-body"><div class="section-head"><div class="muted">Metadata-only: ABAP/RSEC, HANA instance, HANA System-PKI, hdbuserstore, LKY, and SCC</div><input class="filter" placeholder="Filter SSFS…" data-target="ssfs-table"></div><p class="notice">A .DAT/.KEY pair is operational evidence, not proof of secure lifecycle. A missing key may mean another configured path; SCC/default-key contexts need product-specific confirmation. No record names, values, HMAC keys, master keys, or decrypted bytes are included.</p><details class="technical-group" open><summary><span>Secure-store artifacts</span><span class="summary-meta">$($script:Tables.Ssfs.Count) metadata record(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table id="ssfs-table"><thead><tr><th>Family</th><th>SID/store</th><th>Role</th><th>Path</th><th>Bytes</th><th>Owner</th><th>Group</th><th>Mode</th><th>ACL</th><th>Safe detail</th></tr></thead><tbody>$ssfsHtml</tbody></table></div></div></details></div></details>
<details id="tools" class="report-section"><summary><h2>SAP tools</h2><span class="count-badge">$($script:Tables.Tools.Count) tool(s)</span></summary><div class="section-body"><div class="section-head"><div class="muted">Administration/runtime binaries; not executed</div><input class="filter" placeholder="Filter tools…" data-target="tools-table"></div><details class="technical-group" open><summary><span>Tool instances and integrity metadata</span><span class="summary-meta">$($script:Tables.Tools.Count) binary record(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table id="tools-table"><thead><tr><th>Name</th><th>Capability</th><th>Path</th><th>Source</th><th>Version</th><th>Owner</th><th>Group</th><th>Mode</th><th>ACL</th><th>Bytes</th><th>SHA-256</th><th>Signature</th><th>Signer</th></tr></thead><tbody>$toolsHtml</tbody></table></div></div></details></div></details>
<details id="profiles" class="report-section"><summary><h2>Profiles and parameters</h2><span class="count-badge">$($script:Tables.Profiles.Count) parameter(s)</span></summary><div class="section-body"><div class="section-head"><div class="muted">Security-relevant local configuration; secret-like values always redacted</div><input class="filter" placeholder="Filter parameters…" data-target="profiles-table"></div><details class="technical-group" open><summary><span>Observed parameter instances</span><span class="summary-meta">$($script:Tables.Profiles.Count) record(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table id="profiles-table"><thead><tr><th>File</th><th>Parameter</th><th>Value</th><th>Source</th></tr></thead><tbody>$profilesHtml</tbody></table></div></div></details></div></details>
<details id="paths" class="report-section"><summary><h2>Files, directories, and permissions</h2><span class="count-badge">$($script:Tables.Paths.Count) path(s)</span></summary><div class="section-body"><div class="section-head"><div class="muted">Filesystem evidence split into technical categories</div><input class="filter" placeholder="Filter path evidence…" data-target="path-groups"></div><div id="path-groups">$pathGroupsHtml</div></div></details>
<details id="assessment" class="report-section"><summary><h2>Assessment map</h2><span class="count-badge">$($script:Tables.Assessment.Count) area(s)</span></summary><div class="section-body"><div class="section-head"><div class="muted">Automated evidence and required authenticated/active work—absence of evidence is never shown as a pass</div><input class="filter" placeholder="Filter assessment map…" data-target="assessment-table"></div><details class="technical-group" open><summary><span>Coverage areas and required follow-up</span><span class="summary-meta">$($script:Tables.Assessment.Count) area(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table id="assessment-table"><thead><tr><th>Area</th><th>Status</th><th>Evidence collected</th><th>Required next step</th><th>Research source</th></tr></thead><tbody>$assessmentHtml</tbody></table></div></div></details></div></details>
<details id="coverage" class="report-section"><summary><h2>Coverage and limitations</h2><span class="count-badge">$($script:Tables.Coverage.Count) check(s)</span></summary><div class="section-body"><p class="muted">Use this section when interpreting a clean result.</p><details class="technical-group" open><summary><span>Collection coverage</span><span class="summary-meta">$($script:Tables.Coverage.Count) check(s)</span></summary><div class="technical-group-body"><div class="scroll-hint">Scroll horizontally to see all columns →</div><div class="table-wrap"><table><thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead><tbody>$coverageHtml</tbody></table></div></div></details><details class="technical-group"><summary><span>Scoring model</span><span class="summary-meta">How section and aggregate scores work</span></summary><div class="technical-group-body"><p>Each unique affected asset contributes Critical 30, High 18, Medium 8, or Low 3 points. Each section is capped independently at 100; the backward-compatible aggregate index is also capped at 100. A 0–9, B 10–24, C 25–49, D 50–74, F 75–100. This prioritizes remediation; it is not a probability of compromise.</p></div></details><details class="technical-group"><summary><span>Assessment boundary</span><span class="summary-meta">What this host-local pass cannot prove</span></summary><div class="technical-group-body"><p>This host-local pass can prove selected file metadata, profile values, processes/services, and socket state at collection time. It cannot prove network-zone reachability, SAP authorizations, current Security Notes, TLS cipher quality, per-session SNC, database roles, or ABAP code security. Those require authenticated, change-controlled follow-up.</p></div></details><details class="technical-group"><summary><span>Research basis</span><span class="summary-meta">References behind recognition and risk context</span></summary><div class="technical-group-body"><p>Recognition and risk context align with SAP documentation, OWASP Core Business Application Security, the SAP Pentest Playbook, and PySAP protocol/file-format modules. SAPstract has no PySAP, Scapy, Python, CDN, or network-scanner runtime dependency.</p></div></details></div></details>
<footer>SAPstract $($script:Version) · JSON companion: $(Encode-Html $jsonName) · Protect this topology report.</footer></div>
<script>const root=document.documentElement,themeButton=document.getElementById('theme-toggle');function syncThemeButton(){themeButton.textContent=root.dataset.theme==='dark'?'Light theme':'Dark theme'}syncThemeButton();themeButton.addEventListener('click',()=>{root.dataset.theme=root.dataset.theme==='dark'?'light':'dark';try{localStorage.setItem('sapstract-theme',root.dataset.theme)}catch(e){}syncThemeButton()});document.querySelectorAll('.filter').forEach(input=>input.addEventListener('input',()=>{const q=input.value.toLowerCase(),target=input.dataset.target,direct=document.getElementById(target);let rows=[],items=[];if(direct){rows=[...direct.querySelectorAll('tbody tr')];items=[...direct.querySelectorAll('.search-item')]}else rows=[...document.querySelectorAll('.'+target+' tbody tr')];rows.forEach(row=>row.classList.toggle('hide',!row.textContent.toLowerCase().includes(q)));items.forEach(item=>item.classList.toggle('hide',!item.textContent.toLowerCase().includes(q)));if(direct)direct.querySelectorAll('.search-group,.service-category,.path-category').forEach(group=>{const visibleItems=[...group.querySelectorAll('.search-item')].some(item=>!item.classList.contains('hide')),visibleRows=[...group.querySelectorAll('tbody tr')].some(row=>!row.classList.contains('hide'));group.classList.toggle('hide',!(visibleItems||visibleRows))})}));document.querySelectorAll('nav a,.score-card').forEach(link=>link.addEventListener('click',()=>{const target=document.querySelector(link.getAttribute('href'));if(target&&target.tagName==='DETAILS')target.open=true}));document.querySelectorAll('tbody').forEach(body=>{if(!body.children.length){const tr=document.createElement('tr'),td=document.createElement('td');td.className='empty';td.colSpan=20;td.textContent='No evidence recorded for this section.';tr.appendChild(td);body.appendChild(tr)}});</script></body></html>
"@
    [IO.File]::WriteAllText($ReportPath, $html, (New-Object Text.UTF8Encoding($false)))
}

try {
    if ($script:CustomRoot -and -not (Test-Path -LiteralPath $RootPath -PathType Container)) {
        throw "RootPath does not exist: $RootPath"
    }
    if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $OutputDirectory -Force)
    }
    $script:HostName = if (-not [string]::IsNullOrWhiteSpace($HostLabel)) { $HostLabel } elseif ($env:COMPUTERNAME) { $env:COMPUTERNAME } else {
        try { [Net.Dns]::GetHostName() } catch { 'unknown' }
    }
    $script:CollectedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
    $safeHost = $script:HostName -replace '[^A-Za-z0-9_.-]', '_'
    if ([string]::IsNullOrWhiteSpace($ReportPath)) { $ReportPath = Join-Path $OutputDirectory "sapstract-$safeHost-$stamp.html" }
    if ([string]::IsNullOrWhiteSpace($JsonPath)) { $JsonPath = Join-Path $OutputDirectory "sapstract-$safeHost-$stamp.json" }
    foreach ($parent in @((Split-Path -Parent $ReportPath), (Split-Path -Parent $JsonPath)) | Select-Object -Unique) {
        if ($parent -and -not (Test-Path -LiteralPath $parent -PathType Container)) { [void](New-Item -ItemType Directory -Path $parent -Force) }
    }
    $isAdmin = Test-IsAdministrator
    $osDescription = try { [Runtime.InteropServices.RuntimeInformation]::OSDescription } catch { [Environment]::OSVersion.VersionString }
    Add-Coverage 'Host metadata' 'complete' "Host=$($script:HostName); OS=$osDescription; user=$([Environment]::UserName); elevated=$isAdmin; root=$(if($script:CustomRoot){$RootPath}else{'<live>'})"
    if ($isAdmin) { Add-Coverage 'Privilege' 'complete' 'Collector is elevated' }
    else {
        Add-Coverage 'Privilege' 'partial' 'Not elevated: process ownership, sockets, ACLs, and protected paths may be incomplete'
        Write-AuditWarning 'Not elevated; the report will explicitly mark permission-related coverage as partial'
    }

    Write-Banner
    Write-AuditLog "Starting SAPstract $($script:Version) host-local audit"
    Discover-SapSystems
    Scan-SapRegistry
    Collect-Processes
    Collect-Services
    Collect-Sockets
    Scan-KnownPaths
    Scan-ProfilesAndAcls
    Scan-Ssfs
    Scan-Tools
    Scan-SecurityArtifacts
    Build-TopologyModel
    Build-AssessmentCatalog
    Build-SectionScores
    if ($script:TruncatedScans -gt 0) {
        Add-Coverage 'Collection limits' 'partial' "$($script:TruncatedScans) scan(s) reached MaxFiles=$MaxFiles"
    }
    if ($script:SapEvidenceCount -eq 0) {
        Add-Coverage 'SAP footprint' 'none observed' 'No SAP-specific service, process, socket, standard path, SSFS artifact, profile, or tool was found in the inspected scope'
    }
    Write-JsonReport
    Write-HtmlReport
    if (-not $Quiet) { Write-Host '[SAPstract] [OK] Audit complete' -ForegroundColor Green }
    Write-Output "HTML report: $ReportPath"
    Write-Output "JSON report: $JsonPath"
    Write-Output "Risk score: $($script:RiskScore)/100"
} catch {
    $position = $_.InvocationInfo.PositionMessage
    Write-Error "[SAPstract] Fatal error: $($_.Exception.Message)`n$position"
    exit 1
}
