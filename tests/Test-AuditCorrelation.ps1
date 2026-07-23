[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$auditPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'SAPaudit.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $auditPath, [ref]$tokens, [ref]$parseErrors
)
if ($parseErrors.Count) { throw ($parseErrors -join [Environment]::NewLine) }

$requiredFunctions = @(
    'Add-TableRow',
    'Register-SapInstance',
    'Test-SapRegistrySidEvidence',
    'Test-SapNativeProcessText',
    'Test-SapDatabaseProcessCandidateText',
    'Test-SapDatabaseProcessText',
    'Test-SapProcessText',
    'Test-SapServiceEvidence',
    'Test-SapServerServiceEvidence',
    'Get-SapComponent',
    'Split-EndPoint',
    'Get-PortClassification',
    'Test-LoopbackAddress',
    'Test-WildcardAddress',
    'Get-SapPortCorrelationBasis',
    'Add-SocketCandidate',
    'Add-SocketEvidence'
)

$definitions = $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $requiredFunctions -contains $node.Name
}, $true)
foreach ($name in $requiredFunctions) {
    $definition = $definitions | Where-Object Name -eq $name | Select-Object -First 1
    if ($null -eq $definition) { throw "Function not found in audit script: $name" }
    Invoke-Expression $definition.Extent.Text
}

$script:SapSids = @{}
$script:SapInstanceNumbers = @{}
$script:SapPids = @{}
$script:SapProcessByPid = @{}
$script:SapProductContext = @{}
$script:SapServerEvidenceCount = 0
$script:SocketCandidateCount = 0
$script:Tables = @{
    Sockets = New-Object System.Collections.Generic.List[object]
    SocketCandidates = New-Object System.Collections.Generic.List[object]
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

Assert-True (-not (Test-SapServiceEvidence 'WhatsAppUpdater' 'WhatsApp Update Service' 'C:\Tools\whatsapp.exe')) `
    'WhatsApp substring was incorrectly recognized as SAP'
Assert-True (-not (Test-SapRegistrySidEvidence 'RFC' ([pscustomobject]@{}))) `
    'Generic three-character SAP registry key was incorrectly recognized as a SID'
Assert-True (Test-SapRegistrySidEvidence 'ABC' ([pscustomobject]@{ SAPSYSTEMNAME = 'ABC' })) `
    'Registry SID with matching SAPSYSTEMNAME was not recognized'
Assert-True (Test-SapServiceEvidence 'SAPABC_00' 'SAP ABC Instance 00' 'C:\usr\sap\ABC\sapstartsrv.exe') `
    'Canonical SAP instance service was not recognized'
Assert-True (-not (Test-SapServerServiceEvidence 'NWSAPAutoWorkstationUpdateSvc' 'C:\Program Files (x86)\SAP\SAPsetup\Updater.exe')) `
    'SAP client updater service was incorrectly treated as SAP server context'
Assert-True (Test-SapServerServiceEvidence 'SAPABC_00' 'C:\usr\sap\ABC\sapstartsrv.exe') `
    'Canonical SAP instance service was not treated as SAP server context'
Assert-True (-not (Test-SapProcessText 'sqlservr.exe -sMSSQLSERVER' 'NT SERVICE\MSSQLSERVER')) `
    'Uncorrelated SQL Server process was incorrectly recognized as SAP'
Assert-True (Test-SapProcessText 'sapstartsrv.exe pf=C:\usr\sap\ABC\SYS\profile\ABC_D00_host' 'DOMAIN\abcadm') `
    'SAP Start Service process was not recognized'

Register-SapInstance 'ABC' '00'
Assert-True ($script:SapInstanceNumbers.ContainsKey('00')) "Known instance registration failed; keys: $($script:SapInstanceNumbers.Keys -join ',')"
Assert-True (Test-SapProcessText 'sqlservr.exe -sABC' 'DOMAIN\SAPServiceABC') `
    'Database process with a known SAP SID service account was not correlated'
Assert-True (Test-SapProcessText 'C:\sybase\ABC\ASE-16_0\bin\dataserver.exe -sABC' 'DOMAIN\sybabc') `
    'SAP ASE process with a known syb<SID> account and installation path was not correlated'
Assert-True (-not (Test-SapProcessText 'C:\sybase\XYZ\ASE-16_0\bin\dataserver.exe -sXYZ' 'DOMAIN\sybxyz')) `
    'Uncorrelated Sybase process was incorrectly recognized as SAP ASE'

Add-SocketEvidence 'TCP' 'LISTEN' '127.0.0.1:8000' '*:*' '101' 'python' ''
Add-SocketEvidence 'TCP' 'LISTEN' '127.0.0.1:3200' '*:*' '' '' ''
Add-SocketEvidence 'TCP' 'LISTEN' '127.0.0.1:3301' '*:*' '' '' ''
Add-SocketEvidence 'TCP' 'LISTEN' '127.0.0.1:55555' '*:*' '200' 'sapstartsrv.exe' ''
$script:SapProductContext['ase'] = $true
Add-SocketEvidence 'TCP' 'ESTABLISHED' '127.0.0.1:4901' '127.0.0.1:40402' '' '' ''
$script:SapPids['300'] = $true
$script:SapProcessByPid['300'] = 'dataserver'
Add-SocketEvidence 'TCP' 'ESTABLISHED' '127.0.0.1:4901' '127.0.0.1:40403' '300' 'dataserver' ''

if ($script:Tables.SocketCandidates.Count -ne 1) {
    $script:Tables | ConvertTo-Json -Depth 5 | Write-Error
    throw "Expected one uncorroborated port candidate, got $($script:Tables.SocketCandidates.Count)"
}
Assert-True ($script:Tables.SocketCandidates[0].local -eq '127.0.0.1:3301') `
    'Ownerless uncorroborated instance port was not retained as a candidate'
Assert-True (@($script:Tables.SocketCandidates | Where-Object local -eq '127.0.0.1:8000').Count -eq 0) `
    'Port match with a visible non-SAP owner was retained as noise'
Assert-True ($script:Tables.Sockets.Count -eq 4) "Expected four promoted SAP sockets, got $($script:Tables.Sockets.Count)"
Assert-True (@($script:Tables.Sockets | Where-Object { $_.local -eq '127.0.0.1:3200' -and $_.confidence -eq 'medium' }).Count -eq 1) `
    'Known instance port was not promoted with medium confidence'
Assert-True (@($script:Tables.Sockets | Where-Object { $_.local -eq '127.0.0.1:55555' -and $_.confidence -eq 'high' }).Count -eq 1) `
    'SAP-owned nonstandard port was not promoted with high confidence'
Assert-True (@($script:Tables.Sockets | Where-Object {
    $_.local -eq '127.0.0.1:4901' -and
    $_.classification -eq 'SAP ASE Data Server' -and
    $_.confidence -eq 'medium'
}).Count -eq 1) 'Correlated local ASE service port did not override an unrelated ephemeral peer match'
Assert-True (@($script:Tables.Sockets | Where-Object {
    $_.remote -eq '127.0.0.1:40403' -and
    $_.classification -eq 'SAP ASE Data Server' -and
    $_.confidence -eq 'high'
}).Count -eq 1) 'SAP-owned ASE service port did not override an unrelated ephemeral peer match'

Write-Output 'PowerShell correlation regression: OK'
