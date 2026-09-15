[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    [string]$OutputDirectory,
    [string]$InstallerPath,

    [ValidatePattern('^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$')]
    [string]$ReleaseTag,

    [ValidateSet('stable', 'prerelease')]
    [string]$ReleaseChannel = 'stable',

    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$utf8NoBom = New-Object Text.UTF8Encoding($false)

if (-not $ReleaseTag) {
    $ReleaseTag = "v$Version"
}
if (($ReleaseChannel -eq 'stable') -and ($ReleaseTag -ne "v$Version")) {
    throw "Stable releases must use tag v$Version."
}
if (($ReleaseChannel -eq 'prerelease') -and (-not $ReleaseTag.StartsWith("v$Version-", [StringComparison]::Ordinal))) {
    throw "Prereleases must use a tag beginning with v$Version-."
}

function Read-Json([string]$Path) {
    return [IO.File]::ReadAllText($Path) | ConvertFrom-Json
}

function Read-NpmLock([string]$Path) {
    $script = @'
const fs = require('fs');
const lock = JSON.parse(fs.readFileSync(process.argv[1], 'utf8'));
const packages = Object.entries(lock.packages).map(([path, value]) => ({
  path,
  name: value.name || null,
  version: value.version || null,
  license: typeof value.license === 'string' ? value.license : null,
  resolved: value.resolved || null,
  dev: value.dev === true || value.devOptional === true
}));
console.log(JSON.stringify({ version: lock.version, packages }));
'@
    $node = if ($env:npm_node_execpath -and (Test-Path -LiteralPath $env:npm_node_execpath -PathType Leaf)) {
        $env:npm_node_execpath
    } else {
        (Get-Command node -ErrorAction Stop).Source
    }
    $output = & $node -e $script $Path
    if ($LASTEXITCODE -ne 0) {
        throw 'Node failed to normalize package-lock.json.'
    }
    return (($output -join "`n") | ConvertFrom-Json)
}

function Write-Utf8([string]$Path, [string]$Content) {
    [IO.File]::WriteAllText($Path, "$Content`n", $utf8NoBom)
}

function Set-TarField([byte[]]$Header, [int]$Offset, [int]$Length, [string]$Value) {
    $bytes = [Text.Encoding]::ASCII.GetBytes($Value)
    if ($bytes.Length -gt $Length) {
        throw "Tar header field is too long: $Value"
    }
    [Array]::Copy($bytes, 0, $Header, $Offset, $bytes.Length)
}

function Get-TarOctal([long]$Value, [int]$Length) {
    $octal = [Convert]::ToString($Value, 8)
    if ($octal.Length -gt ($Length - 1)) {
        throw "Value $Value does not fit in a tar header field."
    }
    return $octal.PadLeft($Length - 1, '0') + [char]0
}

function Write-TarGzip([string]$SourceDirectory, [string]$ArchivePath, [string]$Prefix) {
    $archiveStream = [IO.File]::Open($ArchivePath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $gzip = New-Object IO.Compression.GZipStream($archiveStream, [IO.Compression.CompressionLevel]::Optimal, $true)
        try {
            foreach ($file in (Get-ChildItem -LiteralPath $SourceDirectory -File -Recurse | Sort-Object FullName)) {
                $relative = $file.FullName.Substring($SourceDirectory.Length).TrimStart('\', '/').Replace('\', '/')
                $entryName = "$Prefix/$relative"
                $name = $entryName
                $pathPrefix = ''
                if ([Text.Encoding]::ASCII.GetByteCount($entryName) -gt 100) {
                    $split = $entryName.LastIndexOf('/')
                    while (($split -gt 0) -and
                        (([Text.Encoding]::ASCII.GetByteCount($entryName.Substring($split + 1)) -gt 100) -or
                         ([Text.Encoding]::ASCII.GetByteCount($entryName.Substring(0, $split)) -gt 155))) {
                        $split = $entryName.LastIndexOf('/', $split - 1)
                    }
                    if ($split -le 0) {
                        throw "Path does not fit in a POSIX ustar header: $entryName"
                    }
                    $pathPrefix = $entryName.Substring(0, $split)
                    $name = $entryName.Substring($split + 1)
                }
                if ([Text.Encoding]::ASCII.GetString([Text.Encoding]::ASCII.GetBytes($entryName)) -cne $entryName) {
                    throw "Non-ASCII snapshot path is not supported by the conservative ustar writer: $entryName"
                }

                $header = New-Object byte[] 512
                Set-TarField $header 0 100 $name
                Set-TarField $header 100 8 (Get-TarOctal 420 8)
                Set-TarField $header 108 8 (Get-TarOctal 0 8)
                Set-TarField $header 116 8 (Get-TarOctal 0 8)
                Set-TarField $header 124 12 (Get-TarOctal $file.Length 12)
                $modified = [DateTimeOffset]::new($file.LastWriteTimeUtc).ToUnixTimeSeconds()
                Set-TarField $header 136 12 (Get-TarOctal $modified 12)
                for ($index = 148; $index -lt 156; $index++) {
                    $header[$index] = 32
                }
                $header[156] = [byte][char]'0'
                Set-TarField $header 257 6 ("ustar" + [char]0)
                Set-TarField $header 263 2 '00'
                if ($pathPrefix) {
                    Set-TarField $header 345 155 $pathPrefix
                }
                $checksum = 0
                foreach ($value in $header) {
                    $checksum += $value
                }
                Set-TarField $header 148 8 (([Convert]::ToString($checksum, 8).PadLeft(6, '0')) + [char]0 + ' ')
                $gzip.Write($header, 0, $header.Length)

                $input = [IO.File]::OpenRead($file.FullName)
                try {
                    $input.CopyTo($gzip)
                } finally {
                    $input.Dispose()
                }
                $paddingLength = (512 - ($file.Length % 512)) % 512
                if ($paddingLength -gt 0) {
                    $padding = New-Object byte[] $paddingLength
                    $gzip.Write($padding, 0, $padding.Length)
                }
            }
            $endBlocks = New-Object byte[] 1024
            $gzip.Write($endBlocks, 0, $endBlocks.Length)
        } finally {
            $gzip.Dispose()
        }
    } finally {
        $archiveStream.Dispose()
    }
}

function Assert-Version([string]$Label, [string]$Actual) {
    if ($Actual -ne $Version) {
        throw "$Label is '$Actual'; expected '$Version'."
    }
}

function Get-LocalLockVersion([string]$LockPath, [string]$PackageName) {
    $escapedName = [regex]::Escape($PackageName)
    $match = [regex]::Match(
        [IO.File]::ReadAllText($LockPath),
        "(?ms)^\[\[package\]\]\r?\nname = `"$escapedName`"\r?\nversion = `"([^`"]+)`""
    )
    if (-not $match.Success) {
        throw "Package '$PackageName' was not found in $LockPath."
    }
    return $match.Groups[1].Value
}

function Get-CargoCommand {
    $command = Get-Command cargo -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    $userCargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
    if (Test-Path -LiteralPath $userCargo -PathType Leaf) {
        return $userCargo
    }
    throw 'cargo was not found on PATH or in the default rustup location.'
}

function Get-SpdxId([string]$Ecosystem, [string]$Name, [string]$PackageVersion) {
    $safeName = $Name -replace '[^A-Za-z0-9.-]', '-'
    $bytes = [Text.Encoding]::UTF8.GetBytes("$Ecosystem`:$Name@$PackageVersion")
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $suffix = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').Substring(0, 12)
    } finally {
        $sha.Dispose()
    }
    return "SPDXRef-$Ecosystem-$safeName-$suffix"
}

function Add-SbomRecord(
    [hashtable]$Records,
    [string]$Ecosystem,
    [string]$Name,
    [string]$PackageVersion,
    [string]$License,
    [string]$DownloadLocation,
    [string]$Scope,
    [string]$Purpose
) {
    if (-not $Name -or -not $PackageVersion) {
        return
    }
    $key = "$Ecosystem`:$Name@$PackageVersion"
    if (-not $Records.ContainsKey($key)) {
        $Records[$key] = [ordered]@{
            ecosystem = $Ecosystem
            name = $Name
            version = $PackageVersion
            license = $License
            download = $(if ($DownloadLocation) { $DownloadLocation } else { 'NOASSERTION' })
            scope = $Scope
            purpose = $Purpose
        }
    } elseif ((Get-ScopeRank $Scope) -gt (Get-ScopeRank $Records[$key].scope)) {
        $Records[$key].scope = $Scope
    }
}

function Get-ScopeRank([string]$Scope) {
    switch ($Scope) {
        'contained' { return 4 }
        'runtime' { return 3 }
        'build' { return 2 }
        'development' { return 1 }
        default { return 0 }
    }
}

function Test-ExcludedSnapshotPath([string]$RelativePath, [bool]$IsDirectory, [bool]$NonGitSnapshot = $false) {
    $normalized = $RelativePath.Replace('\', '/')
    if ($normalized -match '(^|/)(\.git|node_modules|target|release|dist|coverage|build|\.venv|\.pytest_cache|__pycache__|\.idea|\.vscode|cases|samples|malware)(/|$)') {
        return $true
    }
    if ($normalized -match '^apps/desktop/src-tauri/(gen|binaries)(/|$)') {
        return $true
    }
    if ($NonGitSnapshot -and -not $IsDirectory -and
        ([IO.Path]::GetExtension($normalized) -ieq '.exe') -and
        ($normalized -match '^testfiles/[^/]+$')) {
        return $true
    }
    if (-not $IsDirectory) {
        $name = [IO.Path]::GetFileName($normalized)
        if (($name -eq '.env') -or (($name -like '.env.*') -and ($name -ne '.env.example'))) {
            return $true
        }
        if ($name -match '(?i)(^|[._-])(credentials?|secrets?|id_rsa|id_ed25519)([._-]|$)') {
            return $true
        }
        if ([IO.Path]::GetExtension($name) -match '(?i)^\.(key|pem|pfx|p12|cer|der|jks|keystore)$') {
            return $true
        }
    }
    return $false
}

function Get-SnapshotFiles([string]$Directory, [string]$RelativeBase) {
    $files = New-Object Collections.Generic.List[IO.FileInfo]
    foreach ($entry in Get-ChildItem -LiteralPath $Directory -Force) {
        $relative = if ($RelativeBase) { "$RelativeBase/$($entry.Name)" } else { $entry.Name }
        $isDirectory = $entry -is [IO.DirectoryInfo]
        if (Test-ExcludedSnapshotPath $relative $isDirectory $true) {
            continue
        }
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            continue
        }
        if ($isDirectory) {
            foreach ($file in Get-SnapshotFiles $entry.FullName $relative) {
                $files.Add($file)
            }
        } else {
            $files.Add($entry)
        }
    }
    return $files
}

$rootPackage = Read-Json (Join-Path $root 'package.json')
$desktopPackage = Read-Json (Join-Path $root 'apps\desktop\package.json')
$npmLock = Read-NpmLock (Join-Path $root 'package-lock.json')
$tauriConfig = Read-Json (Join-Path $root 'apps\desktop\src-tauri\tauri.conf.json')
$cargoToml = [IO.File]::ReadAllText((Join-Path $root 'Cargo.toml'))
$workspaceVersion = [regex]::Match($cargoToml, '(?m)^version = "([^"]+)"').Groups[1].Value

Assert-Version 'root package.json' $rootPackage.version
Assert-Version 'desktop package.json' $desktopPackage.version
Assert-Version 'package-lock.json root' $npmLock.version
Assert-Version 'package-lock.json root package' (($npmLock.packages | Where-Object path -eq '').version)
Assert-Version 'package-lock.json desktop workspace' (($npmLock.packages | Where-Object path -eq 'apps/desktop').version)
Assert-Version 'Cargo workspace' $workspaceVersion
Assert-Version 'Tauri config' $tauriConfig.version

$workspacePackages = @(
    'artifacta-desktop', 'tf-case', 'tf-db', 'tf-model', 'tf-pe',
    'tf-protocol', 'tf-report', 'tf-rules', 'tf-store', 'tf-yara'
)
foreach ($packageName in $workspacePackages) {
    Assert-Version "Cargo.lock $packageName" (Get-LocalLockVersion (Join-Path $root 'Cargo.lock') $packageName)
}
foreach ($packageName in @('tf-model', 'tf-pe', 'tf-protocol', 'tf-report')) {
    Assert-Version "fuzz/Cargo.lock $packageName" (Get-LocalLockVersion (Join-Path $root 'fuzz\Cargo.lock') $packageName)
}

$frontend = [IO.File]::ReadAllText((Join-Path $root 'apps\desktop\src\App.tsx'))
if (-not $frontend.Contains("hostStatus?.version ?? `"$Version`"")) {
    throw "The UI fallback is not $Version."
}
if ($tauriConfig.identifier -ne 'org.traceforge.desktop') {
    throw 'The intentional legacy Tauri identifier changed without a migration.'
}
if ($tauriConfig.bundle.createUpdaterArtifacts -ne $false) {
    throw 'Updater artifacts must remain disabled.'
}
if ($tauriConfig.bundle.windows.allowDowngrades -ne $false) {
    throw 'Installer downgrades must remain disabled.'
}

Write-Host "Version consistency check passed for $Version."
if ($CheckOnly) {
    exit 0
}

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $root "release\$Version"
} elseif (-not [IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory = Join-Path $root $OutputDirectory
}
$finalOutputDirectory = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\', '/')
if (($finalOutputDirectory -eq [IO.Path]::GetPathRoot($finalOutputDirectory).TrimEnd('\', '/')) -or
    ($finalOutputDirectory -eq $root.TrimEnd('\', '/'))) {
    throw "Refusing unsafe release output directory: $finalOutputDirectory"
}
if (Test-Path -LiteralPath $finalOutputDirectory -PathType Leaf) {
    throw "Release output path is a file: $finalOutputDirectory"
}

$stageRoot = Join-Path ([IO.Path]::GetTempPath()) ("artifacta-release-output-" + [guid]::NewGuid().ToString('N'))
$OutputDirectory = Join-Path $stageRoot 'output'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

try {

$expectedInstallerName = "Artifacta_${Version}_x64-setup.exe"
$installerStatus = 'NOT ASSESSED: installer was not supplied to the release tool.'
$installerDestination = $null
if ($InstallerPath) {
    $resolvedInstaller = (Resolve-Path -LiteralPath $InstallerPath).Path
    $finalPrefix = $finalOutputDirectory + [IO.Path]::DirectorySeparatorChar
    if ([IO.Path]::GetFullPath($resolvedInstaller).StartsWith($finalPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'InstallerPath must not point into the reusable release output directory.'
    }
    if ([IO.Path]::GetFileName($resolvedInstaller) -cne $expectedInstallerName) {
        throw "Installer must be named exactly '$expectedInstallerName'."
    }
    $installerDestination = Join-Path $OutputDirectory $expectedInstallerName
    if ([IO.Path]::GetFullPath($resolvedInstaller) -ne [IO.Path]::GetFullPath($installerDestination)) {
        Copy-Item -LiteralPath $resolvedInstaller -Destination $installerDestination -Force
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $installerDestination
    if ($signature.Status -eq 'Valid') {
        $installerStatus = "SIGNED: Authenticode signature is valid; signer subject: $($signature.SignerCertificate.Subject)"
    } else {
        $installerStatus = "UNSIGNED: Authenticode status is $($signature.Status). No signing is performed by this tool or the release workflow."
    }
}
Write-Utf8 (Join-Path $OutputDirectory 'SIGNING-STATUS.txt') $installerStatus

Copy-Item -LiteralPath (Join-Path $root 'LICENSE') -Destination (Join-Path $OutputDirectory 'LICENSE.txt') -Force
Copy-Item -LiteralPath (Join-Path $root 'NOTICE') -Destination (Join-Path $OutputDirectory 'NOTICE.txt') -Force

$sourceName = "artifacta-$Version-source.tar.gz"
$sourcePath = Join-Path $OutputDirectory $sourceName
$insideGit = $false
$sourceCommit = $null
$git = Get-Command git -ErrorAction SilentlyContinue
if ($git -and (Test-Path -LiteralPath (Join-Path $root '.git'))) {
    $gitResult = & $git.Source -C $root rev-parse --is-inside-work-tree 2>$null
    $insideGit = ($LASTEXITCODE -eq 0) -and (($gitResult -join '').Trim() -eq 'true')
}
if ($insideGit) {
    $gitStatus = @(& $git.Source -C $root status --porcelain=v1 --untracked-files=all)
    if ($LASTEXITCODE -ne 0) {
        throw 'git status failed before release preparation.'
    }
    if ($gitStatus.Count -gt 0) {
        throw "Refusing to prepare a Git release from a dirty working tree:`n$($gitStatus -join "`n")"
    }
    $sourceCommit = ((& $git.Source -C $root rev-parse HEAD) -join '').Trim()
    if (($LASTEXITCODE -ne 0) -or ($sourceCommit -notmatch '^[0-9a-f]{40}$')) {
        throw 'Could not resolve the source commit before release preparation.'
    }
    $trackedFiles = & $git.Source -C $root ls-files
    if ($LASTEXITCODE -ne 0) {
        throw 'git ls-files failed before source archive creation.'
    }
    $unsafeTracked = @($trackedFiles | Where-Object { Test-ExcludedSnapshotPath $_ $false })
    if ($unsafeTracked.Count -gt 0) {
        throw "Refusing to archive excluded or secret-like tracked paths: $($unsafeTracked -join ', ')"
    }
    & $git.Source -C $root archive --format=tar.gz "--prefix=artifacta-$Version/" "--output=$sourcePath" HEAD
    if ($LASTEXITCODE -ne 0) {
        throw 'git archive failed.'
    }
    $sourceMethod = "git archive $sourceCommit"
} else {
    $sourceStageRoot = Join-Path ([IO.Path]::GetTempPath()) ("artifacta-release-source-" + [guid]::NewGuid().ToString('N'))
    $stageSource = Join-Path $sourceStageRoot "artifacta-$Version"
    New-Item -ItemType Directory -Path $stageSource -Force | Out-Null
    try {
        foreach ($file in Get-SnapshotFiles $root '') {
            $relative = $file.FullName.Substring($root.Length).TrimStart('\', '/')
            $destination = Join-Path $stageSource $relative
            $parent = Split-Path -Parent $destination
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
            Copy-Item -LiteralPath $file.FullName -Destination $destination
        }
        Write-TarGzip $stageSource $sourcePath "artifacta-$Version"
    } finally {
        Remove-Item -LiteralPath $sourceStageRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    $sourceMethod = 'filtered non-git snapshot'
}

$cargo = Get-CargoCommand
$cargoOutput = & $cargo metadata --locked --format-version 1 --manifest-path (Join-Path $root 'Cargo.toml')
if ($LASTEXITCODE -ne 0) {
    throw 'cargo metadata failed while generating the SBOM.'
}
$cargoMetadata = ($cargoOutput -join "`n") | ConvertFrom-Json
$records = @{}
$workspaceMemberIds = @{}
foreach ($id in $cargoMetadata.workspace_members) {
    $workspaceMemberIds[$id] = $true
}

# Classify the resolved Cargo graph without presenting test/build tools as runtime dependencies.
$nodeById = @{}
foreach ($node in $cargoMetadata.resolve.nodes) {
    $nodeById[$node.id] = $node
}
$scopeById = @{}
$scopeQueue = New-Object Collections.Generic.Queue[object]
foreach ($id in $cargoMetadata.workspace_members) {
    $scopeById[$id] = 'contained'
    $scopeQueue.Enqueue([pscustomobject]@{ id = $id; scope = 'runtime' })
}
while ($scopeQueue.Count -gt 0) {
    $current = $scopeQueue.Dequeue()
    $node = $nodeById[$current.id]
    if (-not $node) {
        continue
    }
    foreach ($dependency in $node.deps) {
        $edgeScope = 'development'
        foreach ($dependencyKind in $dependency.dep_kinds) {
            $candidateScope = switch ($dependencyKind.kind) {
                'dev' { 'development' }
                'build' { 'build' }
                default { 'runtime' }
            }
            if ((Get-ScopeRank $candidateScope) -gt (Get-ScopeRank $edgeScope)) {
                $edgeScope = $candidateScope
            }
        }
        $nextScope = if ($current.scope -eq 'development') {
            'development'
        } elseif (($current.scope -eq 'build') -or ($edgeScope -eq 'build')) {
            'build'
        } else {
            $edgeScope
        }
        if ((Get-ScopeRank $nextScope) -gt (Get-ScopeRank $scopeById[$dependency.pkg])) {
            $scopeById[$dependency.pkg] = $nextScope
            $scopeQueue.Enqueue([pscustomobject]@{ id = $dependency.pkg; scope = $nextScope })
        }
    }
}
foreach ($package in $cargoMetadata.packages) {
    $download = if ($package.source -and $package.source.StartsWith('registry+')) {
        "https://crates.io/crates/$($package.name)/$($package.version)/download"
    } else {
        'NOASSERTION'
    }
    $scope = if ($workspaceMemberIds.ContainsKey($package.id)) { 'contained' } elseif ($scopeById[$package.id]) { $scopeById[$package.id] } else { 'inventory' }
    $purpose = if ($package.name -eq 'artifacta-desktop') { 'APPLICATION' } else { 'LIBRARY' }
    Add-SbomRecord $records 'cargo' $package.name $package.version $package.license $download $scope $purpose
}

Add-SbomRecord $records 'npm' $desktopPackage.name $desktopPackage.version $desktopPackage.license 'NOASSERTION' 'contained' 'APPLICATION'
foreach ($npmPackage in $npmLock.packages) {
    if (($npmPackage.path -notmatch '(^|/)node_modules/') -or -not $npmPackage.version) {
        continue
    }
    $tail = ($npmPackage.path -split 'node_modules/')[-1]
    $segments = $tail -split '/'
    $derivedName = if ($segments[0].StartsWith('@') -and $segments.Count -gt 1) {
        "$($segments[0])/$($segments[1])"
    } else {
        $segments[0]
    }
    $name = if ($npmPackage.name) { $npmPackage.name } else { $derivedName }
    $scope = if ($npmPackage.dev) { 'development' } else { 'runtime' }
    Add-SbomRecord $records 'npm' $name $npmPackage.version $npmPackage.license $npmPackage.resolved $scope 'LIBRARY'
}

$rootSpdxId = 'SPDXRef-Package-Artifacta'
$spdxPackages = New-Object Collections.Generic.List[object]
$spdxPackages.Add([ordered]@{
    SPDXID = $rootSpdxId
    name = 'Artifacta'
    versionInfo = $Version
    downloadLocation = 'NOASSERTION'
    filesAnalyzed = $false
    licenseConcluded = 'Apache-2.0'
    licenseDeclared = 'Apache-2.0'
    copyrightText = 'Copyright 2026 Artifacta contributors'
    primaryPackagePurpose = 'APPLICATION'
})
$relationships = New-Object Collections.Generic.List[object]
$relationships.Add([ordered]@{
    spdxElementId = 'SPDXRef-DOCUMENT'
    relationshipType = 'DESCRIBES'
    relatedSpdxElement = $rootSpdxId
})
foreach ($record in ($records.Values | Sort-Object { $_['ecosystem'] }, { $_['name'] }, { $_['version'] })) {
    $spdxId = Get-SpdxId $record.ecosystem $record.name $record.version
    $purlName = if (($record.ecosystem -eq 'npm') -and $record.name.StartsWith('@') -and $record.name.Contains('/')) {
        $scopeAndName = $record.name.Substring(1).Split('/', 2)
        "%40$([uri]::EscapeDataString($scopeAndName[0]))/$([uri]::EscapeDataString($scopeAndName[1]))"
    } else {
        [uri]::EscapeDataString($record.name)
    }
    $package = [ordered]@{
        SPDXID = $spdxId
        name = $record.name
        versionInfo = $record.version
        downloadLocation = $record.download
        filesAnalyzed = $false
        licenseConcluded = 'NOASSERTION'
        licenseDeclared = 'NOASSERTION'
        copyrightText = 'NOASSERTION'
        primaryPackagePurpose = $record.purpose
        comment = "Conservative lockfile inventory scope: $($record.scope). Runtime relationships may be transitive; npm development scope includes build and test tooling."
        externalRefs = @([ordered]@{
            referenceCategory = 'PACKAGE-MANAGER'
            referenceType = 'purl'
            referenceLocator = "pkg:$($record.ecosystem)/$purlName@$([uri]::EscapeDataString($record.version))"
        })
    }
    if ($record.license) {
        $package.licenseComments = "Declared by package metadata: $($record.license)"
    }
    $spdxPackages.Add($package)
    $relationship = switch ($record.scope) {
        'contained' {
            [ordered]@{ spdxElementId = $rootSpdxId; relationshipType = 'CONTAINS'; relatedSpdxElement = $spdxId }
        }
        'runtime' {
            [ordered]@{ spdxElementId = $rootSpdxId; relationshipType = 'DEPENDS_ON'; relatedSpdxElement = $spdxId }
        }
        'build' {
            [ordered]@{ spdxElementId = $spdxId; relationshipType = 'BUILD_DEPENDENCY_OF'; relatedSpdxElement = $rootSpdxId }
        }
        'development' {
            [ordered]@{ spdxElementId = $spdxId; relationshipType = 'DEV_DEPENDENCY_OF'; relatedSpdxElement = $rootSpdxId }
        }
        default {
            [ordered]@{
                spdxElementId = $rootSpdxId
                relationshipType = 'OTHER'
                relatedSpdxElement = $spdxId
                comment = 'Present in resolved metadata but not reachable in the classified workspace graph.'
            }
        }
    }
    $relationships.Add($relationship)
}

$lockFingerprintInput = (Get-FileHash (Join-Path $root 'Cargo.lock') -Algorithm SHA256).Hash +
    (Get-FileHash (Join-Path $root 'package-lock.json') -Algorithm SHA256).Hash
$fingerprintBytes = [Text.Encoding]::UTF8.GetBytes($lockFingerprintInput)
$fingerprintSha = [Security.Cryptography.SHA256]::Create()
try {
    $fingerprint = ([BitConverter]::ToString($fingerprintSha.ComputeHash($fingerprintBytes))).Replace('-', '').Substring(0, 16).ToLowerInvariant()
} finally {
    $fingerprintSha.Dispose()
}
$createdUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$spdx = [ordered]@{
    spdxVersion = 'SPDX-2.3'
    dataLicense = 'CC0-1.0'
    SPDXID = 'SPDXRef-DOCUMENT'
    name = "Artifacta $Version SBOM"
    documentNamespace = "https://spdx.org/spdxdocs/artifacta-$Version-$fingerprint"
    creationInfo = [ordered]@{
        created = $createdUtc
        creators = @('Tool: tools/release.ps1')
    }
    packages = $spdxPackages
    relationships = $relationships
}
$sbomName = "artifacta-$Version.spdx.json"
Write-Utf8 (Join-Path $OutputDirectory $sbomName) ($spdx | ConvertTo-Json -Depth 12)

$cycloneDxComponents = New-Object Collections.Generic.List[object]
$cycloneDxComponents.Add([ordered]@{
    type = 'application'
    name = 'Artifacta'
    version = $Version
    purl = "pkg:generic/artifacta@${Version}"
    scope = 'required'
    licenses = @(@{ license = [ordered]@{ id = 'Apache-2.0' } })
})
foreach ($record in ($records.Values | Sort-Object { $_['ecosystem'] }, { $_['name'] }, { $_['version'] })) {
    $purlName = if (($record.ecosystem -eq 'npm') -and $record.name.StartsWith('@') -and $record.name.Contains('/')) {
        $scopeAndName = $record.name.Substring(1).Split('/', 2)
        "%40$([uri]::EscapeDataString($scopeAndName[0]))/$([uri]::EscapeDataString($scopeAndName[1]))"
    } else {
        [uri]::EscapeDataString($record.name)
    }
    $scope = if ($record.scope -eq 'development') { 'optional' } else { 'required' }
    $component = [ordered]@{
        type = 'library'
        name = $record.name
        version = $record.version
        purl = "pkg:$($record.ecosystem)/$purlName@$([uri]::EscapeDataString($record.version))"
        scope = $scope
    }
    if ($record.license) {
        $component.licenses = @(@{ license = [ordered]@{ name = $record.license } })
    }
    if ($record.download -and $record.download -ne 'NOASSERTION') {
        $component.externalReferences = @(@{
            type = 'distribution'
            url = $record.download
        })
    }
    $cycloneDxComponents.Add($component)
}
$cycloneDx = [ordered]@{
    bomFormat = 'CycloneDX'
    specVersion = '1.6'
    version = 1
    metadata = [ordered]@{
        tools = @(@{ name = 'tools/release.ps1' })
        component = [ordered]@{
            type = 'application'
            name = 'Artifacta'
            version = $Version
        }
        timestamp = $createdUtc
    }
    components = $cycloneDxComponents
}
$cycloneDxName = "artifacta-$Version.cdx.json"
Write-Utf8 (Join-Path $OutputDirectory $cycloneDxName) ($cycloneDx | ConvertTo-Json -Depth 12)

$releaseMetadata = [ordered]@{
    schemaVersion = 1
    product = 'Artifacta'
    version = $Version
    tag = $ReleaseTag
    releaseChannel = $ReleaseChannel
    qualificationStatus = $(if ($ReleaseChannel -eq 'prerelease') { 'pre-release evaluation; Windows lifecycle qualification pending' } else { 'stable release' })
    platform = 'windows-x86_64'
    tauriIdentifier = 'org.traceforge.desktop'
    identifierStatus = 'intentional legacy identifier retained for local-data compatibility'
    installer = [ordered]@{
        expectedName = $expectedInstallerName
        included = [bool]$installerDestination
        authenticode = $installerStatus
        publisher = 'Artifacta'
    }
    repository = 'https://github.com/ThejasRajamoney/Artifacta'
    securityReporting = 'https://github.com/ThejasRajamoney/Artifacta/security/advisories/new'
    signingPolicy = 'Installers are Authenticode-signed only when a trusted certificate is configured; otherwise the release is explicitly marked unsigned and distributed with SHA-256 checksums.'
    updaterEnabled = $false
    sourceArchive = $sourceName
    sourceMethod = $sourceMethod
    sourceCommit = $sourceCommit
    sbom = $sbomName
    sbomFormat = 'SPDX-2.3 JSON'
    cycloneDxSbom = $cycloneDxName
    cycloneDxFormat = 'CycloneDX 1.6 JSON'
    sbomScope = 'Conservative Cargo and npm resolved inventory; relationships distinguish contained application packages, runtime dependencies, Cargo build dependencies, and development/test/build tooling.'
    licenseNotices = @('LICENSE.txt', 'NOTICE.txt')
    unresolved = @()
    generatedUtc = $createdUtc
}
Write-Utf8 (Join-Path $OutputDirectory 'release-metadata.json') ($releaseMetadata | ConvertTo-Json -Depth 8)

$payloadNames = @(
    'LICENSE.txt',
    'NOTICE.txt',
    'SIGNING-STATUS.txt',
    $sourceName,
    $sbomName,
    $cycloneDxName,
    'release-metadata.json'
)
if ($installerDestination) {
    $payloadNames += $expectedInstallerName
}
$payloads = $payloadNames | Sort-Object | ForEach-Object {
    Get-Item -LiteralPath (Join-Path $OutputDirectory $_)
}
$checksumLines = foreach ($payload in $payloads) {
    $hash = (Get-FileHash -LiteralPath $payload.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $($payload.Name)"
}
Write-Utf8 (Join-Path $OutputDirectory 'SHA256SUMS') ($checksumLines -join "`n")
if ($installerDestination) {
    $installerHash = (Get-FileHash -LiteralPath $installerDestination -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Utf8 "$installerDestination.sha256" "$installerHash  $expectedInstallerName"
}

$expectedNames = @($payloadNames) + @('SHA256SUMS')
if ($installerDestination) {
    $expectedNames += "$expectedInstallerName.sha256"
}
$actualEntries = @(Get-ChildItem -LiteralPath $OutputDirectory -Force)
$unexpected = @($actualEntries | Where-Object { $_.PSIsContainer -or ($expectedNames -cnotcontains $_.Name) } | ForEach-Object Name)
$actualNames = @($actualEntries | Where-Object { -not $_.PSIsContainer } | ForEach-Object Name)
$missing = @($expectedNames | Where-Object { $actualNames -cnotcontains $_ })
if (($unexpected.Count -gt 0) -or ($missing.Count -gt 0)) {
    throw "Release staging allowlist mismatch. Unexpected: $($unexpected -join ', '); missing: $($missing -join ', ')."
}

$finalParent = Split-Path -Parent $finalOutputDirectory
New-Item -ItemType Directory -Path $finalParent -Force | Out-Null
if (Test-Path -LiteralPath $finalOutputDirectory) {
    $replaceableNames = @($expectedNames) + @($expectedInstallerName, "$expectedInstallerName.sha256")
    $existingUnexpected = @(Get-ChildItem -LiteralPath $finalOutputDirectory -Force |
        Where-Object { $_.PSIsContainer -or ($replaceableNames -cnotcontains $_.Name) } |
        ForEach-Object Name)
    if ($existingUnexpected.Count -gt 0) {
        throw "Refusing to replace output containing unexpected entries: $($existingUnexpected -join ', ')"
    }
    Remove-Item -LiteralPath $finalOutputDirectory -Recurse -Force
}
Move-Item -LiteralPath $OutputDirectory -Destination $finalOutputDirectory
Write-Host "Release companions written to $finalOutputDirectory"
} finally {
    if (Test-Path -LiteralPath $stageRoot) {
        Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
