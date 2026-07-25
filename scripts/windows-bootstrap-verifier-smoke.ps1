param(
    [Parameter(Mandatory = $true)]
    [string]$VerifierPackagePath,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedVerifierPackageSHA256,
    [Parameter(Mandatory = $true)]
    [string]$AnchorPath,
    [Parameter(Mandatory = $true)]
    [string]$HandoffPath,
    [Parameter(Mandatory = $true)]
    [string]$RootPath,
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,
    [Parameter(Mandatory = $true)]
    [string[]]$SignaturePath,
    [Parameter(Mandatory = $true)]
    [string]$InstallerPath,
    [string]$ReceiptDirectory = "",
    [string]$Now = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($env:MESH_WINDOWS_BOOTSTRAP_NATIVE_TEST -ne "1") {
    throw "Set MESH_WINDOWS_BOOTSTRAP_NATIVE_TEST=1 explicitly on an isolated Windows test host."
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "The native Windows bootstrap proof requires an elevated Administrator shell."
}

$architecture = switch ($env:PROCESSOR_ARCHITECTURE.ToUpperInvariant()) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    default { throw "Unsupported Windows architecture $($env:PROCESSOR_ARCHITECTURE)." }
}
if ($ExpectedVerifierPackageSHA256 -cnotmatch '^[0-9a-f]{64}$') {
    throw "ExpectedVerifierPackageSHA256 must be 64 lowercase hexadecimal characters obtained independently."
}
if ($SignaturePath.Count -lt 1 -or $SignaturePath.Count -gt 16) {
    throw "Pass between 1 and 16 detached root-role signature paths."
}
if (-not [string]::IsNullOrWhiteSpace($Now)) {
    $parsedNow = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact($Now, "yyyy-MM-ddTHH:mm:ssZ", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsedNow)) {
        throw "Now must be canonical UTC RFC3339 without fractional seconds."
    }
}

function Resolve-RegularFile([string]$Role, [string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "$Role path is required."
    }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $item = Get-Item -LiteralPath $resolved -Force
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or $item.Length -le 0) {
        throw "$Role must be a nonempty regular file, not a directory or reparse point."
    }
    return $resolved
}

function Get-LowerSHA256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

$repository = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$package = Resolve-RegularFile "verifier package" $VerifierPackagePath
$anchor = Resolve-RegularFile "bootstrap anchor" $AnchorPath
$handoff = Resolve-RegularFile "bootstrap handoff" $HandoffPath
$root = Resolve-RegularFile "bootstrap root" $RootPath
$manifest = Resolve-RegularFile "bootstrap manifest" $ManifestPath
$installer = Resolve-RegularFile "Windows installer" $InstallerPath
$signatures = @()
foreach ($path in $SignaturePath) {
    $signatures += Resolve-RegularFile "bootstrap signature" $path
}

$tar = Get-Command tar.exe -ErrorAction Stop
$proofParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$proofLeaf = "mesh-windows-bootstrap-native-" + [Guid]::NewGuid().ToString("N")
$proofRoot = Join-Path $proofParent $proofLeaf
New-Item -ItemType Directory -Path $proofRoot | Out-Null
try {
    & icacls.exe $proofRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not apply the private LocalSystem/Administrators proof DACL."
    }
    $proofItem = Get-Item -LiteralPath $proofRoot -Force
    if (($proofItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Private proof directory became a reparse point."
    }

    $authenticatedPackage = Join-Path $proofRoot "verifier-package.tar"
    [IO.File]::Copy($package, $authenticatedPackage, $false)
    $packageSHA256 = Get-LowerSHA256 $authenticatedPackage
    if ($packageSHA256 -cne $ExpectedVerifierPackageSHA256) {
        throw "Private verifier-package snapshot differs from the digest obtained through the independent channel."
    }
    $members = @(& $tar.Source -tf $authenticatedPackage)
    if ($LASTEXITCODE -ne 0) {
        throw "Windows tar could not list the authenticated verifier package."
    }
    $expectedMembers = @("package.json", "bin/mesh-bootstrap-verify.exe")
    if ($members.Count -ne $expectedMembers.Count) {
        throw "Authenticated Windows verifier package does not contain exactly two members."
    }
    for ($index = 0; $index -lt $expectedMembers.Count; $index++) {
        if ($members[$index] -cne $expectedMembers[$index]) {
            throw "Authenticated Windows verifier package member $index is not canonical."
        }
    }

    & $tar.Source -xf $authenticatedPackage -C $proofRoot "bin/mesh-bootstrap-verify.exe"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not extract the exact verifier from the authenticated package."
    }
    $verifier = Resolve-RegularFile "extracted standalone verifier" (Join-Path $proofRoot "bin\mesh-bootstrap-verify.exe")
    $verifierSHA256 = Get-LowerSHA256 $verifier

    $arguments = @(
        "--handoff", $handoff,
        "--handoff-anchor", $anchor,
        "--root", $root,
        "--manifest", $manifest
    )
    foreach ($signature in $signatures) {
        $arguments += @("--signature", $signature)
    }
    $arguments += @("--installer", $installer)
    if (-not [string]::IsNullOrWhiteSpace($Now)) {
        $arguments += @("--now", $Now)
    }

    $stderrPath = Join-Path $proofRoot "verifier.stderr"
    $output = @(& $verifier @arguments 2> $stderrPath)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        $diagnostics = ""
        if (Test-Path -LiteralPath $stderrPath) {
            $diagnostics = [IO.File]::ReadAllText($stderrPath)
        }
        throw "Native standalone verifier failed with exit code $exitCode. $diagnostics"
    }
    if ($output.Count -ne 1) {
        throw "Native standalone verifier emitted an unexpected number of receipt lines."
    }
    $verification = $output[0] | ConvertFrom-Json
    $anchorSHA256 = Get-LowerSHA256 $anchor
    $handoffSHA256 = Get-LowerSHA256 $handoff
    $rootSHA256 = Get-LowerSHA256 $root
    $installerSHA256 = Get-LowerSHA256 $installer
    if ($verification.schema -cne "mesh-bootstrap-verification-v3" -or
        $verification.os -cne "windows" -or $verification.arch -cne $architecture -or
        $verification.anchor_sha256 -cne $anchorSHA256 -or
        $verification.handoff_sha256 -cne $handoffSHA256 -or
        $verification.verifier_package_sha256 -cne $packageSHA256 -or
        $verification.root_sha256 -cne $rootSHA256 -or
        $verification.installer_sha256 -cne $installerSHA256) {
        throw "Native standalone verifier receipt does not bind the exact Windows host, authority, package, root, and installer."
    }
    if ($verification.authenticode_policy_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $verification.authenticode_signer_spki_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $verification.authenticode_certificate_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "Native standalone verifier receipt does not bind the exact Authenticode policy, signer SPKI, and signer certificate."
    }

    if ([string]::IsNullOrWhiteSpace($ReceiptDirectory)) {
        $ReceiptDirectory = Join-Path $repository "bin\windows-native-bootstrap"
    }
    New-Item -ItemType Directory -Force -Path $ReceiptDirectory | Out-Null
    $receiptDirectoryItem = Get-Item -LiteralPath $ReceiptDirectory -Force
    if (-not $receiptDirectoryItem.PSIsContainer -or (($receiptDirectoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Receipt directory must be a real directory, not a reparse point."
    }
    $sourceFiles = @(
        "scripts\windows-bootstrap-verifier-smoke.ps1",
        "internal\bootstrapanchor\anchor.go",
        "internal\bootstraphandoff\handoff.go",
        "internal\bootstrapverify\files.go",
        "internal\bootstrapverify\files_other.go",
        "internal\bootstrapverify\authenticode.go",
        "internal\bootstrapverify\authenticode_windows.go",
        "internal\bootstrapverify\verify.go",
        "internal\installerinspect\inspect_pe.go",
        "internal\installerinspect\inspect_verifier.go",
        "internal\verifierbundle\model.go"
    )
    $sourceSHA256 = [ordered]@{}
    foreach ($relative in ($sourceFiles | Sort-Object -CaseSensitive -Unique)) {
        $sourceSHA256[$relative.Replace('\', '/')] = Get-LowerSHA256 (Join-Path $repository $relative)
    }
    $receipt = [ordered]@{
        schema = "mesh-windows-native-bootstrap-receipt-v2"
        architecture = $architecture
        verified_at = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        verifier_package_sha256 = $packageSHA256
        verifier_sha256 = $verifierSHA256
        anchor_sha256 = $anchorSHA256
        handoff_sha256 = $handoffSHA256
        root_sha256 = $rootSHA256
        installer_sha256 = $installerSHA256
        verification = $verification
        proofs = @(
            "independently supplied exact verifier-package digest",
            "canonical two-member Windows verifier USTAR",
            "private LocalSystem and Administrators extraction DACL",
            "native Windows verifier execution",
            "v2 handoff and v2 anchor exact host selection",
            "root-role threshold authorization without installer execution",
            "online whole-chain Authenticode verification with exact policy, signer SPKI, and certificate binding"
        )
        source_sha256 = $sourceSHA256
    }
    $receiptJSON = ($receipt | ConvertTo-Json -Depth 8 -Compress) + "`n"
    $receiptPath = Join-Path $receiptDirectoryItem.FullName ((Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ") + "-receipt.json")
    $receiptBytes = [Text.UTF8Encoding]::new($false).GetBytes($receiptJSON)
    $receiptStream = [IO.File]::Open($receiptPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $receiptStream.Write($receiptBytes, 0, $receiptBytes.Length)
        $receiptStream.Flush($true)
    }
    finally {
        $receiptStream.Dispose()
    }
    Write-Output $receiptPath
}
finally {
    if ((Split-Path -Parent $proofRoot) -ceq $proofParent -and $proofLeaf -cmatch '^mesh-windows-bootstrap-native-[0-9a-f]{32}$' -and (Test-Path -LiteralPath $proofRoot)) {
        $cleanupItem = Get-Item -LiteralPath $proofRoot -Force
        if (($cleanupItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
            Remove-Item -LiteralPath $proofRoot -Recurse -Force
        }
    }
}
