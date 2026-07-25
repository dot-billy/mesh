param(
    [string]$ReceiptDirectory = "",
    [string]$BundlePath = "",
    [string]$UpgradeBundlePath = "",
    [Parameter(Mandatory = $true)]
    [string]$NativeDNSLocalIP,
    [Parameter(Mandatory = $true)]
    [string]$AuthenticodePolicyFrame
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($env:MESH_WINDOWS_NATIVE_FAULT_TEST -ne "1") {
    throw "Set MESH_WINDOWS_NATIVE_FAULT_TEST=1 explicitly on an isolated Windows test host."
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "The native Windows lifecycle smoke requires an elevated Administrator shell."
}

$repository = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repository
$architecture = switch ($env:PROCESSOR_ARCHITECTURE.ToUpperInvariant()) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    default { throw "Unsupported Windows architecture $($env:PROCESSOR_ARCHITECTURE)." }
}

if ([string]::IsNullOrWhiteSpace($BundlePath)) {
    $BundlePath = $env:MESH_WINDOWS_NATIVE_BUNDLE
}
if ([string]::IsNullOrWhiteSpace($BundlePath)) {
    throw "Pass -BundlePath or set MESH_WINDOWS_NATIVE_BUNDLE to one canonical final signed Windows bundle."
}
$env:MESH_WINDOWS_NATIVE_BUNDLE = (Resolve-Path $BundlePath).Path
if ([string]::IsNullOrWhiteSpace($UpgradeBundlePath)) {
    $UpgradeBundlePath = $env:MESH_WINDOWS_NATIVE_UPGRADE_BUNDLE
}
if ([string]::IsNullOrWhiteSpace($UpgradeBundlePath)) {
    throw "Pass -UpgradeBundlePath or set MESH_WINDOWS_NATIVE_UPGRADE_BUNDLE to a distinct final signed Windows upgrade bundle."
}
$env:MESH_WINDOWS_NATIVE_UPGRADE_BUNDLE = (Resolve-Path $UpgradeBundlePath).Path
$initialBundleSHA256 = (Get-FileHash -Algorithm SHA256 -Path $env:MESH_WINDOWS_NATIVE_BUNDLE).Hash.ToLowerInvariant()
$upgradeBundleSHA256 = (Get-FileHash -Algorithm SHA256 -Path $env:MESH_WINDOWS_NATIVE_UPGRADE_BUNDLE).Hash.ToLowerInvariant()
if ($env:MESH_WINDOWS_NATIVE_UPGRADE_BUNDLE -ceq $env:MESH_WINDOWS_NATIVE_BUNDLE -or $upgradeBundleSHA256 -ceq $initialBundleSHA256) {
    throw "BundlePath and UpgradeBundlePath must identify distinct final signed artifacts."
}
$parsedNativeDNSIP = [Net.IPAddress]::None
if (-not [Net.IPAddress]::TryParse($NativeDNSLocalIP, [ref]$parsedNativeDNSIP) -or $parsedNativeDNSIP.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $parsedNativeDNSIP.ToString() -cne $NativeDNSLocalIP) {
    throw "NativeDNSLocalIP must be one canonical IPv4 address assigned to this Windows host."
}
if ($AuthenticodePolicyFrame.Length -lt 1 -or $AuthenticodePolicyFrame.Length -gt 16384 -or
    -not $AuthenticodePolicyFrame.StartsWith("MESH_WINDOWS_AUTHENTICODE_V1.") -or
    -not $AuthenticodePolicyFrame.EndsWith(".END_MESH_WINDOWS_AUTHENTICODE_V1") -or
    $AuthenticodePolicyFrame -cmatch '\s') {
    throw "AuthenticodePolicyFrame must be one canonical whitespace-free v1 policy frame."
}
$env:MESH_WINDOWS_NATIVE_DNS_TEST = "1"
$env:MESH_WINDOWS_NATIVE_DNS_LOCAL_IP = $NativeDNSLocalIP

$goVersion = (& go version).Trim()
$architecture = $env:PROCESSOR_ARCHITECTURE
$started = [DateTimeOffset]::UtcNow

& go test -buildvcs=false -count=1 "-ldflags=-X mesh/internal/windowsauthenticode.Identity=$AuthenticodePolicyFrame" -run '^(TestWindowsContainedChildNative|TestWindowsInstallerLifecycleNative|TestWindowsNativeDNSNRPTLifecycle)$' ./cmd/meshctl ./internal/windowsinstall ./internal/nodeagent
if ($LASTEXITCODE -ne 0) {
    throw "Native Windows contained-child, install, upgrade, rollback, uninstall, or resolver proof failed."
}

if ([string]::IsNullOrWhiteSpace($ReceiptDirectory)) {
    $ReceiptDirectory = Join-Path $repository "bin\windows-native-runtime"
}
New-Item -ItemType Directory -Force -Path $ReceiptDirectory | Out-Null
$receiptDirectoryItem = Get-Item -LiteralPath $ReceiptDirectory -Force
if (-not $receiptDirectoryItem.PSIsContainer -or (($receiptDirectoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw "Receipt directory must be a real directory, not a reparse point."
}
$receiptPath = Join-Path $ReceiptDirectory ((Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ") + "-receipt.json")

$testFiles = @(
    "scripts\windows-native-runtime-smoke.ps1",
    "cmd\meshctl\agent_supervised_runtime_windows.go",
    "cmd\meshctl\agent_supervised_runtime_windows_test.go",
    "cmd\meshctl\agent_entry_windows.go",
    "internal\windowsinstall\activation_windows.go",
    "internal\windowsinstall\activation_authority_windows.go",
    "internal\windowsinstall\activation_journal_core.go",
    "internal\windowsinstall\activation_journal_windows.go",
    "internal\windowsinstall\accepted_stage_windows.go",
    "internal\windowsinstall\artifact_capture_windows.go",
    "internal\windowsinstall\authority_core.go",
    "internal\windowsinstall\candidate_intake_production_windows.go",
    "internal\windowsinstall\candidate_intake_windows.go",
    "internal\windowsinstall\install_state_core.go",
    "internal\windowsinstall\install_state_codec.go",
    "internal\windowsinstall\install_state_store_windows.go",
	"internal\windowsinstall\current_core.go",
	"internal\windowsinstall\current_switch_core.go",
	"internal\windowsinstall\layout_windows.go",
    "internal\windowsinstall\intake_record_core.go",
    "internal\windowsinstall\intake_record_store_windows.go",
    "internal\windowsinstall\installer_lock_windows.go",
    "internal\windowsinstall\installer_windows.go",
    "internal\windowsinstall\offline_snapshot_core.go",
    "internal\windowsinstall\offline_snapshot_prepare_windows.go",
    "internal\windowsinstall\offline_snapshot_windows.go",
    "internal\windowsinstall\publication_core.go",
    "internal\windowsinstall\publication_windows.go",
    "internal\windowsinstall\root_history_core.go",
    "internal\windowsinstall\root_history_store_windows.go",
	"internal\windowsinstall\service_core.go",
	"internal\windowsinstall\service_windows.go",
	"internal\windowsinstall\runtime_uninstall_codec.go",
	"internal\windowsinstall\runtime_uninstall_core.go",
	"internal\windowsinstall\runtime_uninstall_journal_windows.go",
	"internal\windowsinstall\runtime_uninstall_windows.go",
    "internal\windowsinstall\windows_native_test.go",
    "internal\windowsinstallercompat\compat.go",
    "internal\windowsbundle\candidate.go",
	"internal\windowsbundle\model.go",
	"internal\windowsbundle\policy.go",
	"internal\windowsbundle\signed_build.go",
	"internal\windowsauthenticode\pe.go",
	"internal\windowsauthenticode\policy.go",
	"internal\windowsauthenticode\receipt.go",
	"internal\windowsauthenticode\verify_windows.go",
    "internal\nodeagent\native_dns.go",
    "internal\nodeagent\native_dns_nrpt.go",
    "internal\nodeagent\native_dns_proxy.go",
    "internal\nodeagent\native_dns_windows.go",
    "internal\nodeagent\native_dns_windows_test.go",
    "internal\control\dns.go",
    "internal\windowssecurity\descriptor.go",
    "internal\windowssecurity\inspect_windows.go"
)
$hashes = [ordered]@{}
foreach ($relative in ($testFiles | Sort-Object -CaseSensitive -Unique)) {
    $path = Join-Path $repository $relative
    $hashes[$relative.Replace('\', '/')] = (Get-FileHash -Algorithm SHA256 -Path $path).Hash.ToLowerInvariant()
}

$authenticodePrefix = "MESH_WINDOWS_AUTHENTICODE_V1."
$authenticodeSuffix = ".END_MESH_WINDOWS_AUTHENTICODE_V1"
$authenticodeEncoded = $AuthenticodePolicyFrame.Substring(
    $authenticodePrefix.Length,
    $AuthenticodePolicyFrame.Length - $authenticodePrefix.Length - $authenticodeSuffix.Length
).Replace('-', '+').Replace('_', '/')
switch ($authenticodeEncoded.Length % 4) {
    0 { }
    2 { $authenticodeEncoded += "==" }
    3 { $authenticodeEncoded += "=" }
    default { throw "AuthenticodePolicyFrame contains invalid base64url." }
}
$authenticodePolicyJSON = [Convert]::FromBase64String($authenticodeEncoded)
$authenticodePolicyHasher = [Security.Cryptography.SHA256]::Create()
try {
    $authenticodePolicySHA256 = ([BitConverter]::ToString($authenticodePolicyHasher.ComputeHash($authenticodePolicyJSON))).Replace("-", "").ToLowerInvariant()
}
finally {
    $authenticodePolicyHasher.Dispose()
}
$receipt = [ordered]@{
    schema = "mesh-windows-native-runtime-receipt-v4"
    architecture = $architecture
    go_version = $goVersion
    native_fault_gate = $env:MESH_WINDOWS_NATIVE_FAULT_TEST
    bundle_path = $env:MESH_WINDOWS_NATIVE_BUNDLE
    bundle_sha256 = $initialBundleSHA256
    upgrade_bundle_path = $env:MESH_WINDOWS_NATIVE_UPGRADE_BUNDLE
    upgrade_bundle_sha256 = $upgradeBundleSHA256
    authenticode_policy_sha256 = $authenticodePolicySHA256
    native_dns_local_ip = $NativeDNSLocalIP
    started_at = $started.ToString("yyyy-MM-ddTHH:mm:ssZ")
    verified_at = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    proofs = @(
        "suspended process creation",
        "kill-on-close non-breakaway job policy",
        "exact process image and argument identity",
        "whole-job termination and idempotent wait",
        "component-by-component reparse rejection",
        "DACL drift rejection and exact repair",
        "ephemeral 2-of-2 release threshold acceptance",
        "exact signed online-bundle intake persistence",
        "exact LocalSystem-private offline snapshot intake",
        "operator-path exact private offline snapshot preparation",
        "append-only root-history replay and durable high-water authority",
        "cross-process installer transaction locking",
        "bounded signed artifact capture, recovery, and terminal discard",
        "deterministic accepted-stage restart recovery",
        "single-link candidate intake and published-tree enforcement",
        "canonical bundle expansion and write-through no-replace publication",
        "finalized-stage recovery before publication",
        "journaled current-selector and SCM service lifecycle",
		"authority-bound active-state and intake finalization replay",
		"distinct signed-v3 sequence-2 upgrade with exact persisted-previous selection",
		"native rollback to the exact prior release with upgrade authority retained as high water",
		"recovery-safe runtime uninstall with retained release and anti-rollback authority",
        "role-pinned online-revocation Authenticode enforcement for every activated PE",
        "native Windows NRPT split-DNS activation, packet resolution, effective-policy readback, and exact cleanup"
    )
    source_sha256 = $hashes
}
$receiptJSON = ($receipt | ConvertTo-Json -Depth 5 -Compress) + "`n"
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
