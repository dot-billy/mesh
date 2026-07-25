[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BundlePath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9.-]{3,50}$')]
    [string]$IdentityName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Publisher,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PublisherDisplayName,

    [ValidateSet('x64', 'arm64')]
    [string]$Architecture = 'x64'
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $PSCommandPath
$repoRoot = (Resolve-Path (Join-Path $scriptRoot '..\..\..')).Path
$resolvedBundle = (Resolve-Path $BundlePath).Path
foreach ($relativePath in @(
    'mesh_desktop.exe',
    'flutter_windows.dll',
    'data\app.so',
    'data\flutter_assets\NOTICES.Z'
)) {
    if (-not (Test-Path -LiteralPath (Join-Path $resolvedBundle $relativePath) -PathType Leaf)) {
        throw "Invalid Mesh desktop Windows bundle: missing $relativePath"
    }
}

function Get-MeshPeMachine {
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
        throw "Invalid PE file: $Path"
    }
    $headerOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    if ($headerOffset -lt 0 -or $headerOffset + 6 -gt $bytes.Length -or
        $bytes[$headerOffset] -ne 0x50 -or $bytes[$headerOffset + 1] -ne 0x45 -or
        $bytes[$headerOffset + 2] -ne 0 -or $bytes[$headerOffset + 3] -ne 0) {
        throw "Invalid PE header: $Path"
    }
    return [BitConverter]::ToUInt16($bytes, $headerOffset + 4)
}

$expectedPeMachine = if ($Architecture -eq 'x64') { 0x8664 } else { 0xaa64 }
foreach ($relativePath in @('mesh_desktop.exe', 'flutter_windows.dll')) {
    $machine = Get-MeshPeMachine -Path (Join-Path $resolvedBundle $relativePath)
    if ($machine -ne $expectedPeMachine) {
        throw "Windows bundle architecture mismatch for ${relativePath}: 0x$($machine.ToString('x4'))"
    }
}

$versionLine = Select-String -Path (Join-Path $repoRoot 'desktop\pubspec.yaml') -Pattern '^version:\s*([0-9]+)\.([0-9]+)\.([0-9]+)' | Select-Object -First 1
if ($null -eq $versionLine) {
    throw 'Unable to read the desktop version from pubspec.yaml'
}
$versionParts = @(
    [int]$versionLine.Matches[0].Groups[1].Value,
    [int]$versionLine.Matches[0].Groups[2].Value,
    [int]$versionLine.Matches[0].Groups[3].Value
)
if ($versionParts.Where({ $_ -gt 65535 }).Count -ne 0) {
    throw 'Desktop version components exceed the MSIX 16-bit limit'
}
$version = '{0}.{1}.{2}.0' -f $versionLine.Matches[0].Groups[1].Value, $versionLine.Matches[0].Groups[2].Value, $versionLine.Matches[0].Groups[3].Value

$makeAppx = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\makeappx.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending |
    Select-Object -First 1
if ($null -eq $makeAppx) {
    throw 'MakeAppx.exe was not found in the installed Windows SDK'
}

$tempRoot = if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    [System.IO.Path]::GetTempPath()
}
else {
    $env:RUNNER_TEMP
}
$tempRoot = [System.IO.Path]::GetFullPath($tempRoot)
$stagePrefix = Join-Path $tempRoot 'mesh-msix-'
$validationPrefix = Join-Path $tempRoot 'mesh-msix-validation-'
$stage = $stagePrefix + [guid]::NewGuid().ToString('N')
$validation = $validationPrefix + [guid]::NewGuid().ToString('N')
$outputDir = Join-Path $repoRoot 'artifacts\desktop'
$output = Join-Path $outputDir "mesh-desktop_${version}_${Architecture}.msix"

function New-MeshLogo {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$Width,
        [Parameter(Mandatory = $true)][int]$Height
    )

    Add-Type -AssemblyName System.Drawing
    $bitmap = [System.Drawing.Bitmap]::new($Width, $Height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $graphics.Clear([System.Drawing.Color]::FromArgb(16, 19, 24))
        $accent = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(163, 237, 99), [Math]::Max(2, [int]($Width / 18)))
        $node = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(163, 237, 99))
        try {
            $left = [System.Drawing.Point]::new([int]($Width * 0.24), [int]($Height * 0.28))
            $right = [System.Drawing.Point]::new([int]($Width * 0.76), [int]($Height * 0.28))
            $center = [System.Drawing.Point]::new([int]($Width * 0.50), [int]($Height * 0.50))
            $bottom = [System.Drawing.Point]::new([int]($Width * 0.50), [int]($Height * 0.78))
            $graphics.DrawLine($accent, $left, $center)
            $graphics.DrawLine($accent, $right, $center)
            $graphics.DrawLine($accent, $center, $bottom)
            $radius = [Math]::Max(3, [int]($Width * 0.075))
            foreach ($point in @($left, $right, $center, $bottom)) {
                $graphics.FillEllipse($node, $point.X - $radius, $point.Y - $radius, $radius * 2, $radius * 2)
            }
        }
        finally {
            $accent.Dispose()
            $node.Dispose()
        }
        $bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    }
    finally {
        $graphics.Dispose()
        $bitmap.Dispose()
    }
}

try {
    New-Item -ItemType Directory -Path $stage, (Join-Path $stage 'Assets'), $outputDir -Force | Out-Null
    Copy-Item -Path (Join-Path $resolvedBundle '*') -Destination $stage -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $repoRoot 'LICENSE') -Destination (Join-Path $stage 'LICENSE') -Force
    Copy-Item -LiteralPath (Join-Path $repoRoot 'THIRD_PARTY_NOTICES.md') -Destination (Join-Path $stage 'THIRD_PARTY_NOTICES.md') -Force

    New-MeshLogo -Path (Join-Path $stage 'Assets\Square44x44Logo.png') -Width 44 -Height 44
    New-MeshLogo -Path (Join-Path $stage 'Assets\Square150x150Logo.png') -Width 150 -Height 150
    New-MeshLogo -Path (Join-Path $stage 'Assets\StoreLogo.png') -Width 50 -Height 50

    $manifest = Get-Content -Raw (Join-Path $scriptRoot 'AppxManifest.xml.in')
    $manifest = $manifest.Replace('@IDENTITY@', [Security.SecurityElement]::Escape($IdentityName))
    $manifest = $manifest.Replace('@PUBLISHER@', [Security.SecurityElement]::Escape($Publisher))
    $manifest = $manifest.Replace('@PUBLISHER_DISPLAY_NAME@', [Security.SecurityElement]::Escape($PublisherDisplayName))
    $manifest = $manifest.Replace('@VERSION@', $version)
    $manifest = $manifest.Replace('@ARCH@', $Architecture)
    Set-Content -Path (Join-Path $stage 'AppxManifest.xml') -Value $manifest -Encoding utf8NoBOM

    & $makeAppx.FullName pack /d $stage /p $output /o
    if ($LASTEXITCODE -ne 0) {
        throw "MakeAppx failed with exit code $LASTEXITCODE"
    }

    & $makeAppx.FullName unpack /p $output /d $validation /o
    if ($LASTEXITCODE -ne 0) {
        throw "MakeAppx validation unpack failed with exit code $LASTEXITCODE"
    }
    foreach ($relativePath in @(
        'mesh_desktop.exe',
        'flutter_windows.dll',
        'data\app.so',
        'data\flutter_assets\NOTICES.Z',
        'LICENSE',
        'THIRD_PARTY_NOTICES.md',
        'AppxManifest.xml'
    )) {
        if (-not (Test-Path -LiteralPath (Join-Path $validation $relativePath) -PathType Leaf)) {
            throw "MSIX payload validation failed: missing $relativePath"
        }
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($output)
    try {
        if ($archive.Entries.FullName -contains 'AppxSignature.p7x') {
            throw 'CI packaging must remain unsigned; the MSIX contains a signature'
        }
    }
    finally {
        $archive.Dispose()
    }

    [xml]$packagedManifest = Get-Content -Raw (Join-Path $validation 'AppxManifest.xml')
    $namespace = [System.Xml.XmlNamespaceManager]::new($packagedManifest.NameTable)
    $namespace.AddNamespace('pkg', 'http://schemas.microsoft.com/appx/manifest/foundation/windows10')
    $identity = $packagedManifest.SelectSingleNode('/pkg:Package/pkg:Identity', $namespace)
    if ($null -eq $identity -or
        $identity.GetAttribute('Name') -ne $IdentityName -or
        $identity.GetAttribute('Publisher') -ne $Publisher -or
        $identity.GetAttribute('Version') -ne $version -or
        $identity.GetAttribute('ProcessorArchitecture') -ne $Architecture) {
        throw 'MSIX identity validation failed'
    }

    $hash = (Get-FileHash -Algorithm SHA256 $output).Hash.ToLowerInvariant()
    $hashLine = "$hash  $([System.IO.Path]::GetFileName($output))"
    Set-Content -Path "$output.sha256" -Value $hashLine -Encoding ascii
    Write-Host "Built validated unsigned package $output"
    Write-Host 'Sign the MSIX in a protected release job before distribution.'
}
finally {
    if ($stage.StartsWith($stagePrefix, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path $stage)) {
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
    if ($validation.StartsWith($validationPrefix, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path $validation)) {
        Remove-Item -LiteralPath $validation -Recurse -Force
    }
}
