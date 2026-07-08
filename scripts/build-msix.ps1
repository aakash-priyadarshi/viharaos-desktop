param(
  [Parameter(Mandatory = $true)]
  [string]$Version,

  [string]$TargetTriple = "x86_64-pc-windows-msvc",
  [string]$Architecture = "x64",
  [string]$PackageName = "OrivraaLTD.ViharaOS",
  [string]$Publisher = "CN=B2A437AC-7FFC-46EE-8124-FF5F92077F5E",
  [string]$PublisherDisplayName = "Orivraa LTD",
  [string]$ProductName = "ViharaOS",
  [string]$ApplicationId = "viharaOS"
)

$ErrorActionPreference = "Stop"

function Convert-ToMsixVersion {
  param([string]$InputVersion)

  $parts = $InputVersion.Split(".")
  if ($parts.Count -eq 3) {
    $parts += "0"
  }

  if ($parts.Count -ne 4) {
    throw "MSIX version '$InputVersion' must have three or four numeric parts."
  }

  foreach ($part in $parts) {
    if ($part -notmatch "^\d+$") {
      throw "MSIX version '$InputVersion' must contain only numeric parts."
    }
  }

  return ($parts -join ".")
}

function Resolve-TauriExecutable {
  param([string]$ReleaseDir)

  $preferred = @(
    (Join-Path $ReleaseDir "ViharaOS.exe"),
    (Join-Path $ReleaseDir "viharaos-desktop.exe")
  )

  foreach ($path in $preferred) {
    if (Test-Path $path) {
      return (Resolve-Path $path).Path
    }
  }

  $candidate = Get-ChildItem $ReleaseDir -Filter "*.exe" -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch "(?i)(setup|installer|uninst)" } |
    Sort-Object Length -Descending |
    Select-Object -First 1

  if (-not $candidate) {
    throw "Could not find a built Tauri executable in $ReleaseDir."
  }

  return $candidate.FullName
}

function Copy-Asset {
  param(
    [string]$IconsDir,
    [string]$DestinationDir,
    [string]$SourceName,
    [string]$DestinationName,
    [string]$FallbackName = "icon.png"
  )

  $source = Join-Path $IconsDir $SourceName
  if (-not (Test-Path $source)) {
    $source = Join-Path $IconsDir $FallbackName
  }
  if (-not (Test-Path $source)) {
    throw "Could not find asset '$SourceName' or fallback '$FallbackName' in $IconsDir."
  }

  Copy-Item -LiteralPath $source -Destination (Join-Path $DestinationDir $DestinationName) -Force
}

function Get-SigningCertificate {
  param(
    [string]$ManifestPath,
    [string]$OutputDir
  )

  $certPassword = if ($env:WINDOWS_CERTIFICATE_PASSWORD) { $env:WINDOWS_CERTIFICATE_PASSWORD } else { "password" }
  $certPath = Join-Path $OutputDir "ViharaOS_msix_signing.pfx"

  if ($env:WINDOWS_CERTIFICATE) {
    $encodedPath = Join-Path $OutputDir "windows-certificate.txt"
    Set-Content -LiteralPath $encodedPath -Value $env:WINDOWS_CERTIFICATE
    certutil -decode $encodedPath $certPath | Out-Null
    Remove-Item -LiteralPath $encodedPath -Force
  } else {
    winapp cert generate `
      --manifest $ManifestPath `
      --output $certPath `
      --password $certPassword `
      --valid-days 365 `
      --if-exists Overwrite `
      --export-cer
  }

  if (-not (Test-Path $certPath)) {
    throw "MSIX signing certificate was not created at $certPath."
  }

  return @{
    Path = $certPath
    Password = $certPassword
  }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$srcTauriDir = Join-Path $repoRoot "src-tauri"
$releaseDir = Join-Path $srcTauriDir "target\$TargetTriple\release"
$iconsDir = Join-Path $srcTauriDir "icons"
$msixVersion = Convert-ToMsixVersion $Version
$stageRoot = Join-Path $srcTauriDir "target\msix-stage"
$stageDir = Join-Path $stageRoot "$ProductName-$msixVersion-$Architecture"
$bundleDir = Join-Path $releaseDir "bundle\msix"
$outputPath = Join-Path $bundleDir "${ProductName}_${msixVersion}_${Architecture}.msix"

if (-not (Test-Path $releaseDir)) {
  throw "Tauri release directory does not exist: $releaseDir"
}

New-Item -ItemType Directory -Path $bundleDir -Force | Out-Null
New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null
if (Test-Path $stageDir) {
  Remove-Item -LiteralPath $stageDir -Recurse -Force
}
New-Item -ItemType Directory -Path $stageDir -Force | Out-Null

$assetsDir = Join-Path $stageDir "Assets"
New-Item -ItemType Directory -Path $assetsDir -Force | Out-Null

$builtExe = Resolve-TauriExecutable -ReleaseDir $releaseDir
Copy-Item -LiteralPath $builtExe -Destination (Join-Path $stageDir "$ProductName.exe") -Force

Copy-Asset -IconsDir $iconsDir -DestinationDir $assetsDir -SourceName "StoreLogo.png" -DestinationName "StoreLogo.png"
Copy-Asset -IconsDir $iconsDir -DestinationDir $assetsDir -SourceName "Square150x150Logo.png" -DestinationName "MedTile.png"
Copy-Asset -IconsDir $iconsDir -DestinationDir $assetsDir -SourceName "Square44x44Logo.png" -DestinationName "AppList.png"

$manifest = @"
<?xml version="1.0" encoding="utf-8"?>
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
  xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
  IgnorableNamespaces="uap rescap">
  <Identity
    Name="$PackageName"
    Publisher="$Publisher"
    Version="$msixVersion"
    ProcessorArchitecture="$Architecture" />
  <Properties>
    <DisplayName>$ProductName</DisplayName>
    <PublisherDisplayName>$PublisherDisplayName</PublisherDisplayName>
    <Logo>Assets\StoreLogo.png</Logo>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.18362.0" MaxVersionTested="10.0.26200.0" />
  </Dependencies>
  <Resources>
    <Resource Language="en-us" />
  </Resources>
  <Applications>
    <Application Id="$ApplicationId" Executable="`$targetnametoken`$.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements
        DisplayName="$ProductName"
        Description="ViharaOS - Hotel Management System for the Indian Buddhist Circuit"
        BackgroundColor="transparent"
        Square150x150Logo="Assets\MedTile.png"
        Square44x44Logo="Assets\AppList.png" />
    </Application>
  </Applications>
  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
  </Capabilities>
</Package>
"@

$manifestPath = Join-Path $stageDir "Package.appxmanifest"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($manifestPath, $manifest, $utf8NoBom)

$cert = Get-SigningCertificate -ManifestPath $manifestPath -OutputDir $bundleDir

if (Test-Path $outputPath) {
  Remove-Item -LiteralPath $outputPath -Force
}

winapp pack $stageDir `
  --manifest $manifestPath `
  --executable "$ProductName.exe" `
  --output $outputPath `
  --cert $cert.Path `
  --cert-password $cert.Password

if (-not (Test-Path $outputPath)) {
  throw "MSIX package was not created at $outputPath."
}

Get-ChildItem $bundleDir -Filter "*.pfx" -File -ErrorAction SilentlyContinue | Remove-Item -Force

Write-Host "MSIX package: $outputPath"

if ($env:GITHUB_OUTPUT) {
  "msix=$outputPath" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
}
