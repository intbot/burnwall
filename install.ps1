# Burnwall installer for Windows.
#
# Usage:
#   irm https://raw.githubusercontent.com/intbot/burnwall/main/install.ps1 | iex
#
# Environment variables:
#   $env:BURNWALL_VERSION       Specific version (e.g. "0.3.1"). Defaults to latest.
#   $env:BURNWALL_INSTALL_DIR   Where to place the binary. Defaults to $HOME\.burnwall\bin.

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'

$repo = 'intbot/burnwall'
$installDir = if ($env:BURNWALL_INSTALL_DIR) {
    $env:BURNWALL_INSTALL_DIR
} else {
    Join-Path $HOME '.burnwall\bin'
}
$version = if ($env:BURNWALL_VERSION) { $env:BURNWALL_VERSION } else { 'latest' }

function Info($msg)  { Write-Host "burnwall: $msg" }
function Die($msg)   { Write-Host "burnwall installer error: $msg" -ForegroundColor Red; exit 1 }

# Detect architecture. PROCESSOR_ARCHITEW6432 wins if present (covers 32-bit shells on 64-bit hosts).
$arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
switch ($arch) {
    'AMD64' { $target = 'x86_64-pc-windows-msvc' }
    'ARM64' { Die "Windows ARM64 binaries are not yet published. Use 'cargo install burnwall' or build from source." }
    default { Die "unsupported architecture: $arch" }
}

# Resolve version → tag
if ($version -eq 'latest') {
    Info 'resolving latest release...'
    try {
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -UseBasicParsing
        $tag = $rel.tag_name
    } catch {
        Die "could not resolve latest release tag: $_"
    }
} else {
    # Accept "0.3.1" or "v0.3.1"
    $tag = if ($version.StartsWith('v')) { $version } else { "v$version" }
}

$url      = "https://github.com/$repo/releases/download/$tag/burnwall-$target.zip"
$tmpDir   = Join-Path $env:TEMP "burnwall-install-$(Get-Random)"
$tmpZip   = Join-Path $tmpDir 'burnwall.zip'
$tmpExtr  = Join-Path $tmpDir 'extract'

try {
    New-Item -ItemType Directory -Force -Path $tmpDir  | Out-Null
    New-Item -ItemType Directory -Force -Path $tmpExtr | Out-Null

    Info "downloading $tag for $target..."
    try {
        Invoke-WebRequest -Uri $url -OutFile $tmpZip -UseBasicParsing
    } catch {
        Die "download failed. URL: $url"
    }

    Info 'extracting...'
    Expand-Archive -Path $tmpZip -DestinationPath $tmpExtr -Force

    $exe = Get-ChildItem -Path $tmpExtr -Filter 'burnwall.exe' -Recurse | Select-Object -First 1
    if (-not $exe) {
        Die 'archive did not contain burnwall.exe'
    }

    # Install. Stop a running burnwall.exe first so the copy doesn't fail.
    if (-not (Test-Path $installDir)) {
        New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    }
    $dest = Join-Path $installDir 'burnwall.exe'
    if (Test-Path $dest) {
        # If a previous burnwall is currently running, ask it to stop.
        try { & $dest stop 2>$null | Out-Null } catch {}
    }
    Copy-Item -Path $exe.FullName -Destination $dest -Force

    Info ''
    Info "installed $tag to $dest"
    try { & $dest --version } catch {}

    # Persist to User PATH if not already there
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $alreadyOnPath = $false
    if ($userPath) {
        $alreadyOnPath = ($userPath -split ';' | Where-Object { $_ -eq $installDir }).Count -gt 0
    }
    if (-not $alreadyOnPath) {
        $newPath = if ($userPath) { "$userPath;$installDir" } else { $installDir }
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        # Also patch the current session so the next command works without reopening.
        $env:Path = "$env:Path;$installDir"
        Info ''
        Info "added $installDir to your User PATH (persisted)."
        Info 'open a new terminal so other shells pick up the change.'
    }

    Info ''
    Info 'next steps:'
    Info '  burnwall init --apply    # detect AI tools and configure env vars'
    Info '  burnwall start           # run the proxy'
} finally {
    if (Test-Path $tmpDir) {
        Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
