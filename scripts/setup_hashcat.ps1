<#
.SYNOPSIS
  Copy a local hashcat distribution into the ignored runtime/ directory.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts/setup_hashcat.ps1 `
    -Source "D:\tools\hashcat-8.0.0"

.NOTES
  The hashcat binaries are not committed to Git.  Download hashcat from
  https://hashcat.net/hashcat/ and point -Source at the extracted folder.
#>
param(
    [string]$Source = $env:HASHCAT_SOURCE,
    [string]$Destination = (Join-Path $PSScriptRoot "..\runtime\hashcat")
)

$ErrorActionPreference = "Stop"

if (-not $Source) {
    throw "Provide -Source <hashcat folder> or set HASHCAT_SOURCE."
}

$sourcePath = (Resolve-Path -LiteralPath $Source).Path
$exe = Join-Path $sourcePath "hashcat.exe"
if (-not (Test-Path -LiteralPath $exe)) {
    throw "hashcat.exe not found in $sourcePath"
}

$destinationPath = [System.IO.Path]::GetFullPath($Destination)
New-Item -ItemType Directory -Force -Path $destinationPath | Out-Null

Write-Host "Copying hashcat from:"
Write-Host "  $sourcePath"
Write-Host "to:"
Write-Host "  $destinationPath"

Copy-Item -Path (Join-Path $sourcePath "*") -Destination $destinationPath -Recurse -Force

$version = & (Join-Path $destinationPath "hashcat.exe") --version
Write-Host "Installed hashcat: $version"
