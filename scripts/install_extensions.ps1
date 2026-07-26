param(
    [string]$DataRoot = $env:WEB_VULN_MINING_DATA,
    [string]$OnlyTools = ''
)
# ============================ Configuration zone ============================
# DataRoot: user-owned root containing the portable bin and archive cache.
# The versions and SHA-256 values are mirrored in config/tool-lock.windows.json.
# OnlyTools: comma-separated repair subset; empty installs all three extensions.
$ErrorActionPreference = 'Stop'
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($DataRoot)) { $DataRoot = Join-Path $env:LOCALAPPDATA 'web-vuln-mining' }
$BinDirectory = Join-Path $DataRoot 'bin'
$CacheDirectory = Join-Path $DataRoot 'cache'
$Dalfox = @{ Name='dalfox'; Archive='dalfox-v3.1.2-windows-x86_64.zip'; Url='https://github.com/hahwul/dalfox/releases/download/v3.1.2/dalfox-v3.1.2-windows-x86_64.zip'; Sha256='9aac0bb85fec8710ba23f1df96de34217931dee81693503ebcf61150c4368300'; Binary='dalfox.exe'; Destination='dalfox.exe' }
$Ffuf = @{ Name='ffuf'; Archive='ffuf_2.2.1_windows_amd64.zip'; Url='https://github.com/ffuf/ffuf/releases/download/v2.2.1/ffuf_2.2.1_windows_amd64.zip'; Sha256='717e3d103ee36ce743a18605be66a4424fca27758eebed1e8ebb2eb0a3645589'; Binary='ffuf.exe'; Destination='ffuf.exe' }
$Sqlmap = @{ Name='sqlmap'; Archive='sqlmap-1.10.zip'; Url='https://codeload.github.com/sqlmapproject/sqlmap/zip/refs/tags/1.10'; Sha256='97b8fe8e06ed8b6c75c234f111393bae79e2c3d3283c086351354716277dfff1' }
$RequestedTools = @($OnlyTools.Split(',', [StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() })
# ============================================================================

function Get-VerifiedDownload([hashtable]$Release) {
    $target = Join-Path $CacheDirectory $Release.Archive
    New-Item -ItemType Directory -Force -Path $CacheDirectory | Out-Null
    if (-not (Test-Path -LiteralPath $target) -or ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Release.Sha256)) {
        Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue
        Invoke-WebRequest -Uri $Release.Url -OutFile $target
    }
    $actual = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Release.Sha256) { throw "SHA-256 mismatch for $($Release.Name): $actual" }
    return $target
}
function Install-ArchiveTool([hashtable]$Release) {
    $archive = Get-VerifiedDownload $Release
    $extract = Join-Path $CacheDirectory "extract-$($Release.Name)"
    Remove-Item -LiteralPath $extract -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive -LiteralPath $archive -DestinationPath $extract -Force
    $binary = Get-ChildItem -LiteralPath $extract -Recurse -File -Filter $Release.Binary | Select-Object -First 1
    if (-not $binary) { throw "$($Release.Binary) was not found in $($Release.Archive)" }
    New-Item -ItemType Directory -Force -Path $BinDirectory | Out-Null
    Copy-Item -LiteralPath $binary.FullName -Destination (Join-Path $BinDirectory $Release.Destination) -Force
}
function Test-Selected([string]$Name) { return $RequestedTools.Count -eq 0 -or $Name -in $RequestedTools }
if (Test-Selected 'dalfox') { Install-ArchiveTool $Dalfox }
if (Test-Selected 'ffuf') { Install-ArchiveTool $Ffuf }
if (Test-Selected 'sqlmap') {
    $sqlmapPath = Join-Path $BinDirectory 'sqlmap'
    $sqlmapArchive = Get-VerifiedDownload $Sqlmap
    $sqlmapExtract = Join-Path $CacheDirectory 'extract-sqlmap'
    Remove-Item -LiteralPath $sqlmapExtract -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive -LiteralPath $sqlmapArchive -DestinationPath $sqlmapExtract -Force
    $sqlmapSource = Get-ChildItem -LiteralPath $sqlmapExtract -Directory | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'sqlmap.py') } | Select-Object -First 1
    if (-not $sqlmapSource) { throw 'sqlmap archive did not contain sqlmap.py' }
    Remove-Item -LiteralPath $sqlmapPath -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $sqlmapSource.FullName -Destination $sqlmapPath -Recurse -Force
    & (Get-Command python -ErrorAction Stop).Source (Join-Path $RepositoryRoot 'scripts\prepare_sqlmap.py') $sqlmapSource.FullName $sqlmapPath
    if (-not (Test-Path -LiteralPath (Join-Path $sqlmapPath 'sqlmap_entry.zlib'))) { throw 'sqlmap preparation did not produce sqlmap_entry.zlib' }
}
$installedLabel = if ($RequestedTools.Count -eq 0) { 'Dalfox, ffuf, and sqlmap' } else { $RequestedTools -join ', ' }
Write-Host "Installed $installedLabel into $BinDirectory"
