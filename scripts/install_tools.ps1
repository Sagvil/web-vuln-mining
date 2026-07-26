param(
    [string]$DataRoot = $env:WEB_VULN_MINING_DATA,
    [switch]$SkipZap
)
# Web vulnerability mining tool installer
# ============================ Configuration zone ============================
# DataRoot: user-owned directory for downloaded archives and executables.
# SkipZap: omit the ZAP package when Java or ZAP is intentionally managed elsewhere.
$ErrorActionPreference = 'Stop'
$WorkbenchRoot = Split-Path -Parent $PSScriptRoot              # Portable repository root.
if ([string]::IsNullOrWhiteSpace($DataRoot)) { $DataRoot = Join-Path $env:LOCALAPPDATA 'web-vuln-mining' }
$PythonExecutable = (Get-Command python -ErrorAction Stop).Source # Python used for Semgrep and runner dependencies.
$CacheDirectory = Join-Path $DataRoot 'cache'                  # Download cache; safe to clear after installation.
$BinDirectory = Join-Path $DataRoot 'bin'                      # Pinned executable location.
$InstallZap = -not $SkipZap                                    # Install ZAP package when true.
# ============================================================================

$Releases = @(
    @{ Name='trivy'; Archive='trivy_0.72.0_windows-64bit.zip'; Url='https://github.com/aquasecurity/trivy/releases/download/v0.72.0/trivy_0.72.0_windows-64bit.zip'; Checksums='https://github.com/aquasecurity/trivy/releases/download/v0.72.0/trivy_0.72.0_checksums.txt'; Executable='trivy.exe'; Destination='trivy.exe' },
    @{ Name='gitleaks'; Archive='gitleaks_8.30.1_windows_x64.zip'; Url='https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_windows_x64.zip'; Checksums='https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt'; Executable='gitleaks.exe'; Destination='gitleaks.exe' },
    @{ Name='nuclei'; Archive='nuclei_3.11.0_windows_amd64.zip'; Url='https://github.com/projectdiscovery/nuclei/releases/download/v3.11.0/nuclei_3.11.0_windows_amd64.zip'; Checksums='https://github.com/projectdiscovery/nuclei/releases/download/v3.11.0/nuclei_3.11.0_checksums.txt'; Executable='nuclei.exe'; Destination='nuclei.exe' },
    @{ Name='pd-httpx'; Archive='httpx_1.10.0_windows_amd64.zip'; Url='https://github.com/projectdiscovery/httpx/releases/download/v1.10.0/httpx_1.10.0_windows_amd64.zip'; Checksums='https://github.com/projectdiscovery/httpx/releases/download/v1.10.0/httpx_1.10.0_checksums.txt'; Executable='httpx.exe'; Destination='pd-httpx.exe' },
    @{ Name='katana'; Archive='katana_1.6.1_windows_amd64.zip'; Url='https://github.com/projectdiscovery/katana/releases/download/v1.6.1/katana_1.6.1_windows_amd64.zip'; Checksums='https://github.com/projectdiscovery/katana/releases/download/v1.6.1/katana-1.6.1-checksums.txt'; Executable='katana.exe'; Destination='katana.exe' }
)
$CodeQl = @{ Archive='codeql-bundle-win64.tar.gz'; Url='https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.26.1/codeql-bundle-win64.tar.gz'; Sha256='ca630f02e0bcf4f35f5c39159e82a794f1f598ff8df51f32ba1d20a9bfd75cbb' }
$Zap = @{ Archive='ZAP_2.17.0_Crossplatform.zip'; Url='https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Crossplatform.zip'; Sha256='94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0' }

function Get-Download([string]$Url, [string]$Target) {
    $existing = Get-Item -LiteralPath $Target -ErrorAction SilentlyContinue
    if ($existing -and $existing.Length -gt 0) { return }
    Remove-Item -LiteralPath $Target -Force -ErrorAction SilentlyContinue
    $jobName = "web-vuln-mining-" + [IO.Path]::GetFileName($Target)
    Get-BitsTransfer -Name $jobName -AllUsers:$false -ErrorAction SilentlyContinue | Remove-BitsTransfer -ErrorAction SilentlyContinue
    Write-Host "Downloading $Url"
    $job = Start-BitsTransfer -Source $Url -Destination $Target -DisplayName $jobName -Asynchronous
    while ($job.JobState -in @('Connecting', 'Transferring', 'Queued', 'Suspended')) {
        Start-Sleep -Seconds 2
        $job = Get-BitsTransfer -Id $job.JobId -ErrorAction Stop
    }
    if ($job.JobState -ne 'Transferred') {
        $errorText = $job.ErrorDescription
        Remove-BitsTransfer -BitsJob $job -ErrorAction SilentlyContinue
        throw "BITS download failed for ${Url}: $errorText"
    }
    Complete-BitsTransfer -BitsJob $job
}

function Assert-Sha256([string]$Path, [string]$Expected) {
    $Actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Actual -ne $Expected.ToLowerInvariant()) { throw "SHA-256 mismatch for $Path. expected=$Expected actual=$Actual" }
}

function Get-VerifiedDownload([string]$Url, [string]$Target, [string]$Expected) {
    Get-Download $Url $Target
    try {
        Assert-Sha256 $Target $Expected
    } catch {
        # A cancelled BITS job can leave a non-empty partial archive; retry it once cleanly.
        Remove-Item -LiteralPath $Target -Force -ErrorAction SilentlyContinue
        Get-Download $Url $Target
        Assert-Sha256 $Target $Expected
    }
}

function Get-ReleaseHash([hashtable]$Release) {
    $ChecksumPath = Join-Path $CacheDirectory "$($Release.Name)-checksums.txt"
    Get-Download $Release.Checksums $ChecksumPath
    $Match = Get-Content -LiteralPath $ChecksumPath | Where-Object { $_ -match [regex]::Escape($Release.Archive) } | Select-Object -First 1
    if (-not $Match) { throw "Checksum for $($Release.Archive) was not found in $ChecksumPath" }
    return ($Match -split '\s+')[0]
}

function Install-ZipBinary([hashtable]$Release) {
    $ArchivePath = Join-Path $CacheDirectory $Release.Archive
    Get-VerifiedDownload $Release.Url $ArchivePath (Get-ReleaseHash $Release)
    $ExtractPath = Join-Path $CacheDirectory "extract-$($Release.Name)"
    Remove-Item -LiteralPath $ExtractPath -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive -LiteralPath $ArchivePath -DestinationPath $ExtractPath -Force
    $Binary = Get-ChildItem -LiteralPath $ExtractPath -Recurse -File -Filter $Release.Executable | Select-Object -First 1
    if (-not $Binary) { throw "$($Release.Executable) was not present in $($Release.Archive)" }
    Copy-Item -LiteralPath $Binary.FullName -Destination (Join-Path $BinDirectory $Release.Destination) -Force
}

New-Item -ItemType Directory -Path $CacheDirectory,$BinDirectory -Force | Out-Null
foreach ($Release in $Releases) { Install-ZipBinary $Release }

$CodeQlArchive = Join-Path $CacheDirectory $CodeQl.Archive
Get-VerifiedDownload $CodeQl.Url $CodeQlArchive $CodeQl.Sha256
Remove-Item -LiteralPath (Join-Path $BinDirectory 'codeql') -Recurse -Force -ErrorAction SilentlyContinue
& tar.exe -xzf $CodeQlArchive -C $BinDirectory
if (-not (Test-Path -LiteralPath (Join-Path $BinDirectory 'codeql\codeql.exe'))) { throw 'CodeQL extraction did not produce bin\codeql\codeql.exe' }

if ($InstallZap) {
    $ZapArchive = Join-Path $CacheDirectory $Zap.Archive
    Get-VerifiedDownload $Zap.Url $ZapArchive $Zap.Sha256
    $ZapExtract = Join-Path $CacheDirectory 'extract-zap'
    Remove-Item -LiteralPath $ZapExtract -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive -LiteralPath $ZapArchive -DestinationPath $ZapExtract -Force
    $ZapBat = Get-ChildItem -LiteralPath $ZapExtract -Recurse -File -Filter 'zap.bat' | Select-Object -First 1
    if (-not $ZapBat) { throw 'ZAP archive did not contain zap.bat' }
    Remove-Item -LiteralPath (Join-Path $BinDirectory 'zap') -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $ZapBat.Directory.FullName -Destination (Join-Path $BinDirectory 'zap') -Recurse -Force
}

$PythonTools = Join-Path $BinDirectory 'python-tools'
if (-not (Test-Path -LiteralPath (Join-Path $PythonTools 'Scripts\python.exe'))) { & $PythonExecutable -m venv $PythonTools }
& (Join-Path $PythonTools 'Scripts\python.exe') -m pip install --upgrade pip 'semgrep==1.171.0'
& $PythonExecutable -m pip install --upgrade -r (Join-Path $WorkbenchRoot 'requirements-runner.txt')

Write-Host 'Installed Web vulnerability mining toolchain:'
Get-ChildItem -LiteralPath $BinDirectory -Recurse -File | Where-Object { $_.Name -match '^(trivy|gitleaks|nuclei|pd-httpx|katana|codeql|semgrep|zap)\.(exe|bat)$' } | Select-Object FullName
