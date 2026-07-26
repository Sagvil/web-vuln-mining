param(
    [ValidateSet('default')][string]$Profile = 'default',
    [switch]$WithHexStrike,
    [string]$HexStrikeConfig = '',
    [switch]$InstallCodexSkill,
    [switch]$Repair,
    [string]$OnlyTools = '',
    [switch]$DryRun
)
# ============================ Configuration zone ============================
# Profile: reserved installation profile; default installs all twelve locked Web/API tools.
# WithHexStrike: deploy and validate the remote policy service using HexStrikeConfig.
# InstallCodexSkill: copy the portable Codex adapter into the current user's Skill directory.
# Repair: explicit idempotent self-healing invocation from preflight.py.
# OnlyTools: comma-separated repair subset; empty installs all twelve tools.
# DryRun: show prerequisite actions without downloading tool archives.
$ErrorActionPreference = 'Stop'
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$DataRoot = if ($env:WEB_VULN_MINING_DATA) { $env:WEB_VULN_MINING_DATA } else { Join-Path $env:LOCALAPPDATA 'web-vuln-mining' }
# ============================================================================

function Ensure-WingetPackage([string]$Id, [string]$Name) {
    if (Get-Command $Name -ErrorAction SilentlyContinue) { return }
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { throw "Missing $Name and winget is unavailable." }
    if ($DryRun) { Write-Host "[dry-run] winget install $Id"; return }
    winget install --id $Id --exact --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) { throw "winget failed to install $Name" }
}

Ensure-WingetPackage 'Git.Git' 'git'
Ensure-WingetPackage 'Python.Python.3.12' 'python'
Ensure-WingetPackage 'EclipseAdoptium.Temurin.17.JDK' 'java'
Ensure-WingetPackage 'astral-sh.uv' 'uvx'
if (-not $DryRun) {
    $requested = @($OnlyTools.Split(',', [StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() })
    $coreNames = @('semgrep','codeql','trivy','gitleaks','pd-httpx','katana','nuclei','zap','schemathesis','runtime')
    $extensionNames = @('dalfox','sqlmap','ffuf')
    if ($requested.Count -eq 0 -or @($requested | Where-Object { $_ -in $coreNames }).Count -gt 0) { & (Join-Path $RepositoryRoot 'scripts\install_tools.ps1') -DataRoot $DataRoot -OnlyTools $OnlyTools }
    if ($requested.Count -eq 0 -or @($requested | Where-Object { $_ -in $extensionNames }).Count -gt 0) { & (Join-Path $RepositoryRoot 'scripts\install_extensions.ps1') -DataRoot $DataRoot -OnlyTools $OnlyTools }
    if (-not ($Repair -and $requested.Count -gt 0)) {
        $env:WEB_VULN_MINING_DATA = $DataRoot
        & python (Join-Path $RepositoryRoot 'scripts\preflight.py') --json --check-policy
        if ($LASTEXITCODE -ne 0) { throw 'Post-install preflight failed.' }
        $preflight = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'runs\preflight-latest.json') -Raw | ConvertFrom-Json
        $lockPath = Join-Path $RepositoryRoot 'config\tool-lock.windows.json'
        $state = @{ schema_version = 1; installed_at = (Get-Date).ToUniversalTime().ToString('o'); platform = 'windows'; profile = $Profile; data_root = $DataRoot; lock_sha256 = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant(); tools = $preflight.tools }
        $state | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 (Join-Path $DataRoot 'install-state.json')
    }
    else {
        Write-Host "Repair subset installed; caller will re-run preflight: $OnlyTools"
    }
}
elseif ($Repair) { Write-Host "[dry-run] repair locked tools: $OnlyTools" }
if ($InstallCodexSkill) {
    $skillRoot = Join-Path $env:USERPROFILE '.codex\skills\web-vuln-mining'
    New-Item -ItemType Directory -Force -Path $skillRoot | Out-Null
    Copy-Item -Force (Join-Path $RepositoryRoot 'adapters\codex\SKILL.md') (Join-Path $skillRoot 'SKILL.md')
}
if ($WithHexStrike) {
    if ([string]::IsNullOrWhiteSpace($HexStrikeConfig)) { throw 'WithHexStrike requires -HexStrikeConfig config\hexstrike.remote.local.yaml' }
    if ($DryRun) { Write-Host "[dry-run] install HexStrike requirements and deploy using $HexStrikeConfig" }
    else {
        & python -m pip install --upgrade -r (Join-Path $RepositoryRoot 'requirements-hexstrike.txt')
        & python (Join-Path $RepositoryRoot 'scripts\hexstrike_deploy.py') --config $HexStrikeConfig
    }
}
