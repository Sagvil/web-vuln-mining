param(
    [ValidateSet('default')][string]$Profile = 'default',
    [switch]$WithHexStrike,
    [string]$HexStrikeConfig = '',
    [switch]$InstallCodexSkill,
    [switch]$DryRun
)
# ============================ Configuration zone ============================
# Profile: reserved installation profile; default installs the first-batch Web/API toolchain.
# WithHexStrike: deploy and validate the remote policy service using HexStrikeConfig.
# InstallCodexSkill: copy the portable Codex adapter into the current user's Skill directory.
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
    & (Join-Path $RepositoryRoot 'scripts\install_tools.ps1') -DataRoot $DataRoot
    $state = @{ schema_version = 1; installed_at = (Get-Date).ToUniversalTime().ToString('o'); platform = 'windows'; profile = $Profile; data_root = $DataRoot }
    $state | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $DataRoot 'install-state.json')
    & python (Join-Path $RepositoryRoot 'scripts\preflight.py') --json --check-policy
}
if ($InstallCodexSkill) {
    $skillRoot = Join-Path $env:USERPROFILE '.codex\skills\web-vuln-mining'
    New-Item -ItemType Directory -Force -Path $skillRoot | Out-Null
    Copy-Item -Force (Join-Path $RepositoryRoot 'adapters\codex\SKILL.md') (Join-Path $skillRoot 'SKILL.md')
}
if ($WithHexStrike) {
    if ([string]::IsNullOrWhiteSpace($HexStrikeConfig)) { throw 'WithHexStrike requires -HexStrikeConfig config\hexstrike.remote.local.yaml' }
    & python (Join-Path $RepositoryRoot 'scripts\hexstrike_deploy.py') --config $HexStrikeConfig
}
