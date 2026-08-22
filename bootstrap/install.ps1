param(
    [ValidateSet('default')][string]$Profile = 'default',
    [switch]$WithHexStrike,
    [string]$HexStrikeConfig = '',
    [switch]$InstallCodexSkill,
    [switch]$Repair,
    [string]$OnlyTools = '',
    [switch]$DryRun
)
# Compatibility front end: all release installation and verification stays in
# scripts/install_toolchain.py, shared with Bash and Linux ARM64.
$ErrorActionPreference = 'Stop'
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$Command = @('python', (Join-Path $RepositoryRoot 'scripts\install_toolchain.py'), '--lock', 'tool-lock.windows.json')
if (-not [string]::IsNullOrWhiteSpace($OnlyTools)) { $Command += @('--only-tools', $OnlyTools) }
if ($DryRun) { Write-Host ('[dry-run] ' + ($Command -join ' ')); exit 0 }
& $Command[0] $Command[1..($Command.Length - 1)]
if ($LASTEXITCODE -ne 0) { throw 'Locked tool installation failed.' }
& python (Join-Path $RepositoryRoot 'scripts\preflight.py') --json --required-profiles source web-baseline api
if ($LASTEXITCODE -ne 0) { throw 'Post-install integrity preflight failed.' }
if ($InstallCodexSkill) {
    $SkillRoot = Join-Path $env:USERPROFILE '.codex\skills\web-vuln-mining'
    New-Item -ItemType Directory -Force -Path $SkillRoot | Out-Null
    Copy-Item -Force (Join-Path $RepositoryRoot 'adapters\codex\SKILL.md') (Join-Path $SkillRoot 'SKILL.md')
}
if ($WithHexStrike) {
    if ([string]::IsNullOrWhiteSpace($HexStrikeConfig)) { throw 'WithHexStrike requires -HexStrikeConfig FILE' }
    & python -m pip install --require-hashes -r (Join-Path $RepositoryRoot 'requirements-hexstrike.lock')
    & python (Join-Path $RepositoryRoot 'scripts\hexstrike_deploy.py') --config $HexStrikeConfig
}
Write-Host "Installed profile $Profile with immutable lock verification."
