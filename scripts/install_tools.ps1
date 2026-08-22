param([string]$DataRoot = $env:WEB_VULN_MINING_DATA, [string]$OnlyTools = '', [switch]$SkipZap)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
if ($DataRoot) { $env:WEB_VULN_MINING_DATA = $DataRoot }
$Command = @('python', (Join-Path $Root 'scripts\install_toolchain.py'), '--lock', 'tool-lock.windows.json')
if ($OnlyTools) { $Command += @('--only-tools', $OnlyTools) }
& $Command[0] $Command[1..($Command.Length - 1)]
exit $LASTEXITCODE
