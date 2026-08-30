# The script block that 40-powershell.ps1 asserts on.
#
# Runs under powershell.exe, launched by Start-Probe.
#
# A block built at runtime is always logged as 4104 with exactly the text below. This
# file's own text is not: PowerShell was observed to skip it for this script, with
# Tetragon not running and EnableScriptBlockLogging already 1. Do not match the file's
# own text instead.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Marker
)

$ErrorActionPreference = 'Stop'

& ([scriptblock]::Create("'$Marker'")) | Out-Null
Write-Host "script block: emitted '$Marker'"
exit 0
