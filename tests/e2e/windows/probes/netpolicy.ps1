# The two http requests that 30-netpolicy.ps1 asserts on.
#
# Runs under powershell.exe, launched by Start-Probe. Exits with the number of checks
# that failed, which the module turns into its enforcement check.

[CmdletBinding()]
param(
    # Reachable, and outside the CIDR the policy denies.
    [string]$AllowedUrl = 'https://www.google.com',

    # Inside the CIDR the policy denies for this binary.
    [string]$DeniedUrl = 'http://142.250.217.78',

    [int]$UrlTimeoutSeconds = 15
)

$ErrorActionPreference = 'Stop'

# Windows PowerShell defaults can still negotiate TLS 1.0, and the progress bar costs
# seconds per request here.
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

# The pair is what makes the deny falsifiable: without a reachable control url, a
# blocked connect is indistinguishable from a machine with no route out.
$failures = 0

# Denied first, then allowed. The module asserts that the denied endpoint produces no
# connect event, and stops reading the export once it has matched the allowed one -- so
# the allowed request has to come second for that absence to prove anything.
#
# A deny has been seen both as an instant WSAEACCES 10013 and as a plain client-side
# timeout, so the only safe assertion is that the request did not succeed. Any success
# fails the check, not just a 200: an unblocked host can answer 301 or 403.
try {
    Invoke-WebRequest -Uri $DeniedUrl -TimeoutSec $UrlTimeoutSeconds -UseBasicParsing | Out-Null
    Write-Host "deny: $DeniedUrl was reachable, the policy should have blocked it"
    $failures++
}
catch {
    Write-Host "deny: $DeniedUrl blocked - $($_.Exception.Message)"
}

try {
    Invoke-WebRequest -Uri $AllowedUrl -TimeoutSec $UrlTimeoutSeconds -UseBasicParsing | Out-Null
    Write-Host "allow: $AllowedUrl reachable"
}
catch {
    Write-Host "allow: $AllowedUrl unreachable - $($_.Exception.Message)"
    $failures++
}

exit $failures
