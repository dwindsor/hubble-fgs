# One end of the loopback TCP exchange that 20-network.ps1 asserts on.
#
# Runs under powershell.exe, launched by Start-Probe. IPv4 only.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('server', 'client')]
    [string]$Role,

    [int]$Port = 7991
)

$ErrorActionPreference = 'Stop'

if ($Role -eq 'server') {
    # Loopback rather than Any: a wildcard bind is subject to the runner's firewall.
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
    $listener.Start()
    Write-Host "server: listening on 127.0.0.1:$Port"

    $peer = $listener.AcceptTcpClient()
    $stream = $peer.GetStream()
    $reader = [System.IO.StreamReader]::new($stream)
    $writer = [System.IO.StreamWriter]::new($stream)
    $writer.AutoFlush = $true

    # One blocking read, so the exchange completes instead of racing DataAvailable.
    $writer.WriteLine("echo: $($reader.ReadLine())")

    $writer.Dispose()
    $reader.Dispose()
    $peer.Dispose()
    $listener.Stop()
    Write-Host 'server: closed'
    exit 0
}

$tcp = [System.Net.Sockets.TcpClient]::new()
$tcp.Connect([System.Net.IPAddress]::Loopback, $Port)
$stream = $tcp.GetStream()
$reader = [System.IO.StreamReader]::new($stream)
$writer = [System.IO.StreamWriter]::new($stream)
$writer.AutoFlush = $true

$writer.WriteLine('hello from the smoke test')
Write-Host "client: server said '$($reader.ReadLine())'"

$writer.Dispose()
$reader.Dispose()
$tcp.Dispose()
exit 0
