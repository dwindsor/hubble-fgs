# Simple TCP server in PowerShell
param(
    [switch]$ipv6
)

$port = 7991
if ($ipv6) {
    $ipAddress = [System.Net.IPAddress]::IPv6Any
    Write-Host "Using IPv6."
} else {
    $ipAddress = [System.Net.IPAddress]::Any
    Write-Host "Using IPv4."
}
$listener = [System.Net.Sockets.TcpListener]::new($ipAddress, $port)
$listener.Start()
Write-Host "Server listening on port $port..."


$client = $listener.AcceptTcpClient()
Write-Host "Client connected: $($client.Client.RemoteEndPoint)"
$stream = $client.GetStream()
$reader = New-Object System.IO.StreamReader($stream)
$writer = New-Object System.IO.StreamWriter($stream)
$writer.AutoFlush = $true

while ($stream.DataAvailable) {
    $line = $reader.ReadLine()
    Write-Host "Received: $line"
    $writer.WriteLine("Echo: $line")
}

$writer.Close()
$reader.Close()
$client.Close()
Write-Host "Client disconnected."
