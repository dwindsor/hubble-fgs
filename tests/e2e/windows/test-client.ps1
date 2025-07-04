param(
    [switch]$ipv6
)

if ($ipv6) {
    $server = "::1"
    Write-Host "Using IPv6."
} else {
    $server = "127.0.0.1"
    Write-Host "Using IPv4."
}
$port = 7991            

$client = New-Object System.Net.Sockets.TcpClient
$client.Connect($server, $port)

$stream = $client.GetStream()
$writer = New-Object System.IO.StreamWriter($stream)
$reader = New-Object System.IO.StreamReader($stream)

# Send a message to the server
$message = "Hello from client"
$writer.WriteLine($message)
$writer.Flush()

# Read response from server
$response = $reader.ReadLine()
Write-Host "Received from server: $response"

# Cleanup
$writer.Close()
$reader.Close()
$client.Close()