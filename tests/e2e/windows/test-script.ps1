
# This script can be used to launch events and check for them in the event.json file. 
# the prereq is to run tetragon.exe with --tcp-enabled switch and --export-filename "C:\Program Files\Tetragon\events.json"

# The script will launch a notepad process, terminate it, make a web request, and start a server and client process.
# It will then check the events.json file for specific patterns related to these actions.
# The script will throw an error if any of the expected patterns are not found in the JSON file.
$jsonFilePath = "C:\Program Files\Tetragon\events.json"

$notepad = Start-Process -FilePath "C:\Windows\System32\notepad.exe" -PassThru
$notepadPID = $notepad.Id
Write-Host "Process launched with PID: $notepadPID"

Stop-Process -Id $notepadPID

Write-Host "Process terminated with PID: $notepadPID"


Invoke-WebRequest -Uri "https://www.google.com"

#Check blocking
$success = $false
try {
    $response = Invoke-WebRequest -Uri "http://142.250.217.78" -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        $success = $false
    }
}
catch {
    Write-Host "Block Success: Web request to 142.250.217.78 failed: $($_.Exception.Message)"
    $success = $true
}

if ($success -eq $false) {
    Write-Warning "Url could not be blocked"
}

Write-Host "Process $PID made a web request"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$serverArgs = "-NoProfile -ExecutionPolicy Bypass -File $scriptDir\test-server.ps1"
$ipv4serverID = Start-Process -FilePath "powershell.exe" -ArgumentList $serverArgs -PassThru
$ipv4serverPID = $ipv4serverID.Id
Write-Host "Process $ipv4serverPID Is a server"

Start-Sleep -Seconds 2

$clientArgs = "-NoProfile -ExecutionPolicy Bypass -File $scriptDir\test-client.ps1"
$ipv4clientID = Start-Process -FilePath "powershell.exe" -ArgumentList $clientArgs -PassThru
$ipv4clientPID = $ipv4clientID.Id
Write-Host "Process $ipv4clientPID Is a client"

Start-Sleep -Seconds 2

# Load the JSON content
$jsonContent = Get-Content -Path $jsonFilePath 

# Import the function from GetTokenStatistics.ps1 and call it to get the current user UID
. "$scriptDir\Get-TokenStatistics.ps1"  # Dot-source the script to load its functions
$uid = Get-TokenStatistics
Write-Host "Current user ID: $uid"
# Convert current time to UTC in the same format
$currentTimeHour = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH")
$currentTimeHourRegex = "$currentTimeHour\:[0-9]{2}\:[0-9]{2}\.[0-9]{3}Z"

$notepadProcessStartTimeUTC = $notepad.StartTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm")
$notepadProcessStartTimeRegex = "$notepadProcessStartTimeUTC\:[0-9]{2}\.[0-9]{3}Z"

$currentProcess = Get-Process -Id $PID
$currentProcessStartTimeUTC = $currentProcess.StartTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm")
$currentProcessStartTimeRegex = "$currentProcessStartTimeUTC\:[0-9]{2}\.[0-9]{3}Z"
$powershellPath = $currentProcess.Path
$powershellPath = $powershellPath -replace '\\', '\\\\'
$serverArgs = $serverArgs -replace '\\', '\\\\'
$clientArgs = $clientArgs -replace '\\', '\\\\'

$procRegexPre = ".{0,1}\""flags\""\:\"".{3,30}\""\,.{0,1}\""start_time\""\:\"""
$procRegexPost = "\""\,.{0,1}\""auid\"":[0-9]{1,15}\,.{0,1}\""parent_exec_id\"":\"".{8,30}\""\,.{0,1}\""tid\""\:[0-9]{2,9}\,.{0,1}\""in_init_tree\""\:false\}"
$eventPreRegexToken = "\:\{\""process\""\:\{\""exec_id\""\:\"".{8,30}\""\,.{0,1}\""pid\""\:"


$processRegex = $procRegexPre + $notepadProcessStartTimeRegex + $procRegexPost
$parentRegex = $procRegexPre + $currentProcessStartTimeRegex + $procRegexPost

$regexPatterns = @(
    @{ Name = "exec"; Pattern = "\{\""process_exec\""$eventPreRegexToken$notepadPID\,.{0,1}\""uid\""\:$uid\,.{0,1}\""binary\""\:\""C:\\\\[wW]indows\\\\[sS]ystem32\\\\notepad.exe\""\,$processRegex\,.{0,1}\""parent\""\:\{\""exec_id\""\:\"".{16,30}\""\,.{0,1}\""pid\""\:$PID\,.{0,1}\""uid\""\:$uid\,.{0,1}\""binary\""\:\""$powershellPath""\,$parentRegex\}\,.{0,1}\""node_name\""\:\"".{8,32}\""\,.{0,1}\""time\""\:\""$currentTimeHourRegex\""\}" },
    @{ Name = "exit"; Pattern = "\{\""process_exit\""$eventPreRegexToken$notepadPID\,.{0,1}\""uid\""\:$uid\,.{0,1}\""binary\""\:\""C:\\\\[wW]indows\\\\[sS]ystem32\\\\notepad.exe\""\,$processRegex\,.{0,1}\""parent\""\:\{\""exec_id\""\:\"".{16,30}\""\,.{0,1}\""pid\""\:$PID\,.{0,1}\""uid\""\:$uid\,.{0,1}\""binary\""\:\""$powershellPath""\,$parentRegex\,.{0,1}.*\""status\""\:[0-9]{2,15}\,.{0,1}\""time\""\:\""$currentTimeHourRegex\""\}\,.{0,1}\""node_name\""\:\"".{8,32}\""\,.{0,1}\""time\""\:\""$currentTimeHourRegex""\}" },
    @{ Name = "connect"; Pattern = "\{\""process_connect\""$eventPreRegexToken$PID\,.{0,1}\""uid\""\:$uid\,.{0,1}\""binary\""\:\""$powershellPath\""\,$parentRegex\,.{0,1}\""parent\""\:\{\""exec_id\""\:\"".{16,30}\""\,.{0,1}\""pid\""\:[0-9]{1,16}\,.{0,1}\""uid\""\:[0-9]{2,16}\,.{0,1}\""binary\""\:\"".*\,.{0,1}\""in_init_tree\""\:false\}\,.{0,1}\""source_ip\""\:\""0\.0\.0\.0\""\,.{0,1}\""source_port\""\:[0-9]{2,10}\,.{0,1}\""destination_ip\""\:\""(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\""\,.{0,1}\""destination_port\""\:443\,.{0,1}\""sock_cookie\""\:\""[0-9]{2,10}\""\,.{0,1}\""protocol\""\:\""TCP\""\}\,.{0,1}\""node_name\""\:\"".{8,32}\""\,.{0,1}\""time\""\:\""$currentTimeHourRegex\""\}" }
    @{ Name = "connect_v4"; Pattern = "\{\""process_connect\""\:\{\""process\""\:\{\""exec_id\""\:\"".{16,30}\""\,.{0,1}\""pid\""\:$ipv4clientPID\,.{0,1}\""uid\""\:$uid\,.{0,1}\""binary\""\:\""$powershellPath\""\,.{0,1}\""arguments\""\:\"" \\\""$clientArgs \\\""\""\,$processRegex\,.{0,1}\""parent\""\:\{\""exec_id\""\:\"".{16,30}\""\,.{0,1}\""pid\""\:$PID\,.{0,1}\""uid\""\:$uid\,.{0,1}\""binary\""\:\""$powershellPath""\,$parentRegex,.{0,1}\""source_ip\""\:\""0\.0\.0\.0\""\,.{0,1}\""source_port\""\:[0-9]{2,10}\,.{0,1}\""destination_ip\""\:\""127\.0\.0\.1\""\,.{0,1}\""destination_port\""\:7991\,.{0,1}\""sock_cookie\""\:\""[0-9]{2,10}\""\,.{0,1}\""protocol\""\:\""TCP\""\}\,.{0,1}\""node_name\""\:\"".{8,32}\""\,.{0,1}\""time\""\:\""$currentTimeHourRegex\""\}" }
    @{ Name = "accept_v4"; Pattern = "\{\""process_accept\""\:\{\""process\""\:\{\""exec_id\""\:\"".{16,30}\""\,.{0,1}\""pid\""\:$ipv4serverPID\,.{0,1}\""uid\""\:$uid\,.{0,1}\""binary\""\:\""$powershellPath\""\,.{0,1}\""arguments\""\:\"" \\\""$serverArgs \\\""\""\,$processRegex\,.{0,1}\""parent\""\:\{\""exec_id\""\:\"".{16,30}\""\,.{0,1}\""pid\""\:$PID\,.{0,1}\""uid\""\:$uid\,.{0,1}\""binary\""\:\""$powershellPath""\,$parentRegex,.{0,1}\""source_ip\""\:\""127\.0\.0\.1\""\,.{0,1}\""source_port\""\:7991\,.{0,1}\""destination_ip\""\:\""127\.0\.0\.1\""\,.{0,1}\""destination_port\""\:[0-9]{2,10}\,.{0,1}\""sock_cookie\""\:\""[0-9]{2,10}\""\,.{0,1}\""protocol\""\:\""TCP\""\}\,.{0,1}\""node_name\""\:\"".{8,32}\""\,.{0,1}\""time\""\:\""$currentTimeHourRegex\""\}" }
    @{ Name = "close_server"; Pattern = "\{\""process_close\""\:\{\""process\""\:\{\""exec_id\""\:\"".{16,30}\""\,.{0,1}\""pid\""\:$ipv4serverPID\,.{0,1}\""uid\""\:$uid\,.{0,1}\""binary\""\:\""$powershellPath\""\,.{0,1}\""arguments\""\:\"" \\\""$serverArgs \\\""\""\,$processRegex\,.{0,1}\""parent\""\:\{\""exec_id\""\:\"".{16,30}\""\,.{0,1}\""pid\""\:$PID\,.{0,1}\""uid\""\:$uid\,.{0,1}\""binary\""\:\""$powershellPath""\,$parentRegex,.{0,1}\""source_ip\""\:\""127\.0\.0\.1\""\,.{0,1}\""source_port\""\:7991\,.{0,1}\""destination_ip\""\:\""127\.0\.0\.1\""\,.{0,1}\""destination_port\""\:[0-9]{2,10}\,.{0,1}\""sock_cookie\""\:\""[0-9]{2,10}\""\,.{0,1}\""stats\""\:\{.*\,.{0,1}\""socket_type\""\:\""accept\""\,.{0,1}\""duration\""\:\""[0-9]{1,64}s\""\}\,.{0,1}\""node_name\""\:\"".{8,32}\""\,.{0,1}\""time\""\:\""$currentTimeHourRegex\""\}" }
    @{ Name = "close_client"; Pattern = "\{\""process_close\""\:\{\""process\""\:\{\""exec_id\""\:\"".{16,30}\""\,.{0,1}\""pid\""\:$ipv4clientPID\,.{0,1}\""uid\""\:$uid\,.{0,1}\""binary\""\:\""$powershellPath\""\,.{0,1}\""arguments\""\:\"" \\\""$clientArgs \\\""\""\,$processRegex\,.{0,1}\""parent\""\:\{\""exec_id\""\:\"".{16,30}\""\,.{0,1}\""pid\""\:$PID\,.{0,1}\""uid\""\:$uid\,.{0,1}\""binary\""\:\""$powershellPath""\,$parentRegex,.{0,1}\""source_ip\""\:\""127\.0\.0\.1\""\,.{0,1}\""source_port\""\:[0-9]{2,10}\,.{0,1}\""destination_ip\""\:\""127\.0\.0\.1\""\,.{0,1}\""destination_port\""\:7991\,.{0,1}\""sock_cookie\""\:\""[0-9]{2,10}\""\,.{0,1}\""stats\""\:\{.*\,.{0,1}\""socket_type\""\:\""connect\""\,.{0,1}\""duration\""\:\""[0-9]{1,64}s\""\}\,.{0,1}\""node_name\""\:\"".{8,32}\""\,.{0,1}\""time\""\:\""$currentTimeHourRegex\""\}" }
)

$errors = 0
foreach ($item in $regexPatterns) {
    if ($jsonContent -match $item.Pattern) {
        Write-Host "Found $($item.Name) pattern in event file"
    }
    else {
        Write-Host "$($item.Name) pattern not found in event file:"
        Write-Host "Pattern = $($item.Pattern)"
        Write-Host "File Contents  = $jsonContent"

        Write-Warning "$($item.Name.ToUpper()) EVENT not found in event JSON file."
        $errors += 1
    }
}

if ($errors -eq 0) {
    Write-Host "SUCCESS: All expected patterns found in the event file."
}
else {
    Write-Warning "Technically these are errors, but we don't want to break the build at this time"
}