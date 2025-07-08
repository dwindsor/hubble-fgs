# Define the path to the JSON file
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

Write-Host "Process $PID made a web request"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$ipv4serverID =  Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File $scriptDir\test-server.ps1" -PassThru
$ipv4serverPID = $ipv4serverID.Id
Write-Host "Process $ipv4serverPID Is a server"

Start-Sleep -Seconds 2

$ipv4clientID =  Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File $scriptDir\test-client.ps1" -PassThru
$ipv4clientPID = $ipv4clientID.Id
Write-Host "Process $ipv4clientPID Is a client"

Start-Sleep -Seconds 2

# Load the JSON content
$jsonContent = Get-Content -Path $jsonFilePath 

#ToDo: get the UID of the current user
$regexPatterns = @(
@{ Name = "exec"; Pattern = "\{\""process_exec\""\:\{\""process\""\:\{\""exec_id\""\:\"".{16,30}\""\,.{0,1}\""pid\""\:$notepadPID\,.{0,1}\""uid\""\:[0-9]{0,9}\,.{0,1}\""binary\""\:\""C:\\\\Windows\\\\system32\\\\notepad.exe\"""},
@{ Name = "exit"; Pattern = "\{\""process_exit\""\:\{\""process\""\:\{\""exec_id\""\:\"".{16,30}\""\,.{0,1}\""pid\""\:$notepadPID\,.{0,1}\""uid\""\:[0-9]{0,9}\,.{0,1}\""binary\""\:\""C:\\\\Windows\\\\system32\\\\notepad.exe\"""},
@{ Name = "connect"; Pattern = "\{\""process_connect\""\:\{\""process\""\:\{\""exec_id\""\:\"".{16,30}\""\,.{0,1}\""pid\""\:$PID\,.{0,1}\""uid\""\:[0-9]{0,9}\,.{0,1}\""binary\""\:\"".*\\\\powershell.exe\"""}
@{ Name = "connect_v4"; Pattern = "\{\""process_connect\""\:\{\""process\""\:\{\""exec_id\""\:\"".{16,30}\""\,.{0,1}\""pid\""\:$ipv4clientPID\,.{0,1}\""uid\""\:[0-9]{0,9}\,.{0,1}\""binary\""\:\"".*\\\\powershell.exe\"""}
@{ Name = "accept_v4"; Pattern = "\{\""process_accept\""\:\{\""process\""\:\{\""exec_id\""\:\"".{16,30}\""\,.{0,1}\""pid\""\:$ipv4serverPID\,.{0,1}\""uid\""\:[0-9]{0,9}\,.{0,1}\""binary\""\:\"".*\\\\powershell.exe\"""}
)

foreach ($item in $regexPatterns) {
Write-Host "Looking for regex: $($item.Pattern)"
if ($jsonContent -match $item.Pattern) {
    Write-Host "Found $($item.Name) pattern in JSON file: $($item.Pattern)"
} else {
    Write-Host "$($item.Name) pattern not found in event file: $jsonContent"
    throw "$($item.Name.ToUpper()) EVENT not found in event JSON file."
}
}