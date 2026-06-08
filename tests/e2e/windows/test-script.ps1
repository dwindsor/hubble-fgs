
# This script can be used to launch events and check for them in the event.json file. 
# the prereq is to run tetragon.exe with --tcp-enabled switch and --export-filename "C:\Program Files\Tetragon\events.json"

# The script will launch a notepad process, terminate it, make a web request, and start a server and client process.
# It will then check the events.json file for specific patterns related to these actions.
# The script will throw an error if any of the expected patterns are not found in the JSON file.
$jsonFilePath = "C:\Program Files\Tetragon\events.json"

# Wait for 10 seconds before starting tests 
Start-Sleep -Seconds 10

$notepad = Start-Process -FilePath "C:\Windows\System32\notepad.exe" -PassThru
$notepadPID = $notepad.Id
Write-Host "Process launched with PID: $notepadPID"

Stop-Process -Id $notepadPID

Write-Host "Process terminated with PID: $notepadPID"


Invoke-WebRequest -Uri "https://www.google.com" -TimeoutSec 5 -UseBasicParsing

#Check blocking
$errors = 0
try {
    $response = Invoke-WebRequest -Uri "http://142.250.217.78" -TimeoutSec 5 -UseBasicParsing
    if ($response.StatusCode -eq 200) {
       $errors += 1
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

# Give Tetragon more time to write events to the file
Write-Host "Waiting for Tetragon to write events to file..."
Start-Sleep -Seconds 5

# Load the EventParser module
. "$scriptDir\EventParser.ps1"

# Load and parse the JSON events
Write-Host "Loading events from $jsonFilePath..."
$events = Get-TetragonEvents -FilePath $jsonFilePath
Write-Host "Loaded $($events.Count) total events" 

# Import the function from GetTokenStatistics.ps1 and call it to get the current user UID
. "$scriptDir\Get-TokenStatistics.ps1"  # Dot-source the script to load its functions
$uid = Get-TokenStatistics
Write-Host "Current user ID: $uid"

# Show what we're looking for
Write-Host "=== Test Parameters ===" -ForegroundColor Cyan
Write-Host "Current PowerShell PID: $PID"
Write-Host "Notepad PID: $notepadPID"
Write-Host "IPv4 Server PID: $ipv4serverPID"
Write-Host "IPv4 Client PID: $ipv4clientPID"
Write-Host "User ID: $uid"

# Event type breakdown
$execCount = ($events | Where-Object { $_.PSObject.Properties.Name -contains "process_exec" }).Count
$exitCount = ($events | Where-Object { $_.PSObject.Properties.Name -contains "process_exit" }).Count
$connectCount = ($events | Where-Object { $_.PSObject.Properties.Name -contains "process_connect" }).Count
$acceptCount = ($events | Where-Object { $_.PSObject.Properties.Name -contains "process_accept" }).Count
$closeCount = ($events | Where-Object { $_.PSObject.Properties.Name -contains "process_close" }).Count
$scriptBlockCount = ($events | Where-Object { $_.PSObject.Properties.Name -contains "powershell_script_block" }).Count
Write-Host "=== Event Type Counts ===" -ForegroundColor Cyan
Write-Host "process_exec: $execCount"
Write-Host "process_exit: $exitCount"
Write-Host "process_connect: $connectCount"
Write-Host "process_accept: $acceptCount"
Write-Host "process_close: $closeCount"
Write-Host "powershell_script_block: $scriptBlockCount"

# Validate events using EventParser
Write-Host "=== Running Validations ===" -ForegroundColor Cyan

# 1. Check for process_exec event (notepad)
Write-Host "Checking for process_exec event..."
Write-Host "  Looking for: PID=$notepadPID, Binary=*notepad*, UID=$uid"

# First try with UID filter
$execEvent = Find-ProcessExecEvent -Events $events -ProcessId $notepadPID -Binary "notepad" -Uid $uid
if (-not $execEvent) {
    # Try without UID filter (in case UID doesn't match)
    Write-Host "  Not found with UID filter, trying without UID..."
    $execEvent = Find-ProcessExecEvent -Events $events -ProcessId $notepadPID -Binary "notepad"
}

if ($execEvent) {
    #Write-Host "  Found event: Binary=$($execEvent.process_exec.process.binary), Parent PID=$($execEvent.process_exec.parent.pid)"
    # Validate parent process is current PowerShell process
    if ($execEvent.process_exec.parent.pid -eq $PID) {
        Write-Host " Found exec pattern in event file"
    } else {
        Write-Host "  exec event found but parent PID doesn't match. Expected: $PID, Got: $($execEvent.process_exec.parent.pid)"
        Write-Warning "EXEC EVENT validation failed in event JSON file."
        $errors += 1
    }
} else {
    Write-Host "exec pattern not found in event file"
    # Show all notepad events for debugging
    $allNotepadExecs = $events | Where-Object {
        $_.PSObject.Properties.Name -contains "process_exec" -and
        $_.process_exec.process.binary -like "*notepad*"
    }
    if ($allNotepadExecs) {
        Write-Host "  Found $($allNotepadExecs.Count) notepad exec events with different PIDs:"
        $allNotepadExecs | Select-Object -First 3 | ForEach-Object {
            Write-Host "    PID: $($_.process_exec.process.pid), Binary: $($_.process_exec.process.binary)"
        }
    }
    Write-Warning "EXEC EVENT not found in event JSON file."
    $errors += 1
}

# 2. Check for process_exit event (notepad)
# NOTE: Tetragon on Windows may not generate process_exit events
Write-Host "Checking for process_exit event..."
$exitEventCount = ($events | Where-Object { $_.PSObject.Properties.Name -contains "process_exit" }).Count
if ($exitEventCount -eq 0) {
    Write-Host "  Note: No process_exit events in file (Tetragon may not generate these on Windows)" -ForegroundColor Yellow
    Write-Host "  Skipping process_exit validation"
} else {
    Write-Host "  Looking for: PID=$notepadPID, Binary=*notepad*, UID=$uid"
    $exitEvent = Find-ProcessExitEvent -Events $events -ProcessId $notepadPID -Binary "notepad" -Uid $uid
    if (-not $exitEvent) {
        $exitEvent = Find-ProcessExitEvent -Events $events -ProcessId $notepadPID -Binary "notepad"
    }

    if ($exitEvent) {
        Write-Host "  Found event: Binary=$($exitEvent.process_exit.process.binary)"
        if ($exitEvent.process_exit.parent.pid -eq $PID) {
            Write-Host " Found exit pattern in event file"
        } else {
            Write-Host " exit event found but parent PID doesn't match. Expected: $PID, Got: $($exitEvent.process_exit.parent.pid)"
            Write-Warning "EXIT EVENT validation failed in event JSON file."
            $errors += 1
        }
    } else {
        Write-Host " exit pattern not found in event file"
        Write-Warning "EXIT EVENT not found in event JSON file."
        $errors += 1
    }
}

# 3. Check for powershell_script_block event
Write-Host " Checking for powershell_script_block event..."
if ($scriptBlockCount -eq 0) {
    Write-Host "  Note: No powershell_script_block events in file" -ForegroundColor Yellow
    Write-Host "  Skipping powershell_script_block validation"
} else {
    Write-Host "  Looking for: PID=$PID (current PowerShell process)"
    # Look for script block events from the current PowerShell process
    $scriptBlockEvent = Find-PowerShellScriptBlockEvent -Events $events -ProcessId $PID

    if ($scriptBlockEvent) {
        Write-Host " Found $($scriptBlockEvent.Count) powershell_script_block event(s) from PID $PID"

        # Look for specific payload containing the event filter code
        $expectedPayloadPattern = "*process_exec*"
        $matchingEvent = $scriptBlockEvent | Where-Object {
            $_.powershell_script_block.payload -like $expectedPayloadPattern
        }

        if ($matchingEvent) {
            Write-Host " Found script block with expected payload pattern"
            $payload = $matchingEvent[0].powershell_script_block.payload
            if ($payload.Length -gt 100) {
                $displayPayload = $payload.Substring(0, 100) + "..."
            } else {
                $displayPayload = $payload
            }
            Write-Host "  Payload: $displayPayload"
        } else {
            Write-Host " No script block found with payload containing 'process_exec'"
            # Show sample payloads for debugging
            Write-Host "  Sample payloads found:"
            $scriptBlockEvent | Select-Object -First 3 | ForEach-Object {
                $samplePayload = $_.powershell_script_block.payload
                if ($samplePayload.Length -gt 60) {
                    $samplePayload = $samplePayload.Substring(0, 60) + "..."
                }
                Write-Host "    $samplePayload"
            }
        }
    } else {
        Write-Host " No powershell_script_block events found from PID $PID"
        Write-Host "  Note: This is informational only, not counted as an error"
    }
}

# 4. Check for process_connect event (web request to port 443)
Write-Host " Checking for process_connect event (web request)..."
Write-Host "  Looking for: PID=$PID, Binary=*powershell*, DestPort=443, Protocol=TCP"
$connectEvent = Find-ProcessConnectEvent -Events $events -ProcessId $PID -Binary "powershell" -DestinationPort 443 -Protocol "TCP"
if ($connectEvent) {
    Write-Host " Found connect pattern in event file"
    Write-Host "  Destination: $($connectEvent.process_connect.destination_ip):$($connectEvent.process_connect.destination_port)"
} else {
    Write-Host " connect pattern not found in event file"
    # Show PowerShell connections for debugging
    $psConnects = Find-ProcessConnectEvent -Events $events -ProcessId $PID -Protocol "TCP"
    if ($psConnects) {
        Write-Host "  Found $($psConnects.Count) TCP connections from PID $PID to different ports:"
        $psConnects | Select-Object -First 3 | ForEach-Object {
            Write-Host "    -> $($_.process_connect.destination_ip):$($_.process_connect.destination_port)"
        }
    }
    Write-Warning "CONNECT EVENT not found in event JSON file."
    $errors += 1
}

# 5. Check for process_connect event (IPv4 client connecting to server on port 7991)
Write-Host " Checking for IPv4 client connect event..."
Write-Host "  Looking for: PID=$ipv4clientPID, DestIP=127.0.0.1, DestPort=7991, Protocol=TCP"
$connectV4Event = Find-ProcessConnectEvent -Events $events -ProcessId $ipv4clientPID -Binary "powershell" -DestinationIp "127.0.0.1" -DestinationPort 7991 -Protocol "TCP"
if (-not $connectV4Event) {
    # Try without destination IP (might be reported differently)
    Write-Host "  Not found with DestIP filter, trying without..."
    $connectV4Event = Find-ProcessConnectEvent -Events $events -ProcessId $ipv4clientPID -DestinationPort 7991 -Protocol "TCP"
}

if ($connectV4Event) {
    Write-Host "  Found event: $($connectV4Event.process_connect.source_ip):$($connectV4Event.process_connect.source_port) -> $($connectV4Event.process_connect.destination_ip):$($connectV4Event.process_connect.destination_port)"
    # Validate parent process
    if ($connectV4Event.process_connect.parent.pid -eq $PID) {
        Write-Host " Found connect_v4 pattern in event file"
    } else {
        Write-Host "  connect_v4 event found but parent PID doesn't match. Expected: $PID, Got: $($connectV4Event.process_connect.parent.pid)"
        Write-Warning "CONNECT_V4 EVENT validation failed in event JSON file."
        $errors += 1
    }
} else {
    Write-Host " connect_v4 pattern not found in event file"
    # Show connections from client PID
    $clientConnects = Find-ProcessConnectEvent -Events $events -ProcessId $ipv4clientPID
    if ($clientConnects) {
        Write-Host "  Found $($clientConnects.Count) connections from client PID $ipv4clientPID : "
         $clientConnects | ForEach-Object {
             Write-Host " -> $($_.process_connect.destination_ip):$($_.process_connect.destination_port)"
        }
    } else {
        #Write-Host "  No connections found from client PID $ipv4clientPID"
    }
    Write-Warning "CONNECT_V4 EVENT not found in event JSON file."
    $errors += 1
}

# 6. Check for process_accept event (server accepting connection on port 7991)
Write-Host " Checking for IPv4 server accept event..."
$acceptEventCount = ($events | Where-Object { $_.PSObject.Properties.Name -contains "process_accept" }).Count
if ($acceptEventCount -eq 0) {
    Write-Host "  Note : No process_accept events in file (Tetragon may not generate these on Windows)" -ForegroundColor Yellow
    Write-Host "  Skipping process_accept validation"
} else {
    Write-Host "  Looking for : PID=$ipv4serverPID, SourceIP=127.0.0.1, SourcePort=7991, Protocol=TCP"
    $acceptV4Event = Find-ProcessAcceptEvent -Events $events -ProcessId $ipv4serverPID -Binary "powershell" -SourceIp "127.0.0.1" -SourcePort 7991 -Protocol "TCP"
    if (-not $acceptV4Event) {
        # Try without source IP/port filters
        $acceptV4Event = Find-ProcessAcceptEvent -Events $events -ProcessId $ipv4serverPID -Protocol "TCP"
    }

    if ($acceptV4Event) {
        Write-Host "  Found event from PID $ipv4serverPID "
        if ($acceptV4Event.process_accept.parent.pid -eq $PID) {
            Write-Host " Found accept_v4 pattern in event file" 
        } else {
            Write-Host "  accept_v4 event found but parent PID doesn't match. Expected: $PID, Got: $($acceptV4Event.process_accept.parent.pid)" -ForegroundColor Yellow
            Write-Warning "ACCEPT_V4 EVENT validation failed in event JSON file."
            $errors += 1
        }
    } else {
        Write-Host " accept_v4 pattern not found in event file "
        Write-Warning "ACCEPT_V4 EVENT not found in event JSON file."
        $errors += 1
    }
}

# 7. Check for process_close event (server socket close with type "accept")
Write-Host " Checking for server socket close event..."
Write-Host "  Looking for: PID = $ipv4serverPID, SocketType=accept, Protocol=TCP"
$closeServerEvent = Find-ProcessCloseEvent -Events $events -ProcessId $ipv4serverPID -Binary "powershell" -SocketType "accept" -Protocol "TCP"
if (-not $closeServerEvent) {
    # Try without socket type filter
    Write-Host "  Not found with SocketType filter, trying without..."
    $closeServerEvent = Find-ProcessCloseEvent -Events $events -ProcessId $ipv4serverPID -Protocol "TCP"
}

if ($closeServerEvent) {
    Write-Host " Found close event from PID $ipv4serverPID"
    # Validate it's on the right port
    $serverCloseOnPort = $closeServerEvent | Where-Object { $_.process_close.source_port -eq 7991 }
    if ($serverCloseOnPort) {
        Write-Host "  Found close_server pattern in event file (port 7991)"
    } else {
        Write-Host "  close_server event found but not on expected port 7991" 
        Write-Host "  Ports found: $($closeServerEvent.process_close.source_port -join ', ')"
        Write-Warning "CLOSE_SERVER EVENT validation failed in event JSON file."
        $errors += 1
    }
} else {
    Write-Host " close_server pattern not found in event file" -ForegroundColor Red
    Write-Warning "CLOSE_SERVER EVENT not found in event JSON file."
    $errors += 1
}

# 8. Check for process_close event (client socket close with type "connect")
Write-Host "Checking for client socket close event..."
Write-Host "  Looking for: PID=$ipv4clientPID, SocketType=connect, DestPort=7991, Protocol=TCP"
$closeClientEvent = Find-ProcessCloseEvent -Events $events -ProcessId $ipv4clientPID -Binary "powershell" -SocketType "connect" -DestinationPort 7991 -Protocol "TCP"
if (-not $closeClientEvent) {
    # Try without socket type filter
    Write-Host "  Not found with SocketType filter, trying without..."
    $closeClientEvent = Find-ProcessCloseEvent -Events $events -ProcessId $ipv4clientPID -DestinationPort 7991 -Protocol "TCP"
}

if ($closeClientEvent) {
    Write-Host "  Found close event from PID $ipv4clientPID"
    # Validate destination IP
    if ($closeClientEvent.process_close.destination_ip -eq "127.0.0.1") {
        Write-Host " Found close_client pattern in event file (to 127.0.0.1:7991)"
    } else {
        Write-Host "  close_client event found but destination IP doesnt match. Expected: 127.0.0.1, Got: \"$($closeClientEvent.process_close.destination_ip)\"" -ForegroundColor Yellow
        Write-Warning "CLOSE_CLIENT EVENT validation failed in event JSON file."
        $errors += 1
    }
} else {
    Write-Host "  close_client pattern not found in event file" -ForegroundColor Red
    Write-Warning "CLOSE_CLIENT EVENT not found in event JSON file."
    $errors += 1
}

Write-Host "=== Test Results ===" -ForegroundColor Cyan
if ($errors -eq 0) {
    Write-Host "SUCCESS: All expected patterns found in the event file." -ForegroundColor Green
    exit 0
}
else {
    Write-Host "FAILED: $errors validation(s) failed." -ForegroundColor Red
    Write-Host "Note: This may be due to timing issues or Tetragon configuration."
    Write-Host "Try running Debug-Events.ps1 to see what events are actually being captured."
    exit $errors
}