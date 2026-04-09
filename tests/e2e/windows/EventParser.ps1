# EventParser.ps1
# PowerShell module for parsing and validating Tetragon event JSON files

<#
.SYNOPSIS
    Reads and parses Tetragon events from a JSON Lines file.

.DESCRIPTION
    Reads a file where each line contains a separate JSON object (JSON Lines format)
    and parses them into PowerShell objects for easier validation.

.PARAMETER FilePath
    Path to the events.json file to parse.

.EXAMPLE
    $events = Get-TetragonEvents -FilePath "C:\Program Files\Tetragon\events.json"
#>
function Get-TetragonEvents {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    if (-not (Test-Path $FilePath)) {
        throw "Events file not found: $FilePath"
    }

    $events = @()
    Get-Content -Path $FilePath | ForEach-Object {
        $line = $_.Trim()
        if ($line -and $line -ne "") {
            try {
                $events += $_ | ConvertFrom-Json
            }
            catch {
                Write-Warning "Failed to parse JSON line: $_"
            }
        }
    }

    Write-Verbose "Parsed $($events.Count) events from $FilePath"
    return $events
}

<#
.SYNOPSIS
    Helper function to get nested property values from an object.

.DESCRIPTION
    Navigates through nested object properties using dot notation.

.PARAMETER Object
    The object to query.

.PARAMETER PropertyPath
    Dot-separated path to the property (e.g., "process_exec.process.pid").

.EXAMPLE
    $pid = Get-NestedProperty -Object $event -PropertyPath "process_exec.process.pid"
#>
function Get-NestedProperty {
    param(
        [object]$Object,
        [string]$PropertyPath
    )

    $current = $Object
    $parts = $PropertyPath -split '\.'

    foreach ($part in $parts) {
        if ($null -eq $current) {
            return $null
        }

        if ($current.PSObject.Properties.Name -contains $part) {
            $current = $current.$part
        }
        else {
            return $null
        }
    }

    return $current
}

<#
.SYNOPSIS
    Finds process_exec events matching the specified criteria.

.PARAMETER Events
    Array of parsed event objects.

.PARAMETER ProcessId
    Process ID to match.

.PARAMETER Binary
    Binary path to match (supports wildcards).

.PARAMETER Uid
    User ID to match (optional).

.EXAMPLE
    $execEvent = Find-ProcessExecEvent -Events $events -ProcessId 1234 -Binary "notepad.exe"
#>
function Find-ProcessExecEvent {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Events,
        [int]$ProcessId,
        [string]$Binary,
        [int]$Uid = -1
    )

    return $Events | Where-Object {
        $_.PSObject.Properties.Name -contains "process_exec" -and
        $_.process_exec.process.pid -eq $ProcessId -and
        $_.process_exec.process.binary -like "*$Binary*" -and
        ($Uid -eq -1 -or $_.process_exec.process.uid -eq $Uid)
    }
}

<#
.SYNOPSIS
    Finds process_exit events matching the specified criteria.

.PARAMETER Events
    Array of parsed event objects.

.PARAMETER ProcessId
    Process ID to match.

.PARAMETER Binary
    Binary path to match (supports wildcards).

.EXAMPLE
    $exitEvent = Find-ProcessExitEvent -Events $events -ProcessId 1234 -Binary "notepad.exe"
#>
function Find-ProcessExitEvent {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Events,
        [int]$ProcessId,
        [string]$Binary,
        [int]$Uid = -1
    )

    return $Events | Where-Object {
        $_.PSObject.Properties.Name -contains "process_exit" -and
        $_.process_exit.process.pid -eq $ProcessId -and
        $_.process_exit.process.binary -like "*$Binary*" -and
        ($Uid -eq -1 -or $_.process_exit.process.uid -eq $Uid)
    }
}

<#
.SYNOPSIS
    Finds process_connect events matching the specified criteria.

.PARAMETER Events
    Array of parsed event objects.

.PARAMETER ProcessId
    Process ID to match.

.PARAMETER Binary
    Binary path to match (supports wildcards).

.PARAMETER DestinationIp
    Destination IP address to match (optional).

.PARAMETER DestinationPort
    Destination port to match (optional).

.EXAMPLE
    $connectEvent = Find-ProcessConnectEvent -Events $events -ProcessId 1234 -DestinationPort 443
#>
function Find-ProcessConnectEvent {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Events,
        [int]$ProcessId = -1,
        [string]$Binary,
        [string]$DestinationIp,
        [int]$DestinationPort = -1,
        [string]$Protocol
    )

    return $Events | Where-Object {
        $hasEvent = $_.PSObject.Properties.Name -contains "process_connect"
        $pidMatch = ($ProcessId -eq -1 -or $_.process_connect.process.pid -eq $ProcessId)
        $binaryMatch = ([string]::IsNullOrEmpty($Binary) -or $_.process_connect.process.binary -like "*$Binary*")
        $ipMatch = ([string]::IsNullOrEmpty($DestinationIp) -or $_.process_connect.destination_ip -eq $DestinationIp)
        $portMatch = ($DestinationPort -eq -1 -or $_.process_connect.destination_port -eq $DestinationPort)
        $protocolMatch = ([string]::IsNullOrEmpty($Protocol) -or $_.process_connect.protocol -eq $Protocol)

        $hasEvent -and $pidMatch -and $binaryMatch -and $ipMatch -and $portMatch -and $protocolMatch
    }
}

<#
.SYNOPSIS
    Finds process_accept events matching the specified criteria.

.PARAMETER Events
    Array of parsed event objects.

.PARAMETER ProcessId
    Process ID to match.

.PARAMETER SourceIp
    Source IP address to match (optional).

.PARAMETER SourcePort
    Source port to match (optional).

.EXAMPLE
    $acceptEvent = Find-ProcessAcceptEvent -Events $events -ProcessId 1234 -SourcePort 7991
#>
function Find-ProcessAcceptEvent {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Events,
        [int]$ProcessId = -1,
        [string]$Binary,
        [string]$SourceIp,
        [int]$SourcePort = -1,
        [int]$DestinationPort = -1,
        [string]$Protocol
    )

    return $Events | Where-Object {
        $hasEvent = $_.PSObject.Properties.Name -contains "process_accept"
        $pidMatch = ($ProcessId -eq -1 -or $_.process_accept.process.pid -eq $ProcessId)
        $binaryMatch = ([string]::IsNullOrEmpty($Binary) -or $_.process_accept.process.binary -like "*$Binary*")
        $sourceIpMatch = ([string]::IsNullOrEmpty($SourceIp) -or $_.process_accept.source_ip -eq $SourceIp)
        $sourcePortMatch = ($SourcePort -eq -1 -or $_.process_accept.source_port -eq $SourcePort)
        $destPortMatch = ($DestinationPort -eq -1 -or $_.process_accept.destination_port -eq $DestinationPort)
        $protocolMatch = ([string]::IsNullOrEmpty($Protocol) -or $_.process_accept.protocol -eq $Protocol)

        $hasEvent -and $pidMatch -and $binaryMatch -and $sourceIpMatch -and $sourcePortMatch -and $destPortMatch -and $protocolMatch
    }
}

<#
.SYNOPSIS
    Finds process_close events matching the specified criteria.

.PARAMETER Events
    Array of parsed event objects.

.PARAMETER ProcessId
    Process ID to match.

.PARAMETER Binary
    Binary path to match (supports wildcards).

.PARAMETER SocketType
    Socket type to match (e.g., "connect", "accept").

.EXAMPLE
    $closeEvent = Find-ProcessCloseEvent -Events $events -ProcessId 1234 -SocketType "connect"
#>
function Find-ProcessCloseEvent {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Events,
        [int]$ProcessId = -1,
        [string]$Binary,
        [string]$SocketType,
        [string]$DestinationIp,
        [int]$DestinationPort = -1,
        [string]$Protocol
    )

    return $Events | Where-Object {
        $hasEvent = $_.PSObject.Properties.Name -contains "process_close"
        $pidMatch = ($ProcessId -eq -1 -or $_.process_close.process.pid -eq $ProcessId)
        $binaryMatch = ([string]::IsNullOrEmpty($Binary) -or $_.process_close.process.binary -like "*$Binary*")
        $socketTypeMatch = ([string]::IsNullOrEmpty($SocketType) -or $_.process_close.socket_type -eq $SocketType)
        $ipMatch = ([string]::IsNullOrEmpty($DestinationIp) -or $_.process_close.destination_ip -eq $DestinationIp)
        $portMatch = ($DestinationPort -eq -1 -or $_.process_close.destination_port -eq $DestinationPort)
        $protocolMatch = ([string]::IsNullOrEmpty($Protocol) -or $_.process_close.protocol -eq $Protocol)

        $hasEvent -and $pidMatch -and $binaryMatch -and $socketTypeMatch -and $ipMatch -and $portMatch -and $protocolMatch
    }
}

<#
.SYNOPSIS
    Finds powershell_script_block events matching the specified criteria.

.PARAMETER Events
    Array of parsed event objects.

.PARAMETER ProcessId
    Process ID to match.

.PARAMETER Binary
    Binary path to match (supports wildcards).

.PARAMETER Payload
    Script block payload to search for (supports wildcards).

.PARAMETER Uid
    User ID to match (optional).

.EXAMPLE
    $scriptBlockEvent = Find-PowerShellScriptBlockEvent -Events $events -ProcessId 1234
#>
function Find-PowerShellScriptBlockEvent {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Events,
        [int]$ProcessId = -1,
        [string]$Binary,
        [string]$Payload,
        [int]$Uid = -1
    )

    return $Events | Where-Object {
        $hasEvent = $_.PSObject.Properties.Name -contains "powershell_script_block"
        $pidMatch = ($ProcessId -eq -1 -or $_.powershell_script_block.process.pid -eq $ProcessId)
        $binaryMatch = ([string]::IsNullOrEmpty($Binary) -or $_.powershell_script_block.process.binary -like "*$Binary*")
        $payloadMatch = ([string]::IsNullOrEmpty($Payload) -or $_.powershell_script_block.payload -like "*$Payload*")
        $uidMatch = ($Uid -eq -1 -or $_.powershell_script_block.uid -eq $Uid)

        $hasEvent -and $pidMatch -and $binaryMatch -and $payloadMatch -and $uidMatch
    }
}

<#
.SYNOPSIS
    Validates that an event has specific field values.

.PARAMETER Event
    The event object to validate.

.PARAMETER ExpectedFields
    Hashtable of field paths and expected values.

.EXAMPLE
    $isValid = Test-EventFields -Event $event -ExpectedFields @{
        "process_exec.process.pid" = 1234
        "process_exec.process.uid" = 1000
    }
#>
function Test-EventFields {
    param(
        [Parameter(Mandatory=$true)]
        [object]$Event,
        [Parameter(Mandatory=$true)]
        [hashtable]$ExpectedFields
    )

    foreach ($fieldPath in $ExpectedFields.Keys) {
        $expectedValue = $ExpectedFields[$fieldPath]
        $actualValue = Get-NestedProperty -Object $Event -PropertyPath $fieldPath

        if ($actualValue -ne $expectedValue) {
            Write-Verbose "Field mismatch: $fieldPath. Expected: $expectedValue, Actual: $actualValue"
            return $false
        }
    }

    return $true
}

<#
.SYNOPSIS
    Validates an event and reports detailed errors if validation fails.

.PARAMETER Event
    The event object to validate.

.PARAMETER EventType
    The type of event being validated (for error reporting).

.PARAMETER ExpectedFields
    Hashtable of field paths and expected values.

.EXAMPLE
    Assert-EventFields -Event $event -EventType "process_exec" -ExpectedFields @{...}
#>
function Assert-EventFields {
    param(
        [Parameter(Mandatory=$true)]
        [object]$Event,
        [Parameter(Mandatory=$true)]
        [string]$EventType,
        [Parameter(Mandatory=$true)]
        [hashtable]$ExpectedFields
    )

    $mismatches = @()

    foreach ($fieldPath in $ExpectedFields.Keys) {
        $expectedValue = $ExpectedFields[$fieldPath]
        $actualValue = Get-NestedProperty -Object $Event -PropertyPath $fieldPath

        if ($actualValue -ne $expectedValue) {
            $mismatches += [PSCustomObject]@{
                Field = $fieldPath
                Expected = $expectedValue
                Actual = $actualValue
            }
        }
    }

    if ($mismatches.Count -gt 0) {
        Write-Host "Field validation failures for $EventType event:" -ForegroundColor Red
        $mismatches | Format-Table -AutoSize | Out-String | Write-Host
        return $false
    }

    return $true
}

# Note: When dot-sourcing this script, all functions are automatically available.
# If converting to a module (.psm1), uncomment the line below:
# Export-ModuleMember -Function Get-TetragonEvents, Get-NestedProperty, Find-ProcessExecEvent, `
#     Find-ProcessExitEvent, Find-ProcessConnectEvent, Find-ProcessAcceptEvent, `
#     Find-ProcessCloseEvent, Test-EventFields, Assert-EventFields
