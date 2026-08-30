# powershell_script_block, from Event ID 4104.
#
# Needs the PowerShell sensor, so it only ships in a build that has one. No flag: the
# sensor is always on where it exists.
#
# Nothing external enables the logging policy -- Tetragon does it itself, writing
# HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging before it
# subscribes. So this check works on a bare machine and transitively proves Tetragon set
# the policy. Two ordering hazards follow, both handled by the readiness marker below:
# the subscription is a callback that only sees 4104s raised after it attaches, and
# PowerShell reads the logging policy at process start.
#
# The subscriber covers the Windows PowerShell channel only, so the probe has to be
# powershell.exe. A marked block from pwsh raises no 4104 on any channel.

$here = $PSScriptRoot

@{
    Name = 'powershell'

    State = @{
        ProbeScript = [System.IO.Path]::GetFullPath((Join-Path $here '..\probes\powershell.ps1'))

        # The probe emits a runtime script block carrying exactly this text. It is not
        # the probe's own file text: PowerShell was observed not to log that.
        Marker      = 'tetragon-smoke-probe'
    }

    # On stderr, from startPowershellSubscriber(). Gated on separately from the
    # observer's own marker because this subscriber comes up independently of it.
    Ready = @(
        @{ Stream = 'stderr'; Text = 'Tailing Microsoft-Windows-PowerShell/Operational' }
    )

    Probe = { param($s)
        $probe = Start-Probe -State $s -ProbeArgs @('-Marker', $s.Marker)
        $s.Probe = $probe
        Wait-Until -TimeoutSeconds $s.ProbeTimeoutSeconds -What 'the script block probe to exit' -Condition {
            $probe.HasExited
        }
        Write-Host "probe: script block pid $($probe.Id) exited with code $($probe.ExitCode)"
    }

    Expect = { param($s)
        [ordered]@{
            # No assertion on the event's time: powershell_script_block events have been
            # seen carrying a garbage one (year 7267).
            'script-block' = { param($ev, $s)
                $ev.powershell_script_block -and
                $ev.powershell_script_block.process.pid -eq $s.Probe.Id -and
                (Test-Binary $ev.powershell_script_block.process.binary $s.PowershellExe) -and
                $ev.powershell_script_block.process.uid -eq $s.Uid -and
                $ev.powershell_script_block.payload -like "*$($s.Marker)*"
            }
        }
    }
}
