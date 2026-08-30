# process_connect, process_accept and process_close over loopback TCP, plus the exec
# of the PowerShell probe that produces them.
#
# Needs the TCP sensor, so it only ships in a build that has one.
#
# Both ends run under $s.PowershellExe rather than pwsh: that is the binary the
# datapath is configured against elsewhere in this suite, and keeping every network
# probe on it means one process.binary value covers them all.

$here = $PSScriptRoot

@{
    Name = 'network'

    State = @{
        ProbeScript = [System.IO.Path]::GetFullPath((Join-Path $here '..\probes\network.ps1'))
        Port        = 7991
    }

    Flags = [ordered]@{
        '--enable-tcp' = $true
    }

    Probe = { param($s)
        $server = Start-Probe -State $s -ProbeArgs @('-Role', 'server', '-Port', $s.Port)
        $s.Server = $server
        Wait-Until -TimeoutSeconds $s.ProbeTimeoutSeconds -What "the probe server to listen on $($s.Port)" -Condition {
            if ($server.HasExited) { throw "probe server exited early with code $($server.ExitCode)" }
            # Pure .NET rather than Get-NetTCPConnection: no CIM/WMI dependency.
            [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().
                GetActiveTcpListeners().Port -contains $s.Port
        }
        Write-Host "probe: server pid $($server.Id) listening on 127.0.0.1:$($s.Port)"

        $client = Start-Probe -State $s -ProbeArgs @('-Role', 'client', '-Port', $s.Port)
        $s.Client = $client
        Wait-Until -TimeoutSeconds $s.ProbeTimeoutSeconds -What 'the probe client to exit' -Condition { $client.HasExited }
        Wait-Until -TimeoutSeconds $s.ProbeTimeoutSeconds -What 'the probe server to exit' -Condition { $server.HasExited }
        Write-Host "probe: client pid $($client.Id) exited with code $($client.ExitCode)"
    }

    Expect = { param($s)
        [ordered]@{
            # process_connect fires pre-bind, so its source_ip is 0.0.0.0 and only the
            # destination is worth asserting on. process_close carries the real
            # addresses on both sides.
            'exec-client'   = { param($ev, $s)
                $ev.process_exec -and
                $ev.process_exec.process.pid -eq $s.Client.Id -and
                (Test-Binary $ev.process_exec.process.binary $s.PowershellExe) -and
                $ev.process_exec.process.uid -eq $s.Uid -and
                $ev.process_exec.parent.pid -eq $s.HarnessPid
            }
            'connect'       = { param($ev, $s)
                $ev.process_connect -and
                $ev.process_connect.process.pid -eq $s.Client.Id -and
                (Test-Binary $ev.process_connect.process.binary $s.PowershellExe) -and
                $ev.process_connect.process.uid -eq $s.Uid -and
                $ev.process_connect.parent.pid -eq $s.HarnessPid -and
                $ev.process_connect.protocol -eq 'TCP' -and
                $ev.process_connect.destination_ip -eq '127.0.0.1' -and
                $ev.process_connect.destination_port -eq $s.Port
            }
            'close-connect' = { param($ev, $s)
                $ev.process_close -and
                $ev.process_close.process.pid -eq $s.Client.Id -and
                (Test-Binary $ev.process_close.process.binary $s.PowershellExe) -and
                $ev.process_close.process.uid -eq $s.Uid -and
                $ev.process_close.protocol -eq 'TCP' -and
                $ev.process_close.socket_type -eq 'connect' -and
                $ev.process_close.destination_ip -eq '127.0.0.1' -and
                $ev.process_close.destination_port -eq $s.Port
            }
            'accept'        = { param($ev, $s)
                $ev.process_accept -and
                $ev.process_accept.process.pid -eq $s.Server.Id -and
                (Test-Binary $ev.process_accept.process.binary $s.PowershellExe) -and
                $ev.process_accept.process.uid -eq $s.Uid -and
                $ev.process_accept.parent.pid -eq $s.HarnessPid -and
                $ev.process_accept.protocol -eq 'TCP' -and
                $ev.process_accept.source_ip -eq '127.0.0.1' -and
                $ev.process_accept.source_port -eq $s.Port
            }
            'close-accept'  = { param($ev, $s)
                $ev.process_close -and
                $ev.process_close.process.pid -eq $s.Server.Id -and
                (Test-Binary $ev.process_close.process.binary $s.PowershellExe) -and
                $ev.process_close.process.uid -eq $s.Uid -and
                $ev.process_close.protocol -eq 'TCP' -and
                $ev.process_close.socket_type -eq 'accept' -and
                $ev.process_close.source_port -eq $s.Port
            }
        }
    }
}
