# Network policy enforcement: a connect the policy denies must fail, and must leave no
# trace in the event stream.
#
# Needs network policy support, so it only ships in a build that has it. The policy
# file it loads is the reason the probe runs under $s.PowershellExe: that policy names
# that binary by full path, so pwsh is not subject to it, and a deny observed under
# pwsh would have some other cause.
#
# A denied connect emits no process_connect at all -- the policy rejects before the
# event is exported -- so blocking is asserted twice, both as absences:
#
#   no-connect-denied  no process_connect to the denied ip
#   enforcement        the request itself did not succeed (the probe's exit code)
#
# connect-allowed on 443 is the reachability control that gives both their meaning:
# with no route out of the machine, a denied connect and an unreachable one are
# indistinguishable.
#
# The denied ip, its port and the allowed url are coupled to $PolicyFile, whose deny
# rule covers 142.250.217.78/24 over TCP and nothing else. They live here, next to the
# policy path, so the policy and the urls that exercise it cannot drift apart.

$here = $PSScriptRoot
$policy = [System.IO.Path]::GetFullPath(
    (Join-Path $here '..\..\..\..\examples\tetragonnetworkpolicy\windows\example.yaml'))

@{
    Name = 'netpolicy'

    State = @{
        ProbeScript = [System.IO.Path]::GetFullPath((Join-Path $here '..\probes\netpolicy.ps1'))
        PolicyFile  = $policy
        AllowedUrl  = 'https://www.google.com'
        AllowedPort = 443
        DeniedIp    = '142.250.217.78'
        DeniedPort  = 80
    }

    Flags = [ordered]@{
        # Network policies are rejected at startup without the TCP sensor.
        '--enable-tcp'                = $true

        # Without it the endpoint cache is a FakeCache whose AddIpServiceMap is not
        # implemented, so loading this policy's CIDR rule fails and Tetragon exits
        # ("failed to add endpoint for record ... cidr(142.250.217.78/24)"). Not caught
        # by flag validation -- it surfaces only when the policy is loaded.
        '--enable-application-model'  = $true

        '--network-policy'            = $policy
    }

    Probe = { param($s)
        Write-Host "policy: $($s.PolicyFile)"
        $probe = Start-Probe -State $s -ProbeArgs @(
            '-AllowedUrl', $s.AllowedUrl
            '-DeniedUrl', "http://$($s.DeniedIp):$($s.DeniedPort)"
        )
        $s.Probe = $probe
        Wait-Until -TimeoutSeconds $s.ProbeTimeoutSeconds -What 'the url probe to exit' -Condition { $probe.HasExited }
        Write-Host "probe: url checks pid $($probe.Id) exited with code $($probe.ExitCode)"
    }

    Expect = { param($s)
        [ordered]@{
            'connect-allowed' = { param($ev, $s)
                $ev.process_connect -and
                $ev.process_connect.process.pid -eq $s.Probe.Id -and
                (Test-Binary $ev.process_connect.process.binary $s.PowershellExe) -and
                $ev.process_connect.process.uid -eq $s.Uid -and
                $ev.process_connect.parent.pid -eq $s.HarnessPid -and
                $ev.process_connect.protocol -eq 'TCP' -and
                $ev.process_connect.destination_port -eq $s.AllowedPort
            }
        }
    }

    # Sound only because the probe attempts the denied endpoint before the allowed one:
    # matching connect-allowed means the stream has been read past the point where a
    # denied connect would have appeared. Reorder the probe's two requests and this
    # check silently becomes vacuous.
    Forbid = { param($s)
        [ordered]@{
            'no-connect-denied' = @{
                Test = { param($ev, $s)
                    $ev.process_connect -and
                    $ev.process_connect.process.pid -eq $s.Probe.Id -and
                    $ev.process_connect.destination_ip -eq $s.DeniedIp
                }
                Why  = 'An event that must not exist was exported: a process_connect from ' +
                "the url probe to $($s.DeniedIp), which $($s.PolicyFile) denies for that binary."
            }
        }
    }

    Verify = { param($s)
        # The probe's exit code is the number of its url checks that failed.
        @(@{
                Name     = 'enforcement'
                Failures = $s.Probe.ExitCode
                Detail   = "$($s.Probe.ExitCode) url check(s) failed, see probe output above"
                Why      = "$($s.Probe.ExitCode) of the url probe's checks failed: either " +
                "http://$($s.DeniedIp):$($s.DeniedPort) was reachable despite the policy, or " +
                "$($s.AllowedUrl) was not reachable at all. The probes group in this log says which."
            })
    }
}
