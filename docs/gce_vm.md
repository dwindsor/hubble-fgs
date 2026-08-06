# Provisioning a GCE VM for development use

If you need a dedicated development box follow these steps to provision one on
Google Compute Engine. This is helpful if you primarily use a Mac device with
Apple Silicon and need to build `x86_64` binaries in a reasonable amount of
time and/or want to contain your development to a remote machine instead.

* Log in to the [Google Cloud Console](https://console.cloud.google.com/) with your `<username>@cisco.com` account
* Create the new VM under the `isovalent-dev` project
* Add the labels required by [Cisco Cloud Security](https://app.notion.com/p/isovalent/Cisco-Transition-13f6072da09980aea614f90365a8fbff?p=22c6072da0998091b4ced4608ae54ebd&pm=c).
* To ssh in you’ll need to create a firewall policy to allow 22 from your local IP ranges.
  * Add a Network tag to your VM: `is-<userid>-instance`
  * Create a [VPC firewall rule](https://console.cloud.google.com/net-security/firewall-manager/firewall-policies/list).
    * The rule should allow traffic to `tcp:22` from the IP ranges you'll access the host from. One suggestion is to use the IP ranges from Cisco's VPN if you work from multiple locations.
    * Apply the rule to any VMs with the `is-<userid>-instance` tag.
* A common use case is to run the VM only as needed - this reduces the cost and you don’t need to install the Cisco security tooling if uptime stays under 3 days.
  * Look at the [contrib/manage_gce_vm.sh](../contrib/manage_gce_vm.sh) script to help manage the VM. It works well to stop/start/grow/shrink the instance, as well as update your local `ssh/config` with the new IP address each time it starts.
  * A nightly cron job to shut off the VM is helpful to stop the instance if it's accidentally left running
