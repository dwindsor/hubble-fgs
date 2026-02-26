# SmartSwitch AGW & FWA Development Docs

General documentation for developers working on SmartSwitch.

## Logging into Artifactory

In order to build the AGW and FWA containers, you will need to log into artifactory to pull the base images.  Once you have created an artifactory token (see [NX-OS Switch Procedures (SmartSwitch)](nxos-switches.md)), you can log in below:

```
docker login https://artifactory.devhub-cloud.cisco.com
Username: <cec-id>
Password: <artifactory token>
```
