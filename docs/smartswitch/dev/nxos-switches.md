# NX-OS Switch Procedures (SmartSwitch)

This document is a quick operational reference for common Cisco NX-OS tasks used in SmartSwitch development and bring-up.

## Table of Contents

- [NX-OS Service Bring-up (Hypershield)](#nx-os-service-bring-up-hypershield)
- [Artifacts (Artifactory)](#artifacts-artifactory)
  - [Artifact Locations](#artifact-locations)
  - [Artifactory Token](#artifactory-token)
  - [Download Artifacts to a Switch](#download-artifacts-to-a-switch)
  - [Upload Artifacts to Artifactory](#upload-artifacts-to-artifactory)
- [Install / Upgrade](#install--upgrade)
  - [Install Latest NX-OS Image](#install-latest-nx-os-image)
  - [Install Hypershield Agent RPM](#install-hypershield-agent-rpm)
  - [Install DPU Firmware RPM](#install-dpu-firmware-rpm)
- [VRF Configuration](#vrf-configuration)
  - [Add Global VRF](#add-global-vrf)
  - [Remove Global VRF](#remove-global-vrf)
  - [Add Service VRF (Hypershield / Firewall)](#add-service-vrf-hypershield--firewall)
  - [Remove Service VRF](#remove-service-vrf)
- [File Transfer](#file-transfer)
  - [Enable SCP/SFTP Server Features](#enable-scpsftp-server-features)
  - [Copy a File to /bootflash](#copy-a-file-to-bootflash)
- [High Availability (HA)](#high-availability-ha)

## NX-OS Service Bring-up (Hypershield)

The sequence below is the typical bring-up flow for Hypershield services on the switch.

```text
config t
feature service-acceleration
service system hypershield
service firewall
in-service
```

## Artifacts (Artifactory)

Use Artifactory for agent/DPU RPMs and tar images.

### Artifact Locations

Dev key signed RPMs:

- Agent RPMs: https://artifactory.devhub-cloud.cisco.com/ui/repos/tree/General/isovalent-hs-nxos-codedrop-generic/agent
- DPU RPMs: https://artifactory.devhub-cloud.cisco.com/ui/repos/tree/General/isovalent-hs-nxos-codedrop-generic/dpu

Tar files:

- AGW tar files: https://artifactory.devhub-cloud.cisco.com/ui/repos/tree/General/isovalent-images-generic/smartswitch/agw
- FWA tar files: https://artifactory.devhub-cloud.cisco.com/ui/repos/tree/General/isovalent-images-generic/smartswitch/fwa
- Pensando tar files: https://artifactory.devhub-cloud.cisco.com/ui/repos/tree/General/isovalent-images-generic/pensando

### Artifactory Token

General development artifactory username and login credentials can be found in [Keeper](https://keeper.cisco.com/ui/vault/secrets/secret/kv/gitops%2Fisocopy-artifactory-creds/details?namespace=eticloud%2Fapps%2Fhypershield&version=1).  You can also create your own token following the instructions below (90 day expiration):

1. Open https://artifactory.devhub-cloud.cisco.com
2. Click **SAML SSO** to log in.
3. Click your user icon (top right) and open **Edit Profile**.
4. Generate an **Identity Token**.

Treat the token like a password. Do not commit it to git and do not paste it into shared docs/logs.

### Download Artifacts to a Switch

If you need to download directly to the switch:

1. `run bash sudo su`
2. `cd /bootflash/`
3. Use `curl` with the Cisco proxy and Artifactory credentials.  It is easiest to copy the download URL for the specific rpm version directly from the artifactory page.

Example:

```bash
export CEC_USER="<your-username>"
export ARTIFACTORY_TOKEN="<your-identity-token>"

curl -fL -x http://proxy.esl.cisco.com:80 -u "${CEC_USER}:${ARTIFACTORY_TOKEN}" -O "https://artifactory.devhub-cloud.cisco.com/artifactory/isovalent-hs-nxos-codedrop-generic/agent/<version>/<build>/agent-<version>-<nxos>.x86_64.rpm"
curl -fL -x http://proxy.esl.cisco.com:80 -u "${CEC_USER}:${ARTIFACTORY_TOKEN}" -O "https://artifactory.devhub-cloud.cisco.com/artifactory/isovalent-hs-nxos-codedrop-generic/dpu/<version>/<build>/dpu_fw-<version>-<nxos>.x86_64.rpm"
```

### Upload Artifacts to Artifactory

To upload an artifact to Artifactory (like an NX version), ADS has the JFrog CLI already available in `/auto/hypershield/tools/bin`.  Use the below CLI and your access token generated above:

```bash
brilong@sjc-ads-6172 [~]$ jf rt u --flat=true --server-id=devhub /auto/ins-bld-tools/branches/nx_main/nexus/COV_10_6_2_IMG9_0_172/nx/standalone/build/images/final/nxos64-s1-dpu.10.6.2.IMG9.0.172.F.bin isovalent-images-generic/hypershield/nxos/10.6.2/nxos64-s1-dpu.10.6.2.IMG9.0.172.F.bin

jf config show
Server ID:			devhub
JFrog Platform URL:		https://artifactory.devhub-cloud.cisco.com/
Artifactory URL:		https://artifactory.devhub-cloud.cisco.com/artifactory/
Distribution URL:		https://artifactory.devhub-cloud.cisco.com/distribution/
Xray URL:			https://artifactory.devhub-cloud.cisco.com/xray/
Mission Control URL:		https://artifactory.devhub-cloud.cisco.com/mc/
Pipelines URL:			https://artifactory.devhub-cloud.cisco.com/pipelines/
User:				brilong
Access token:			***
Default:			true
```

## Install / Upgrade

Make sure all images are copied to `/bootflash/` (bash) or `bootflash:` (NX-OS CLI) before installing.

### Install Latest NX-OS Image

```bash
copy http://hs-p8-04/~acam/latest_nxos bootflash:nxos.bin vrf management use-kstack
install all nxos bootflash:nxos.bin
```

### Install Hypershield Agent RPM

Download the RPM (see [Download Artifacts on the Switch (curl)](#download-artifacts-on-the-switch-curl)), then install it:

```bash
install add bootflash:agent-<version>-<nxos>.x86_64.rpm activate
```

### Install DPU Firmware RPM

Download the RPM (see [Download Artifacts on the Switch (curl)](#download-artifacts-on-the-switch-curl)), then install it:

```bash
install add bootflash:dpu_fw-<version>-<nxos>.x86_64.rpm activate
```

## VRF Configuration

### Add Global VRF

```text
config t
vrf context red
```

### Remove Global VRF

```text
config t
no vrf context red
```

### Add Service VRF (Hypershield / Firewall)

This configures the Hypershield / firewall service context to use a service VRF.

```text
config t
service system hypershield
service firewall
vrf red module-affinity dynamic
```

### Remove Service VRF

```text
config t
service system hypershield
service firewall
no vrf red
```

## File Transfer

### Enable SCP/SFTP Server Features

Enable the NX-OS features that allow inbound SCP/SFTP to the switch.

```text
config t
feature sftp-server
feature scp-server
```

### Copy a File to /bootflash

From a machine that can reach the switch management interface:

```text
scp -o PubkeyAuthentication=no {file} admin@{switch-ip}:/bootflash/
```

## High Availability (HA)

Configure Hypershield HA settings.

```text
config t
service system hypershield
high-availability
source-interface loopback93
peer 172.31.251.92
no shutdown
```

To change the peer, remove it first and then re-add it.

```text
config t
service system hypershield
high-availability
no peer 172.31.251.92
peer 172.31.251.92
```
