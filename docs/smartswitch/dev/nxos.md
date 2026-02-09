# NX-OS Developer Docs

Developer-facing notes for working with NX-OS in the SmartSwitch environment in the context of AGW.

## Table of Contents

- [gNMI](#gnmi)
  - [Generate the Go Model From YANG](#generate-the-go-model-from-yang)
  - [Manually Interact With NX-OS via gnmic CLI](#manually-interact-with-nx-os-via-gnmic-cli)

## gNMI

### Generate the Go Model From YANG

Build the gNMI model file from the NX-OS YANG model:

```text
gnmi/ygot/generator/generator -generate_simple_unions -output_file=Cisco-NX-OS-device.go -package_name=model Cisco-NX-OS-device.yang
```

Before generating the Go file, apply `yang-model.diff` to the original YANG model.

- **Issue**: `ch-items` is missing in `iso-group`, but it exists in the original YANG model.
- **Fix**: Paste it into `iso-group` in the same way other items are included.

### Manually Interact With NX-OS via gnmic CLI

Example `gnmic` commands to interact with NX-OS gNMI endpoints:

Get:

```bash
gnmic -a $NX_GRPC_IP:$NX_GRPC_PORT -u $NX_GRPC_USER -p $NX_GRPC_PASS --skip-verify --gzip get --path '/System/serviceredir-items/inst-items/service-items'
```

Delete (via `set --delete`):

```bash
gnmic -a $NX_GRPC_IP:$NX_GRPC_PORT -u $NX_GRPC_USER -p $NX_GRPC_PASS --skip-verify --gzip set --delete '/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicystate-items'
```

Set with a file:

Create a file on disk, for example `/tmp/update.json`:

```json
{        
   "pkgAction": "deactivate",
   "url" : "dpu_fw-1.7.13-10.5.3s.x86_64.rpm",
   "isProcessed" : "0"
}
```

Apply it using `--update-file`:

```bash
gnmic -a $NX_GRPC_IP:$NX_GRPC_PORT -u $NX_GRPC_USER -p $NX_GRPC_PASS --skip-verify --gzip set --update-path '/System/swpkgs-items/rpmaction-items' --update-file /tmp/update.json
```
