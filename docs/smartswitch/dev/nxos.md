# NX-OS Developer Docs

Developer-facing notes for working with NX-OS in the SmartSwitch environment in the context of AGW.

## Table of Contents

- [gNMI](#gnmi)
  - [Generate the Go Model From YANG](#generate-the-go-model-from-yang)
  - [Manually Interact With NX-OS via gnmic CLI](#manually-interact-with-nx-os-via-gnmic-cli)

## gNMI

### Generate the Go Model From YANG

Clone the ygot repo (needed to generate the YANG model):

```bash
git clone https://github.com/openconfig/ygot
cd ygot
```

Copy the below diff to changes.patch

```diff
diff --git a/Cisco-NX-OS-device.yang b/Cisco-NX-OS-device.yang
index d358ded41..d0d5625ec 100644
--- a/Cisco-NX-OS-device.yang
+++ b/Cisco-NX-OS-device.yang
@@ -228865,11 +228865,76 @@ module Cisco-NX-OS-device {
         }
     }

+    grouping iso-group {
+        container sas-items {
+            uses sas_Sas-group;
+            description "Instance node for managing SAS";
+        }
+
+        // Overlay instance object
+        container inst-items {
+            list Inst-list {
+                key "name";
+
+                uses l3_Inst-group;
+                description "Overlay Instance list";
+            }
+            description "Overlay Instance";
+        }
+
+        // Install RPM Packages in the system
+        container swpkgs-items {
+
+            uses swpkgs_Install-group;
+            description "Software packages Install";
+        }
+
+        // Container for all the BDs in the system.
+        container bd-items {
+
+            uses bd_Entity-group;
+            description "System BD";
+        }
+
+        container serviceredir-items {
+
+            uses epbr_SvcEntity-group;
+            description "DPU Service Redirection Entity";
+        }
+
+        // Holds ACL control plane configuration
+        container acl-items {
+
+            uses acl_Entity-group;
+            description "Entity of the Access Control List";
+        }
+
+        // Hardware chassis container
+        container ch-items {
+
+            uses eqpt_Ch-group;
+            description "The hardware chassis information container";
+        }
+
+        // Extension chassis
+        container extch-items {
+            list ExtCh-list {
+                config "false";
+                key "id";
+
+                uses eqpt_ExtCh-group;
+                description "FEX list";
+            }
+            description "FEX";
+        }
+    }
+
     container System {
         description "General information about this system";

-        uses System-group;
+        uses iso-group;
     }
+
 //
 // Copyright 2015-2024 Cisco Systems Inc.
 // All rights reserved.
```

```bash
# Copy and rename the Cisco-NX-OS-device.stripped YANG file to Cisco-NX-OS-device.yang in the current directory before applying.
# The patch targets Cisco-NX-OS-device.yang in the current directory.
# Apply the patch
patch -p1 < changes.patch
```

Build the gNMI model file from the patched NX-OS YANG model:

```bash
go run ./generator/generator.go -generate_simple_unions -output_file=Cisco-NX-OS-device.go -package_name=model Cisco-NX-OS-device.yang
```

Copy the new generated go file into `pkg/nxosmodel` package, make sure it builds, and commit the changes:

```bash
mv Cisco-NX-OS-device.go ../hubble-fgs/pkg/nxosmodel/
GOOS=linux GOARCH=amd64 make agw
```

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
