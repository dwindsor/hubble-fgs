# KinD Testing Helpers

This directory contains scripts to facilitate running FGS locally in a KinD cluster.
It requires Docker and KinD to be installed on the host system. One easy way to get such
an environment up and running is to use the scripts in contrib/kvm.

## Quick Start

1. Ensure that Docker and KinD are installed and configured correctly.
2. Run `contrib/end-to-end/bootstrap-cluster.sh` to bring up a k8s cluster.
3. Run `contrib/end-to-end/install-fgs.sh` to install a local development version of FGS into the cluster.
