# Create AWS EKS clusters for tests

*This document originally comes from
[a comment](https://github.com/isovalent/hubble-fgs/issues/2478#issuecomment-1494385977)
on the arm64 support issue.*

## Create an EKS cluster

**You just want to create a cluster in which you don't need to create any
volumes.**

```shell
eksctl create cluster                                              \
    --name $CLUSTER_NAME                                           \
    --tags "usage=fgs-arm64-tests-troubleshooting,owner=$(whoami)" \
    --instance-selector-cpu-architecture arm64                     \
    --nodes 1                                                      \
    --instance-selector-vcpus 4                                    \
    --instance-selector-memory 8GiB
```

Please note:
- You might need to tweak the instance selectors to match existing instances in
  certain regions, for example `--instance-selector-vcpus` to `2` or increase
  `--instance-selector-memmory` to `16GiB`.
- You can have an `amd64` cluster by just switching the value in the
  `--instance-selector-cpu-architecture` flag.

**Warning**: don't forget to delete your cluster manually when your tests are done.

## Create an EKS cluster with the Amazon EBS CSI driver

**You need a cluster that can creates volumes**

Please use this [bash script to create and delete an arm64 cluster with the
Amazon EBS CSI driver](https://gist.github.com/mtardy/659bf4e8fc0df3990ea1e418136dde05).

You can use this script like that:
```text
Create and delete arm64 cluster on EKS with Amazon EBS CSI driver configured.
Dependencies are "aws" and "eksctl" properly configured with your account.

Usage:
    ./script.sh {flags} [cluster name]

Flags:
    -c, --create        Create and configure the cluster with EBS CSI driver
    -d, --delete        Delete all the resources
    -h, --help          Display this message
```

**Warning**: don't forget to delete your cluster when your tests are done. You
can use the script with the `--delete` flag to cleanup all resources.
