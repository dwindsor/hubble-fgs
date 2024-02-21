# Tetragon / HTTP Golden Signals / Pod <-> Pod

This dashboard is intended to monitor HTTP golden signals: requests, errors and duration.

It's tailored for analyzing traffic between pods in Kubernetes clusters. It serves as an effective troubleshooting
tool, offering a range of filters such as nodes, binaries, remote DNS names, as well as Kubernetes-specific metadata:
namespaces, workloads, and pods. The layout consists of two sections, depicting traffic flow in opposing directions.

## Requirements

This dashboard requires [Tetragon Enterprise](https://isovalent.com/projects/tetragon/) to be installed with HTTP
visibility features configured. It's based on Prometheus metrics exported by Tetragon Enterprise.
