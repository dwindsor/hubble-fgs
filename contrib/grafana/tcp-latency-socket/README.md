# Tetragon / TCP Latency / Socket

This dashboard is intended to monitor TCP Smoothed Round Trip Time (SRTT) and one-way latency.

While primarily tailored for traffic analysis in Kubernetes clusters, it's also functional in non-Kubernetes
environments. It serves as an effective troubleshooting tool, offering a range of filters such as nodes, binaries,
remote DNS names, as well as Kubernetes-specific metadata: namespaces, workloads, and pods. The top row provides
a summary for the chosen filters, while subsequent rows break down the data across various dimensions.

## Requirements

This dashboard requires [Tetragon Enterprise](https://isovalent.com/projects/tetragon/) to be installed with TCP
visibility features configured. It's based on Prometheus metrics exported by Tetragon Enterprise.
