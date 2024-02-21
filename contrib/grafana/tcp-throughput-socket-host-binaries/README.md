# Tetragon / TCP Throughput / Socket - Host Binaries

This dashboard is intended to monitor TCP throughput: bytes and segments flow, retransmits, socket drops, and
zero window packets.

While primarily tailored for traffic analysis in Kubernetes clusters, it's also functional in non-Kubernetes
environments. In Kubernetes context, it displays only host binaries (that is, not Kubernetes pods). It serves as
an effective troubleshooting tool, offering a range of filters such as nodes, binaries, remote DNS names. The top row
provides a summary for the chosen filters, while subsequent rows break down the data across various dimensions.

## Requirements

This dashboard requires [Tetragon Enterprise](https://isovalent.com/projects/tetragon/) to be installed with TCP
visibility features configured. It's based on Prometheus metrics exported by Tetragon Enterprise.
