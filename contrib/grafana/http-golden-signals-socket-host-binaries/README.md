# Tetragon / HTTP Golden Signals / Socket - Host Binaries

This dashboard is intended to monitor HTTP golden signals: requests, errors and duration.

While primarily tailored for traffic analysis in Kubernetes clusters, it's also functional in non-Kubernetes
environments. In Kubernetes context, it displays only host binaries (that is, not Kubernetes pods). It serves as
an effective troubleshooting tool, offering a range of filters such as nodes, binaries, remote DNS names. The top row
provides a summary for the chosen filters, while subsequent rows break down the data across various dimensions.

## Requirements

This dashboard requires [Tetragon Enterprise](https://isovalent.com/projects/tetragon/) to be installed with HTTP
visibility features configured. It's based on Prometheus metrics exported by Tetragon Enterprise.
