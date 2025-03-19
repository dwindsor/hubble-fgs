## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* TBD

### Agent Options

* Tetragon groups UDP statistics for DNS servers (identified as listening on a UDP
  port listed in the dns.ports section of the policy) per local address and local port.
  The --dns-stats-per-socket switch reverts to separate statistics per DNS connection.
* New option `--enable-policy-k8swatcher` replaces `--enable-tracing-policy-crd` and
  `--enable-sandboxpolicies-crd`. If true (default), Tetragon watches all
  supported policy resources: TracingPolicy(Namespaced), SandboxPolicy(Namespaced),
  AlertRule and TetragonNetworkPolicy(Namespaced), unless some of the features
  are disabled by other options, or Kubernetes API server is disabled
  entirely by `--enable-k8s-api=false`.
* `--enable-cilium-dns-cache` flag and its corresponding `tetragon.enableCiliumDNSCache`
  Helm value have been removed. Tetragon no longer mirrors Cilium endpoints or
  FQDN cache. Enable [Tetragon's DNS parser](https://docs.isovalent.com/operations-guide/tetragon/networking/l7-visibility/dns.html)
  to associate IP addresses to DNS names in Tetragon networking events. Note that
  Tetragon still supports `--enable-cilium-api` flag and `tetragon.enableCiliumAPI`
  Helm value to mirror Cilium's IP cache to associate IP addresses with Kubernetes
  pods.

### Helm Values

* `dashboards.annotations` value has been removed. Use `annotations` values for
  specific dashboard groups instead, e.g. `dashboards.health.annotations`.
* The new tetragon.dnsStatsPerSocket operates as per the --dns-stats-per-socket
  switch (see Agent Options).
* New value `tetragon.k8sWatcher.policy.enabled` (default true) sets
  `--enable-policy-k8s-watcher` agent flag (see Agent Options). It replaces the
  function of `tetragonOperator.tracingPolicy.enabled` value within the agent
  (it doesn't affect the operator). It has no effect if Kubernetes API server
  is disabled entirely.

### OLM manifests

* TBD

### Kubernetes CRDs

* TracingPolicy new option dns-&gt;reportQuestions specifies that the DNS parser should report DNS
  questions as well as DNS answers. The default is now to not report questions unless
  this option is specified.

### Events (protobuf API)

* Socket statistics events, and socket statistics in close socket events, group UDP
  statistics for DNS servers per local address and local port (see Agent Options).
* The DNS parser will not report DNS questions by default. The dns-&gt;reportQuestions
  tracing policy option can be used to report DNS questions as well as answers.

### Metrics

* Tetragon groups UDP statistics for DNS servers per local address and local port
  (see Agent Options).
