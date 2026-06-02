# Hubble Enterprise Configuration Files

## Configuration Directories

### Synopsis

`config-dir`, `/etc/hubble-fgs/hubble-fgs.conf.d/*`, `/etc/hubble-fgs/hubble-fgs.yaml`, `/usr/local/lib/hubble-fgs/hubble-fgs.conf.d/*`,  `/usr/lib/hubble-fgs/hubble-fgs.conf.d/*`


### Configuration Precedence

The default controlling settings are set during compilation, so configuration is only needed when it is necessary to deviate from those defaults.

In this case, hubble-fgs is able to load its controlling settings that are in [YAML format](https://yaml.org/) according to this order:

1. From the drop-in configuration snippets inside the following directories where each filename maps to a one controlling setting and the content of the file to its corresponding value:

   `/usr/lib/hubble-fgs/hubble-fgs.conf.d/*`
   `/usr/local/lib/hubble-fgs/hubble-fgs.conf.d/*`

2. From the configuration file `/etc/hubble-fgs/hubble-fgs.yaml` if available; overriding previous settings.

3. From the drop-in configuration snippets inside `/etc/hubble-fgs/hubble-fgs.conf.d/*` directory same as 1; overriding previous settings.

4. If the `config-dir` setting is set, hubble-fgs loads its settings from the files inside the directory pointed by this option; overriding previous controlling settings. The `config-dir` is also part of [Kubernetes ConfigMap](https://kubernetes.io/docs/concepts/configuration/configmap/).


When reading configuration from directories, each filename maps to a one controlling setting. If the same controlling setting is set multiple times, then the last value or content of that file overrides previous ones.

As a result the configuration precedence is:

1. Drop-in directory pointed by `--config-dir`

2. Drop-in directory `/etc/hubble-fgs/hubble-fgs.conf.d/*`

3. Configuration file `/etc/hubble-fgs/hubble-fgs.yaml`

4. Drop-in directories:

   `/usr/local/lib/hubble-fgs/hubble-fgs.conf.d/*`
   `/usr/lib/hubble-fgs/hubble-fgs.conf.d/*`


To clear a controlling setting that was set before, set it again to empty value.

Package managers can customize the configuration by installing drop-ins under `/usr/`. Configurations in `/etc/hubble-fgs/` are strictly reserved for the
local administrator, who may use this logic to override package managers or the default installed configuration.


## Configuration Options

This section shows the controlling settings that administrators can set.

```
      --bpf-lib string                            Location of hubble libs (btf and bpf files) (default "/var/lib/hubble-fgs/")
      --btf string                                Location of btf
      --config-dir string                         Configuration directory that contains a file for each option
      --tracing-policy string                     Tracing policy file to load at startup
      --data-cache-size int                       Size of the data events cache (default 1024)
  -d, --debug                                     Enable debug messages. Equivalent to '--log-level=debug'
      --dns-cache-size int                        Set the size of the internal DNS cache. Higher values enable Tetragon to keep track of more destination names before evicting old ones (default 1024)
      --enable-cilium-api                         Access Cilium API to associate FGS events with Cilium endpoints and DNS cache
      --enable-export-aggregation                 Enable JSON export aggregation
      --enable-k8s-api                            Access Kubernetes API to associate FGS events with Kubernetes pods
      --enable-process-ancestors                  Include ancestors in process exec events (default true)
      --enable-process-cred                       Enable process_cred events
      --enable-process-ns                         Enable namespace information in process_exec and process_kprobe events
      --event-queue-size uint                     Set the size of the internal event queue. (default 10000)
      --export-aggregation-buffer-size uint       Aggregator channel buffer size (default 10000)
      --export-aggregation-window-size duration   JSON export aggregation time window (default 15s)
      --export-allowlist string                   JSON export allowlist
      --export-denylist string                    JSON export denylist
      --export-file-compress                      Compress rotated JSON export files
      --export-file-max-backups int               Number of rotated JSON export files to retain (default 5)
      --export-file-max-size-mb int               Size in MB for rotating JSON export files (default 10)
      --export-file-rotation-interval duration    Interval at which to rotate JSON export files in addition to rotating them by size
      --export-filename string                    Filename for JSON export. Disabled by default
      --export-rate-limit int                     Rate limit (per minute) for event export. Set to -1 to disable (default -1)
      --field-filters string                      Field filters for event exports
      --fim-fifo-path string                      Path for the FIFO used for fs-scanner and hubble-fgs communication (default "/var/run/cilium/hubble")
      --force-small-progs                         Force loading small programs, even in kernels with >= 5.3 versions
      --gops-address string                       gops server address (e.g. 'localhost:8118'). Disabled by default
  -h, --help                                      help for hubble-fgs
      --kernel string                             Kernel version
      --log-format string                         Set log format (default "text")
      --log-level string                          Set log level (default "info")
      --metrics-server string                     Metrics server address (e.g. ':2112'). Disabled by default
      --net-ns-cache-size int                     Set the size of the internal network namespace cache. This should be aligned with the maximum number of network namespaces (approximately, the maxumum number of pods) we expect to see in the system (default 256)
      --netns-dir string                          Network namespace dir (default "/var/run/docker/netns/")
      --process-cache-size int                    Size of the process cache (default 65536)
      --procfs string                             Location of procfs to consume existing PIDs (default "/proc/")
      --protocol-shift string                     Shfit the socket protocol field (true) or not (false), or discover automatically (auto) (default "auto")
      --release-pinned-bpf                        Release all pinned BPF programs and maps in Tetragon BPF directory. Enabled by default. Set to false to disable (default true)
      --server-address string                     gRPC server address (e.g. 'localhost:54321' or 'unix:///var/run/tetragon/tetragon.sock'). An empty address disables the gRPC server (default "localhost:54321")
      --server-tls-cert-file string               Path to a PEM-encoded server certificate. When set, TLS is enabled on the TCP gRPC listener.
      --server-tls-client-ca-files strings        Paths to PEM-encoded CA bundles used to verify client certificates. Required when --server-tls-require-client-cert is true.
      --server-tls-key-file string                Path to the PEM-encoded private key matching --server-tls-cert-file. Required when --server-tls-cert-file is set.
      --server-tls-require-client-cert            Require and verify client certificates (mTLS). Requires --server-tls-client-ca-files.
      --verbose int                               set verbosity level
```

### Configuration file hubble-fgs.yaml

Administrators can override the default settings by editing and copying [hubble-fgs.yaml](./hubble-fgs.yaml)
into `/etc/hubble-fgs/hubble-fgs.yaml`. However, using the [Drop-ins Configuration directory](./#drop-ins-configuration-directory) explained in the next sessions is generally the recommended way. Defaults can be restored by simply deleting these files.

### Drop-ins Configuration directory

Overriding the default settings is also possible by "drop-ins" by editing and copying those from [hubble-fgs.conf.d](./hubble-fgs.conf.d/) directory into the `/etc/hubble-fgs/hubble-fgs.conf.d/` subdirectory.

The examples below shows how to override the control settings. Each filename maps to a one controlling setting and the content of the file to its corresponding value. This is the recommended way for administrators to edit Tetragon Enterprise settings.

Default control settings example:

* `/etc/hubble-fgs/hubble-fgs.conf.d/bpf-lib` that is the location of BPF objects:

   ```
   /var/lib/hubble-fgs/
   ```

* `/etc/hubble-fgs/hubble-fgs.conf.d/log-format` with a corresponding value of:

   ```
   text
   ```

* `/etc/hubble-fgs/hubble-fgs.conf.d/export-filename` location of the JSON events export:

   ```
   /var/log/hubble-fgs/hubble-fgs.log
   ```

Note: defaults controlling settings can be restored by simply deleting `/etc/hubble-fgs/hubble-fgs.yaml` and all drop-ins under `/etc/hubble-fgs/hubble-fgs.conf.d/`.

### Restrict gRPC API access

Starting from 1.10 version, the gRPC API supports unix sockets. This can be set using one of the following methods:

1. Use the `--server-address` controlling setting directly:

   ```
   --server-address unix:///var/run/tetragon/tetragon.sock
   ```

2. Or use configuration files, a "drop-in" example:

   ```
   cat /etc/hubble-fgs/hubble-fgs.conf.d/server-address
   unix:///var/run/tetragon/tetragon.sock
   ```

Then to access the gRPC API with Tetragon client, set the `--server-address`:

   ```
   sudo hubble-enterprise --server-address unix:///var/run/tetragon/tetragon.sock getevents
   ```

Note: when `--server-address` points at a TCP address (the default), the agent also serves an
always-on plaintext unix socket at `/var/run/tetragon/tetragon.sock` for local clients, so
in-host tooling keeps working without TLS material.

### Secure the gRPC API with TLS (mTLS)

TLS only applies to the TCP listener configured by `--server-address`; the agent refuses to
start when `--server-tls-*` settings are combined with a `unix://` address. The local unix
socket listener stays plaintext and is protected by file permissions.

1. Enable TLS on the TCP listener using "drop-ins":

   ```
   echo "0.0.0.0:54321"                > /etc/hubble-fgs/hubble-fgs.conf.d/server-address
   echo "/etc/hubble-fgs/tls/tls.crt"  > /etc/hubble-fgs/hubble-fgs.conf.d/server-tls-cert-file
   echo "/etc/hubble-fgs/tls/tls.key"  > /etc/hubble-fgs/hubble-fgs.conf.d/server-tls-key-file
   chmod 0600 /etc/hubble-fgs/tls/tls.key
   ```

2. To require and verify client certificates (mTLS), also set:

   ```
   echo "true"                         > /etc/hubble-fgs/hubble-fgs.conf.d/server-tls-require-client-cert
   echo "/etc/hubble-fgs/tls/ca.crt"   > /etc/hubble-fgs/hubble-fgs.conf.d/server-tls-client-ca-files
   ```

Then connect with the `tetra` client, passing the CA bundle and, for mTLS, the client
certificate and key:

   ```
   tetra --server-address localhost:54321 \
     --tls-ca-cert-files ca.crt \
     --tls-cert-file client.crt \
     --tls-key-file client.key \
     getevents
   ```

The agent watches the configured TLS files and reloads them atomically when their contents
change, so certificates can be rotated without restarting Tetragon Enterprise.

For Kubernetes deployments, certificate provisioning and rotation are handled by the Helm
chart — see the `tetragon.grpc.tls.*` values in the
[Helm chart README](../../install/kubernetes/tetragon/README.md).

### Tracing Policy

A [Tracing Policy](https://github.com/cilium/tetragon/tree/main/docs/tracingpolicy) can be specified by the `--tracing-policy` setting or by creating the drop-in file `/etc/hubble-fgs/hubble-fgs.conf.d/config-file` that contains the location of the Tracing Policy file.

Example:

1. Copy the Tracing Policy [sshd_sys_read.yaml](./sshd_sys_read.yaml) example to `/etc/hubble-fgs/hubble-fgs.policy.d/`:

   ```
   sudo mkdir /etc/hubble-fgs/huble-fgs.policy.d/
   sudo cp sshd_sys_read.yaml /etc/hubble-fgs/hubble-fgs.policy.d/
   ```

2. Update the `/etc/hubble-fgs/hubble-fgs.conf.d/config-file` with the path of the Tracing Policy:

   ```
   cat /etc/hubble-fgs/hubble-fgs.conf.d/config-file
   /etc/hubble-fgs/hubble-fgs.policy.d/sshd_sys_read.yaml
   ```

Tetragon Enterprise will read its configuration, loads the `/etc/hubble-fgs/hubble-fgs.conf.d/config-file` that corresponds to the
`--tracing-policy` setting and use its value to locate and load the Tracing Policy.


For further details on how to write Tracing Policies, please check
[Tracing Policy documentation](https://github.com/cilium/tetragon/tree/main/docs/tracingpolicy).
