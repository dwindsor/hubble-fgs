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

To summerize the configuration precedence:

1. Drop-in directory pointed by `--config-dir`

2. Drop-in directory `/etc/hubble-fgs/hubble-fgs.conf.d/*`

3. Configuration file `/etc/hubble-fgs/hubble-fgs.yaml`

4. Drop-in directories:

   `/usr/local/lib/hubble-fgs/hubble-fgs.conf.d/*`
   `/usr/lib/hubble-fgs/hubble-fgs.conf.d/*`


To clear a controlling setting that was set before, set it again to empty value.

Package managers can customize the configuration by installing drop-ins under `/usr/`. Configurations in `/etc/hubble-fgs/` are strictly reserved for the
local administrator, who may use this logic to override package managers or the default installed configuration.

The [hubble-fgs.yaml](./hubble-fgs.yaml) contains example entries showing the defaults as a guide to the administrator.
Local overrides can be created by editing and copying this file into `/etc/hubble-fgs/hubble-fgs.yaml`, or by editing and
copying "drop-ins" from the [hubble-fgs.conf.d](./hubble-fgs.conf.d/) directory into the `/etc/hubble-fgs/hubble-fgs.conf.d/`
subdirectory. The latter is generally recommended. Defaults can be restored by simply deleting this file and all drop-ins.
