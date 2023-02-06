# Package Deployment

This document will guide you through installing Hubble Enterprise on
your Linux host machines.

## Requirement

### BTF

Many common Linux distributions now ship with BTF enabled and do not require
any extra work. To check if BTF is enabled on your Linux system, the standard
location is:

```
$ ls /sys/kernel/btf/
```

### systemd

Hubble Enterprise will be managed as a systemd service.

## Configuration

Default configurations are shipped with Hubble Enterprise that local administrators
can override by using their own configurations inside `/etc/hubble-fgs/` directory.

To read more about how configurations are handled please check [Hubble Enterprise Configuration doc](../../configuration/README.md).


## Linux Binary Tarball

### Stable versions

TODO complete.

### Unstable Development versions

TODO complete.

### Install

1. Download the latest binary tarball

   TODO complete.

2. Install hubble-fgs

   ```bash
   tar -xvf hubble-fgs-v1.9.0-amd64.tar.gz
   cd hubble-fgs-v1.9.0-amd64/
   sudo ./install.sh
   ```

3. Check hubble-fgs service

   ```bash
   sudo systemctl status hubble-fgs
   ```

   ```
   ● hubble-fgs.service - "Hubble FGS / Tetragon Enterprise - eBPF-based Security Observability and Runtime Enforcement Service"
     Loaded: loaded (/lib/systemd/system/hubble-fgs.service; enabled; vendor preset: enabled)
     Active: active (running) since Mon 2023-02-06 13:26:30 CET; 8s ago
       Docs: https://docs.isovalent.com/
   Main PID: 825990 (hubble-fgs)
      Tasks: 17 (limit: 18985)
     Memory: 196.5M
        CPU: 1.084s
     CGroup: /system.slice/hubble-fgs.service
             └─825990 /usr/local/bin/hubble-fgs
   ```

### Update

To update Hubble Enterprise:

1. Download new tarball

   TODO complete.

2. Stop hubble fgs service

   ```bash
   sudo systemctl stop hubble-fgs
   ```

3. Remove old hubble-fgs version

   ```bash
   sudo rm -fr /usr/lib/systemd/system/hubble-fgs.service
   sudo rm -fr /usr/local/bin/hubble-fgs
   sudo rm -fr /usr/local/lib/hubble-fgs/
   ```

4. Install new hubble-fgs version

   ```bash
   tar -xvf hubble-fgs-v1.9.1-amd64.tar.gz
   cd hubble-fgs-v1.9.1-amd64/
   sudo ./install.sh
   ```

### Configure

By default Hubble Enterprise configuration will be installed in
`/usr/local/lib/hubble-fgs/hubble-fgs.conf.d/`.

If you want to change the configuration, then add your drop-ins inside `/etc/hubble-fgs/hubble-fgs.conf.d/` to override the default
settings. For further details and examples, please check [Hubble Enterprise Configuration doc](../../configuration/README.md).

To restore default settings, remove any added configuration inside
`/etc/hubble-fgs/`.


### Remove

To remove Hubble Enterprise:

Run the `uninstall.sh` script that is provided inside the tarball.

   ```bash
   sudo ./uninstall.sh
   ```

Or manually:

   ```bash
   sudo systemctl stop hubble-fgs
   sudo systemctl disable hubble-fgs
   sudo rm -fr /usr/lib/systemd/system/hubble-fgs.service
   sudo rm -fr /usr/local/bin/hubble-fgs*
   sudo rm -fr /usr/local/bin/hubble-enterprise
   sudo rm -fr /usr/local/lib/hubble-fgs/
   ```

To purge custom settings:

   ```bash
   sudo rm -fr /etc/hubble-fgs/
   ```

## Hubble Enterprise Events

By default events are logged to `/var/log/hubble-fgs/hubble-fgs.log` unless the
this default location is changed. Logs are always rotated into the same directory.

To read real-time events, tailing the logs file is enough.

   ```bash
   sudo tail -f /var/log/hubble-fgs/hubble-fgs.log
   ```

Hubble Enterprise also ships a GRPC client that can be used to receive events.

1. To print events in `json` format using `hubble-entperise` GRPC client:
   ```
   sudo hubble-enterprise getevents
   ```

2. To print events in human compact format:
   ```
   sudo hubble-enterprise getevents -o compact
   ```
