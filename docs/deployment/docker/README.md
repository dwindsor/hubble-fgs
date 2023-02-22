# Docker Deployment

This document will help you get started with Tetragon Enterprise using a docker environment.

## BTF Requirement

Many common Linux distributions now ship with BTF enabled and do not require
any extra work. To check if BTF is enabled on your Linux system, the standard
location is:

```
$ ls /sys/kernel/btf/
```

If the system does not support BTF, Isovalent maintains BTF files for many common distributions. Please contact us for details.

## Deployment

### Stable versions

To run a stable version, please check [Tetragon Enterprise repository](https://quay.io/repository/isovalent/hubble-enterprise?tab=tags)
and select which version you want.

Example to run version `v1.9.3`:

```bash
docker run --name tetragon-enterprise \
   --rm -it -d --pid=host --network=host \
   --cgroupns=host --privileged \
   -v /etc/hubble-fgs:/etc/hubble-fgs \
   -v /sys/fs/bpf:/sys/fs/bpf \
   -v /sys/kernel:/sys/kernel \
   -v /var/log/hubble-fgs:/var/log/hubble-fgs \
   quay.io/isovalent/hubble-enterprise:v1.9.3 \
   /usr/bin/hubble-fgs \
   --process-cache-size=32768 \
   --export-filename /var/log/hubble/hubble-fgs.log
```

To verify that Tetragon Enterprise is running:

```bash
docker exec -it tetragon-enterprise hubble-enterprise status
```

### Docker deployment managed by systemd

1. Install [Tetragon Enterprise systemd unit](../../../install/docker/systemd/tetragon-enterprise-docker.service):

   ```bash
   sudo cp tetragon-enterprise-docker.service /usr/lib/systemd/system/
   ```

2. Start Tetragon Enterprise:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable tetragon-enterprise-docker
   sudo systemctl start tetragon-enterprise-docker
   ```

3. Check Tetragon Enterprise status:

   ```bash
   sudo systemctl status tetragon-enterprise-docker
   ```

   ```
   ● tetragon-enterprise-docker.service - "Tetragon Enterprise - eBPF-based Security Observability and Runtime Enforcement Service"
     Loaded: loaded (/lib/systemd/system/tetragon-enterprise-docker.service; enabled; vendor preset: enabled)
     Active: active (running) since Thu 2023-02-23 23:35:30 CET; 3s ago
       Docs: https://docs.isovalent.com/
    Process: 171983 ExecStartPre=/usr/bin/docker pull quay.io/isovalent/hubble-enterprise:v1.9.3 (code=exited, status=0/SUCCESS)
   Main PID: 172049 (docker)
      Tasks: 10 (limit: 18445)
     Memory: 8.7M
        CPU: 148ms
     CGroup: /system.slice/tetragon-enterprise-docker.service
             └─172049 /usr/bin/docker run --name tetragon-enterprise --rm --pid=host
   ```

   or:
   ```bash
   docker exec -it tetragon-enterprise hubble-enterprise status
   ```


## Tetragon Enterprise Events

By default events are logged to `/var/log/hubble-fgs/hubble-fgs.log` unless the
this default location is changed. Logs are always rotated into the same directory.

To read real-time events, tailing the logs file is enough.

   ```bash
   sudo tail -f /var/log/hubble-fgs/hubble-fgs.log
   ```

Tetragon Enterprise also ships a GRPC client that can be used to receive events.

1. To print events in `json` format using `hubble-entperise` GRPC client:
   ```
   docker exec -it tetragon-enterprise \
      /usr/bin/hubble-enterprise getevents
   ```

2. To print events in human compact format:
   ```
   docker exec -it tetragon-enterprise \
      /usr/bin/hubble-enterprise getevents -o compact
   ```

   Example of output:
   ```
   🚀 process  /usr/bin/curl https://ebpf.io
   💥 exit     /usr/bin/curl https://ebpf.io 0
   🚀 process  /usr/sbin/iptables -w 5 -W 100000 -S KUBE-PROXY-CANARY -t mangle
   🚀 process  /usr/sbin/ip6tables -w 5 -W 100000 -S KUBE-PROXY-CANARY -t mangle
   💥 exit     /usr/sbin/iptables -w 5 -W 100000 -S KUBE-PROXY-CANARY -t mangle 0
   💥 exit     /usr/sbin/ip6tables -w 5 -W 100000 -S KUBE-PROXY-CANARY -t mangle 0
   🚀 process  /usr/bin/whoami
   💥 exit     /usr/bin/whoami  0
   ```
