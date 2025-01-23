export const model = {
  cluster_name: "tetragon-dev",
  node_name: "ip-10-3-6-166.us-west-2.compute.internal",
  time: "2025-01-22T16:18:12.319477189Z",
  application_model: {
    host: {
      processes: [
        {
          arguments:
            "--path.procfs=/host/proc\u0000--path.sysfs=/host/sys\u0000--path.rootfs=/host/root\u0000--path.udev.data=/host/root/run/udev/data\u0000--web.listen-address=[0.0.0.0]:9100\u0000--collector.filesystem.mount-points-exclude=^/(dev|proc|sys|var/lib/docker/.",
          name: "/bin/node_exporter",
        },
        { name: "/opt/cni/bin/cilium-cni" },
        {
          arguments: "/run/cilium/cgroupv2",
          name: "/opt/cni/bin/cilium-mount",
        },
        { name: "/opt/cni/bin/cilium-sysctlfix" },
        { name: "/opt/cni/bin/loopback" },
        {
          arguments:
            "createRuntime\u0000--log-fname\u0000/opt/tetragon/tetragon-oci-hook.log\u0000--grpc-address=localhost:54321\u0000--fail-allow-namespaces\u0000tetragon",
          connections: [
            {
              bytes_received: "2700",
              bytes_sent: "8641",
              destination_name: "127.0.0.1",
              destination_port: "54321",
            },
          ],
          name: "/opt/tetragon/tetragon-oci-hook",
        },
        { name: "/pause" },
        { arguments: "/cni/loopback", name: "/usr/bin/basename" },
        { arguments: "/opt/cni/bin/cilium-cni", name: "/usr/bin/basename" },
        {
          arguments:
            "-c\u0000\n        /usr/bin/chronyc cyclelogs > /dev/null 2>&1 || true\n\u0000logrotate_script\u0000/var/log/chrony/*.log ",
          name: "/usr/bin/bash",
        },
        {
          arguments:
            '-c\u0000--\u0000mount | grep "/sys/fs/bpf type bpf" || mount -t bpf bpf /sys/fs/bpf',
          name: "/usr/bin/bash",
        },
        {
          arguments: "-c\u0000set -o errexit\nset -o pipefail\nset -o nounset\n\n# When running",
          name: "/usr/bin/bash",
        },
        {
          arguments: "/etc/update-motd.d/10-nvidia-eula",
          name: "/usr/bin/bash",
        },
        {
          arguments: "/etc/update-motd.d/70-available-updates",
          name: "/usr/bin/bash",
        },
        { arguments: "/install-plugin.sh", name: "/usr/bin/bash" },
        { arguments: "/usr/sbin/raid-check", name: "/usr/bin/bash" },
        { arguments: "/usr/sbin/update-motd", name: "/usr/bin/bash" },
        { arguments: "/tmp/motd.part2lGei", name: "/usr/bin/cat" },
        { arguments: "/tmp/motd.part4nhZZ", name: "/usr/bin/cat" },
        { arguments: "/tmp/motd.part6sJ4i", name: "/usr/bin/cat" },
        { arguments: "/tmp/motd.part7wU9L", name: "/usr/bin/cat" },
        { arguments: "/tmp/motd.part9pOkX", name: "/usr/bin/cat" },
        { arguments: "/tmp/motd.partSJ2l3", name: "/usr/bin/cat" },
        { arguments: "/tmp/motd.partU6c4g", name: "/usr/bin/cat" },
        { arguments: "/tmp/motd.partayV7g", name: "/usr/bin/cat" },
        { arguments: "/tmp/motd.parthrmcO", name: "/usr/bin/cat" },
        { arguments: "/tmp/motd.partmJX0A", name: "/usr/bin/cat" },
        { arguments: "/tmp/motd.partsqdL4", name: "/usr/bin/cat" },
        { arguments: "/tmp/motd.parttijbD", name: "/usr/bin/cat" },
        {
          arguments: "go+r\u0000/var/lib/update-motd/tmp.AF3JR0mqvf",
          name: "/usr/bin/chmod",
        },
        {
          arguments: "go+r\u0000/var/lib/update-motd/tmp.LwMRU1u0RL",
          name: "/usr/bin/chmod",
        },
        {
          arguments: "go+r\u0000/var/lib/update-motd/tmp.ddZzS7YEvp",
          name: "/usr/bin/chmod",
        },
        {
          arguments: "go+r\u0000/var/lib/update-motd/tmp.iEWYQqXVmA",
          name: "/usr/bin/chmod",
        },
        {
          arguments: "go+r\u0000/var/lib/update-motd/tmp.sqjSiUVRK3",
          name: "/usr/bin/chmod",
        },
        {
          arguments: "go+r\u0000/var/lib/update-motd/tmp.v3HmeCw5Py",
          name: "/usr/bin/chmod",
        },
        { arguments: "cyclelogs", name: "/usr/bin/chronyc" },
        {
          arguments: "--config-dir=/tmp/cilium/config-map",
          name: "/usr/bin/cilium-agent",
        },
        { arguments: "build-config", name: "/usr/bin/cilium-dbg" },
        {
          connections: [
            { destination_name: "104.16.100.215", destination_port: "443" },
            { destination_name: "104.16.97.215", destination_port: "443" },
            {
              bytes_received: "52",
              bytes_sent: "187",
              destination_name: "104.16.98.215",
              destination_port: "443",
            },
            {
              bytes_received: "104",
              bytes_sent: "360",
              destination_name: "104.18.37.147",
              destination_port: "443",
            },
            {
              bytes_received: "104",
              bytes_sent: "360",
              destination_name: "172.64.150.109",
              destination_port: "443",
            },
            {
              bytes_received: "156",
              bytes_sent: "180",
              destination_name: "3.217.127.112",
              destination_port: "443",
            },
            {
              bytes_received: "1108",
              bytes_sent: "1004",
              destination_name: "52.35.2.78",
              destination_port: "443",
            },
            {
              bytes_received: "156",
              bytes_sent: "180",
              destination_name: "52.54.136.228",
              destination_port: "443",
            },
            {
              bytes_received: "288",
              bytes_sent: "208",
              destination_name: "52.92.137.10",
              destination_port: "443",
            },
            {
              bytes_received: "184",
              bytes_sent: "104",
              destination_name: "52.92.250.90",
              destination_port: "443",
            },
            {
              bytes_received: "104",
              bytes_sent: "180",
              destination_name: "54.210.148.48",
              destination_port: "443",
            },
            { destination_name: "54.69.96.148", destination_port: "443" },
            {
              bytes_received: "156",
              bytes_sent: "180",
              destination_name: "54.85.164.83",
              destination_port: "443",
            },
            {
              bytes_received: "260",
              bytes_sent: "412",
              destination_name: "54.85.81.91",
              destination_port: "443",
            },
            {
              destination_name:
                "al2023-repos-us-west-2-de612dc2.s3.dualstack.us-west-2.amazonaws.com",
              destination_port: "443",
            },
            {
              bytes_received: "28499",
              bytes_sent: "7483",
              destination_name: "auth.docker.io",
              destination_port: "443",
            },
            { destination_name: "cdn03.quay.io", destination_port: "443" },
            { destination_name: "quay.io", destination_port: "443" },
          ],
          name: "/usr/bin/containerd",
        },
        {
          arguments: "-namespace\u0000k8s.io\u0000-address\u0000/run/container",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000001c838fa58703e59b39079e771e34f95d688430cc38e9f87aabc3db24196f4be\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000f61ebf54d27b10d9662f33d66c33d9e3668c05f72fe449b65b83ae8d2bfef8f\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000010470c9569195a1ae7b65436f1afb0538ac7942377e80625791d6d3bac806253\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000011780363cb57e16915aa26fd50a4182f0879aff20411cde3895f63d4c951cf2b\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000226f192c02479bc231660f70279c978dcff713dc89b089dcbc75738904350789\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002b403a95ed928377c4fa40816bd80770bcb74a0377317a999105db973e9842fa\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002cf277dde228c8049378182ed54f0dc0872ca1a19403813dbe2d74c1d6b9be58\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000039801891bf87207663929a9d0464008715f7823f720105862dfdc4d3c45731d5\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004a156574dbb330413709f5ee805cce80e88ab42b345f239d476bb33dc0de142d\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004b0b5a6eddf472678fce74b52c8efcdc6c8f3600de5cb3c3bb0db4d71866f8ef\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000054a0a25327f9e7b3ac25f86fe0ec2e6e35edadad6f481b3a4a5f7b9e61e61be7\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000057c6634c28031682ff68d3f66afa35339b4dcfbadab8cb79bde7c26f22f5dcf1\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000057cd698e7e606d62e1579ec666ca05f8379b0ae5dc14a47985847444e17dad53\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00006d895f1ec5c9eb649b4e89a1e9ca47285044e776e53d228bf7c654712a313604\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000791d9de8a37ad97f5290ecb1b7ecdebc868ad3aa391ba311e31351a655b69931\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00007f54b689babb7205afeba54af90a4746af985065bc91bfe1ec02ed4f6510b5fc\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008cd1972438f14389451ffab70d9b573302bf7762b0a73a29d90aca4bbe460602\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000095245f106a342337e4d8c7944552a94ad50e5187a9bedaf09cb21a39267c6706\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009bd0c8389d6f80608b16840c17d36644aefa4774ded7fcfbcef706c6d009f853\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009bed3623d23e677aaf6fbd72161bf097b94d911cf315720b42c6cddaabe970b7\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009cb9f01077dc34f65274d76957267cb8bfb02ecedec9faf54b50407a36a224f1\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a8ea656e9bbfa3136214105c7744b1fca6e20a4f1c3b4785471a6c2ad355a5e5\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000cc03e424e134825a49a4c97eb2d08306169c196dfe51200019d8beaa5ce0ad7f\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d36617d8655f0f2d98e47bcb4461c1098d9958300f57346c91922a348207d008\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d6f25f3f9875800344c9769ba75fcb2d07ed773bc6b70d7a7a22e1378ee636d1\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e4760f0336c5aa5db0bfbea41b8782f5fb613def4da3769be0acdf4850b67106\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f335f55fd406709be7423d5298062c300cec1c308ae3c7043eae70a224b1216e\u0000start",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000011780363cb57e16915aa26fd50a4182f0879aff20411cde3895f63d4c951cf2b\u0000-address\u0000/run/containerd/containerd.sock",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000039801891bf87207663929a9d0464008715f7823f720105862dfdc4d3c45731d5\u0000-address\u0000/run/containerd/containerd.sock",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00006d895f1ec5c9eb649b4e89a1e9ca47285044e776e53d228bf7c654712a313604\u0000-address\u0000/run/containerd/containerd.sock",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00009bed3623d23e677aaf6fbd72161bf097b94d911cf315720b42c6cddaabe970b7\u0000-address\u0000/run/containerd/containerd.sock",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000d36617d8655f0f2d98e47bcb4461c1098d9958300f57346c91922a348207d008\u0000-address\u0000/run/containerd/containerd.sock",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000f335f55fd406709be7423d5298062c300cec1c308ae3c7043eae70a224b1216e\u0000-address\u0000/run/containerd/containerd.sock",
          name: "/usr/bin/containerd-shim-runc-v2",
        },
        {
          arguments: "/cni/loopback\u0000/host/opt/cni/bin/.loopback.new",
          name: "/usr/bin/cp",
        },
        {
          arguments: "/opt/cni/bin/cilium-cni\u0000/host/opt/cni/bin/.cilium-cni.new",
          name: "/usr/bin/cp",
        },
        {
          arguments: "/usr/bin/cilium-mount\u0000/hostbin/cilium-mount",
          name: "/usr/bin/cp",
        },
        {
          arguments: "/usr/bin/cilium-sysctlfix\u0000/hostbin/cilium-sysctlfix",
          name: "/usr/bin/cp",
        },
        { arguments: "-f\u00001\u0000-d\u0000 ", name: "/usr/bin/cut" },
        {
          arguments:
            '-c\u0000until test -s "/tmp/cilium-bootstrap.d/cilium-bootstrap-time"; do\n  echo "Waiting on node-init to run...";\n  sleep 1;\ndone\n',
          name: "/usr/bin/dash",
        },
        {
          arguments:
            '-ec\u0000cp /usr/bin/cilium-mount /hostbin/cilium-mount;\nnsenter --cgroup=/hostproc/1/ns/cgroup --mount=/hostproc/1/ns/mnt "${BIN_PATH}/cilium-mount" $CGROUP_ROOT;\nrm /hostbin/cilium-mount\n',
          name: "/usr/bin/dash",
        },
        {
          arguments:
            '-ec\u0000cp /usr/bin/cilium-sysctlfix /hostbin/cilium-sysctlfix;\nnsenter --mount=/hostproc/1/ns/mnt "${BIN_PATH}/cilium-sysctlfix";\nrm /hostbin/cilium-sysctlfix\n',
          name: "/usr/bin/dash",
        },
        {
          arguments: "/bin/entrypoint.sh\u0000fluentd",
          name: "/usr/bin/dash",
        },
        { arguments: "/init-container.sh", name: "/usr/bin/dash" },
        { arguments: "/usr/sbin/iptables-save", name: "/usr/bin/dash" },
        {
          arguments:
            "-v\u0000bdi=259:4\u0000BEGIN{ret=1} {if ($4 == bdi) {ret=0}} END{exit ret}\u0000/proc/fs/nfsfs/volumes",
          name: "/usr/bin/gawk",
        },
        {
          arguments:
            'function pline() { printf any?"%s\\n":"\\n%s\\n", $0; any=1; }\n         /newer release.*is available/  { sub("^ *", ""); pline(); }\n         /new v',
          name: "/usr/bin/gawk",
        },
        {
          arguments: "-E\u0000-c\u0000AWS-SNAT-CHAIN|AWS-CONNMARK-CHAIN",
          name: "/usr/bin/grep",
        },
        {
          arguments: "-E\u0000^:(KUBE-IPTABLES-HINT|KUBE-PROXY-CANARY)",
          name: "/usr/bin/grep",
        },
        { arguments: "-Pzo\u0000.*Updates(.*\\n)*", name: "/usr/bin/grep" },
        {
          arguments: "-e\u0000 \\-c\u0000-e\u0000 \\-\\-config",
          name: "/usr/bin/grep",
        },
        {
          arguments: "-e\u0000 \\-p\u0000-e\u0000 \\-\\-plugin",
          name: "/usr/bin/grep",
        },
        { arguments: "-q\u0000kmod-nvidia", name: "/usr/bin/grep" },
        { arguments: "/sys/fs/bpf type bpf", name: "/usr/bin/grep" },
        {
          arguments: "^md.*: active\u0000/proc/mdstat",
          name: "/usr/bin/grep",
        },
        { name: "/usr/bin/gzip" },
        { arguments: "--fqdn", name: "/usr/bin/hostname" },
        { arguments: "-u", name: "/usr/bin/id" },
        { arguments: "-q\u0000--\u0000cls_bpf", name: "/usr/bin/kmod" },
        { arguments: "-q\u0000--\u0000fs-ext4", name: "/usr/bin/kmod" },
        {
          arguments: "-q\u0000--\u0000ip_set_hash:ip",
          name: "/usr/bin/kmod",
        },
        {
          arguments: "-q\u0000--\u0000ipt_CONNMARK",
          name: "/usr/bin/kmod",
        },
        { arguments: "-q\u0000--\u0000ipt_CT", name: "/usr/bin/kmod" },
        { arguments: "-q\u0000--\u0000ipt_TPROXY", name: "/usr/bin/kmod" },
        { arguments: "-q\u0000--\u0000ipt_set", name: "/usr/bin/kmod" },
        {
          arguments: "-q\u0000--\u0000net-pf-16-proto-6",
          name: "/usr/bin/kmod",
        },
        {
          arguments: "-q\u0000--\u0000nfnetlink-subsys-6",
          name: "/usr/bin/kmod",
        },
        {
          arguments: "-q\u0000--\u0000rtnl-link-veth",
          name: "/usr/bin/kmod",
        },
        { arguments: "-q\u0000--\u0000sch_clsact", name: "/usr/bin/kmod" },
        {
          connections: [
            {
              bytes_received: "1140615",
              bytes_sent: "374472",
              destination_name: "10.3.5.178",
              destination_port: "443",
            },
            {
              bytes_received: "9289336",
              bytes_sent: "11429652",
              destination_name: "127.0.0.1",
              destination_port: "9879",
            },
            {
              destination_name: "3be81fd965b44e29ee37641b4d0f95cd.gr7.us-west-2.eks.amazonaws.com",
              destination_port: "443",
            },
            {
              bytes_received: "871543",
              bytes_sent: "1238155",
              destination_name: "ip-10-3-6-166.us-west-2.compute.internal",
              destination_port: "6789",
            },
            {
              bytes_received: "110325860",
              bytes_sent: "31999866",
              destination_name: "ip-10-3-6-166.us-west-2.compute.internal",
              destination_port: "9100",
            },
            {
              bytes_received: "157070487",
              bytes_sent: "668679429",
              destination_name: "ip-10-3-6-166.us-west-2.compute.internal",
              destination_port: "30001",
            },
            {
              bytes_received: "15224974",
              bytes_sent: "16836617",
              destination_name: "kube-system/DaemonSet:ebs-csi-node",
              destination_port: "9808",
            },
            {
              bytes_received: "15206725",
              bytes_sent: "16974867",
              destination_name: "logging/DaemonSet:promtail",
              destination_port: "3101",
            },
            {
              bytes_received: "66509529",
              bytes_sent: "67233881",
              destination_name:
                "monitoring/StatefulSet:prometheus-kube-prometheus-stack-prometheus",
              destination_port: "9090",
            },
          ],
          name: "/usr/bin/kubelet",
        },
        {
          arguments: "-s\u0000/usr/sbin/xtables-nft-multi\u0000/usr/sbin/ip6tables",
          name: "/usr/bin/ln",
        },
        {
          arguments: "-s\u0000/usr/sbin/xtables-nft-multi\u0000/usr/sbin/ip6tables-restore",
          name: "/usr/bin/ln",
        },
        {
          arguments: "-s\u0000/usr/sbin/xtables-nft-multi\u0000/usr/sbin/ip6tables-save",
          name: "/usr/bin/ln",
        },
        {
          arguments: "-s\u0000/usr/sbin/xtables-nft-multi\u0000/usr/sbin/iptables",
          name: "/usr/bin/ln",
        },
        {
          arguments: "-s\u0000/usr/sbin/xtables-nft-multi\u0000/usr/sbin/iptables-restore",
          name: "/usr/bin/ln",
        },
        {
          arguments: "-s\u0000/usr/sbin/xtables-nft-multi\u0000/usr/sbin/iptables-save",
          name: "/usr/bin/ln",
        },
        {
          arguments: "--tmpdir\u0000motd.partXXXXX",
          name: "/usr/bin/mktemp",
        },
        {
          arguments: "--tmpdir=/var/lib/update-motd/",
          name: "/usr/bin/mktemp",
        },
        { name: "/usr/bin/mount" },
        {
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2219/fd/21\u0000/var/lib/kubelet/pods/e915e0dc-b690-4963-abba-2507ede8dcdf/volume-subpaths/web-config/prometheus/4",
          name: "/usr/bin/mount",
        },
        {
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2219/fd/22\u0000/var/lib/kubelet/pods/e915e0dc-b690-4963-abba-2507ede8dcdf/volume-subpaths/pvc-1f6e2755-9835-4f73-aac8-8e4ec1be5458/prometheus/2",
          name: "/usr/bin/mount",
        },
        {
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2219/fd/21\u0000/var/lib/kubelet/pods/e915e0dc-b690-4963-abba-2507ede8dcdf/volume-subpaths/web-config/prometheus/4",
          name: "/usr/bin/mount",
        },
        {
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2219/fd/22\u0000/var/lib/kubelet/pods/e915e0dc-b690-4963-abba-2507ede8dcdf/volume-subpaths/pvc-1f6e2755-9835-4f73-aac8-8e4ec1be5458/prometheus/2",
          name: "/usr/bin/mount",
        },
        {
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/b2e6ba27-5148-410b-ba25-a32bbba0a97f/volumes/kubernetes.io~projected/kube-api-access-4nxns",
          name: "/usr/bin/mount",
        },
        {
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/b2e6ba27-5148-410b-ba25-a32bbba0a97f/volumes/kubernetes.io~secret/config",
          name: "/usr/bin/mount",
        },
        {
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7396327424\u0000tmpfs\u0000/var/lib/kubelet/pods/0262a468-ee07-467e-95e0-c06604428ddd/volumes/kubernetes.io~projected/config",
          name: "/usr/bin/mount",
        },
        {
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7396327424\u0000tmpfs\u0000/var/lib/kubelet/pods/0262a468-ee07-467e-95e0-c06604428ddd/volumes/kubernetes.io~projected/kube-api-access-996mp",
          name: "/usr/bin/mount",
        },
        {
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7396327424\u0000tmpfs\u0000/var/lib/kubelet/pods/e915e0dc-b690-4963-abba-2507ede8dcdf/volumes/kubernetes.io~empty-dir/config-out",
          name: "/usr/bin/mount",
        },
        {
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7396327424\u0000tmpfs\u0000/var/lib/kubelet/pods/e915e0dc-b690-4963-abba-2507ede8dcdf/volumes/kubernetes.io~projected/kube-api-access-rd88p",
          name: "/usr/bin/mount",
        },
        {
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7396327424\u0000tmpfs\u0000/var/lib/kubelet/pods/e915e0dc-b690-4963-abba-2507ede8dcdf/volumes/kubernetes.io~projected/tls-assets",
          name: "/usr/bin/mount",
        },
        {
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7396327424\u0000tmpfs\u0000/var/lib/kubelet/pods/e915e0dc-b690-4963-abba-2507ede8dcdf/volumes/kubernetes.io~secret/config",
          name: "/usr/bin/mount",
        },
        {
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7396327424\u0000tmpfs\u0000/var/lib/kubelet/pods/e915e0dc-b690-4963-abba-2507ede8dcdf/volumes/kubernetes.io~secret/web-config",
          name: "/usr/bin/mount",
        },
        {
          arguments: "/host/opt/cni/bin/.cilium-cni.new\u0000/host/opt/cni/bin/cilium-cni",
          name: "/usr/bin/mv",
        },
        {
          arguments: "/host/opt/cni/bin/.loopback.new\u0000/host/opt/cni/bin/loopback",
          name: "/usr/bin/mv",
        },
        {
          arguments: "/var/lib/update-motd/tmp.AF3JR0mqvf\u0000/var/lib/update-motd/motd",
          name: "/usr/bin/mv",
        },
        {
          arguments: "/var/lib/update-motd/tmp.LwMRU1u0RL\u0000/var/lib/update-motd/motd",
          name: "/usr/bin/mv",
        },
        {
          arguments: "/var/lib/update-motd/tmp.ddZzS7YEvp\u0000/var/lib/update-motd/motd",
          name: "/usr/bin/mv",
        },
        {
          arguments: "/var/lib/update-motd/tmp.iEWYQqXVmA\u0000/var/lib/update-motd/motd",
          name: "/usr/bin/mv",
        },
        {
          arguments: "/var/lib/update-motd/tmp.sqjSiUVRK3\u0000/var/lib/update-motd/motd",
          name: "/usr/bin/mv",
        },
        {
          arguments: "/var/lib/update-motd/tmp.v3HmeCw5Py\u0000/var/lib/update-motd/motd",
          name: "/usr/bin/mv",
        },
        {
          arguments:
            "--cgroup=/hostproc/1/ns/cgroup\u0000--mount=/hostproc/1/ns/mnt\u0000/opt/cni/bin/cilium-mount\u0000/run/cilium/cgroupv2",
          name: "/usr/bin/nsenter",
        },
        {
          arguments: "--mount=/hostproc/1/ns/mnt\u0000/opt/cni/bin/cilium-sysctlfix",
          name: "/usr/bin/nsenter",
        },
        {
          arguments: "-e\u0000-o\u0000pid,ppid,state,command",
          name: "/usr/bin/ps",
        },
        {
          arguments: "/usr/bin/dnf\u0000--debuglevel\u00002\u0000updateinfo",
          connections: [
            {
              bytes_received: "64603",
              bytes_sent: "11288",
              destination_name:
                "al2023-repos-us-west-2-de612dc2.s3.dualstack.us-west-2.amazonaws.com",
              destination_port: "443",
            },
            {
              bytes_received: "39732",
              bytes_sent: "6120",
              destination_name: "df-tetragon-dev-ce-01-logs.s3.us-west-2.amazonaws.com",
              destination_port: "443",
            },
          ],
          name: "/usr/bin/python3.9",
        },
        {
          arguments: "/usr/bin/dnf\u0000check-release-update",
          connections: [
            {
              bytes_received: "3214382",
              bytes_sent: "21330",
              destination_name:
                "al2023-repos-us-west-2-de612dc2.s3.dualstack.us-west-2.amazonaws.com",
              destination_port: "443",
            },
          ],
          name: "/usr/bin/python3.9",
        },
        {
          arguments: "/usr/sbin/ebsnvme-id\u0000-u\u0000/dev/nvme1n1",
          name: "/usr/bin/python3.9",
        },
        { arguments: "-f\u0000/tmp/motd.part2lGei", name: "/usr/bin/rm" },
        { arguments: "-f\u0000/tmp/motd.part4nhZZ", name: "/usr/bin/rm" },
        { arguments: "-f\u0000/tmp/motd.part6sJ4i", name: "/usr/bin/rm" },
        { arguments: "-f\u0000/tmp/motd.part7wU9L", name: "/usr/bin/rm" },
        { arguments: "-f\u0000/tmp/motd.part9pOkX", name: "/usr/bin/rm" },
        { arguments: "-f\u0000/tmp/motd.partSJ2l3", name: "/usr/bin/rm" },
        { arguments: "-f\u0000/tmp/motd.partU6c4g", name: "/usr/bin/rm" },
        { arguments: "-f\u0000/tmp/motd.partayV7g", name: "/usr/bin/rm" },
        { arguments: "-f\u0000/tmp/motd.parthrmcO", name: "/usr/bin/rm" },
        { arguments: "-f\u0000/tmp/motd.partmJX0A", name: "/usr/bin/rm" },
        { arguments: "-f\u0000/tmp/motd.partsqdL4", name: "/usr/bin/rm" },
        { arguments: "-f\u0000/tmp/motd.parttijbD", name: "/usr/bin/rm" },
        { arguments: "-f\u0000/usr/sbin/ip6tables", name: "/usr/bin/rm" },
        {
          arguments: "-f\u0000/usr/sbin/ip6tables-restore",
          name: "/usr/bin/rm",
        },
        {
          arguments: "-f\u0000/usr/sbin/ip6tables-save",
          name: "/usr/bin/rm",
        },
        { arguments: "-f\u0000/usr/sbin/iptables", name: "/usr/bin/rm" },
        {
          arguments: "-f\u0000/usr/sbin/iptables-restore",
          name: "/usr/bin/rm",
        },
        {
          arguments: "-f\u0000/usr/sbin/iptables-save",
          name: "/usr/bin/rm",
        },
        { arguments: "/hostbin/cilium-mount", name: "/usr/bin/rm" },
        { arguments: "/hostbin/cilium-sysctlfix", name: "/usr/bin/rm" },
        {
          arguments: "-q\u0000--quiet\u0000dnf-plugin-release-notification",
          name: "/usr/bin/rpm",
        },
        { arguments: "-qa", name: "/usr/bin/rpm" },
        {
          connections: [
            {
              bytes_received: "5517703",
              bytes_sent: "4408968",
              destination_name: "169.254.169.254",
              destination_port: "80",
            },
            {
              bytes_received: "52057",
              bytes_sent: "64130",
              destination_name: "52.94.177.19",
              destination_port: "443",
            },
            {
              bytes_received: "6983",
              bytes_sent: "3762",
              destination_name: "ssm.us-west-2.amazonaws.com",
              destination_port: "443",
            },
            {
              bytes_received: "7406",
              bytes_sent: "3483",
              destination_name: "ssmmessages.us-west-2.amazonaws.com",
              destination_port: "443",
            },
          ],
          name: "/usr/bin/ssm-agent-worker",
        },
        { arguments: "--clean", name: "/usr/bin/systemd-tmpfiles" },
        {
          arguments:
            "install\u0000--interface=nri-hook\u0000--local-install-dir=/hostInstall\u0000--host-install-dir=/opt/tetragon\u0000--oci-hooks.local-dir=/hostHooks\u0000--daemonize\u0000hook-args\u0000--grpc-address=localhost:54321\u0000--fail-allow-namespaces\u0000tetragon",
          name: "/usr/bin/tetragon-oci-hook-setup",
        },
        {
          arguments: "30s\u0000/etc/update-motd.d/10-nvidia-eula",
          name: "/usr/bin/timeout",
        },
        {
          arguments: "30s\u0000/etc/update-motd.d/70-available-updates",
          name: "/usr/bin/timeout",
        },
        {
          arguments: "30s\u0000/usr/bin/dnf\u0000--debuglevel\u00002\u0000updateinfo",
          name: "/usr/bin/timeout",
        },
        {
          arguments: "30s\u0000/usr/bin/dnf\u0000check-release-update",
          name: "/usr/bin/timeout",
        },
        { arguments: "-rs", name: "/usr/bin/uname" },
        { arguments: "-d\u0000-c", name: "/usr/bin/unpigz" },
        { arguments: "-l", name: "/usr/bin/wc" },
        { name: "/usr/lib/systemd/systemd-sysctl" },
        {
          arguments:
            "--prefix=/net/ipv4/conf/cilium\u0000--prefix=/net/ipv4/neigh/cilium\u0000--prefix=/net/ipv6/conf/cilium\u0000--prefix=/net/ipv6/neigh/cilium",
          name: "/usr/lib/systemd/systemd-sysctl",
        },
        {
          arguments:
            "--prefix=/net/ipv4/conf/cilium_host\u0000--prefix=/net/ipv4/neigh/cilium_host\u0000--prefix=/net/ipv6/conf/cilium_host\u0000--prefix=/net/ipv6/neigh/cilium_host",
          name: "/usr/lib/systemd/systemd-sysctl",
        },
        {
          arguments:
            "--prefix=/net/ipv4/conf/cilium_net\u0000--prefix=/net/ipv4/neigh/cilium_net\u0000--prefix=/net/ipv6/conf/cilium_net\u0000--prefix=/net/ipv6/neigh/cilium_net",
          name: "/usr/lib/systemd/systemd-sysctl",
        },
        {
          arguments:
            "--prefix=/net/ipv4/conf/ens6\u0000--prefix=/net/ipv4/neigh/ens6\u0000--prefix=/net/ipv6/conf/ens6\u0000--prefix=/net/ipv6/neigh/ens6",
          name: "/usr/lib/systemd/systemd-sysctl",
        },
        {
          arguments:
            "--prefix=/net/ipv4/conf/lxc3f6046d36480\u0000--prefix=/net/ipv4/neigh/lxc3f6046d36480\u0000--prefix=/net/ipv6/conf/lxc3f6046d36480\u0000--prefix=/net/ipv6/neigh/lxc3f6046d36480",
          name: "/usr/lib/systemd/systemd-sysctl",
        },
        {
          arguments:
            "--prefix=/net/ipv4/conf/lxc66bf239a9d22\u0000--prefix=/net/ipv4/neigh/lxc66bf239a9d22\u0000--prefix=/net/ipv6/conf/lxc66bf239a9d22\u0000--prefix=/net/ipv6/neigh/lxc66bf239a9d22",
          name: "/usr/lib/systemd/systemd-sysctl",
        },
        {
          arguments:
            "--prefix=/net/ipv4/conf/lxc78958fa2cbb6\u0000--prefix=/net/ipv4/neigh/lxc78958fa2cbb6\u0000--prefix=/net/ipv6/conf/lxc78958fa2cbb6\u0000--prefix=/net/ipv6/neigh/lxc78958fa2cbb6",
          name: "/usr/lib/systemd/systemd-sysctl",
        },
        {
          arguments:
            "--prefix=/net/ipv4/conf/lxc_health\u0000--prefix=/net/ipv4/neigh/lxc_health\u0000--prefix=/net/ipv6/conf/lxc_health\u0000--prefix=/net/ipv6/neigh/lxc_health",
          name: "/usr/lib/systemd/systemd-sysctl",
        },
        {
          arguments:
            "--prefix=/net/ipv4/conf/lxcb76c60c3d3a4\u0000--prefix=/net/ipv4/neigh/lxcb76c60c3d3a4\u0000--prefix=/net/ipv6/conf/lxcb76c60c3d3a4\u0000--prefix=/net/ipv6/neigh/lxcb76c60c3d3a4",
          name: "/usr/lib/systemd/systemd-sysctl",
        },
        {
          arguments:
            "--prefix=/net/ipv4/conf/lxce487f89d5f87\u0000--prefix=/net/ipv4/neigh/lxce487f89d5f87\u0000--prefix=/net/ipv6/conf/lxce487f89d5f87\u0000--prefix=/net/ipv6/neigh/lxce487f89d5f87",
          name: "/usr/lib/systemd/systemd-sysctl",
        },
        {
          arguments:
            "--prefix=/net/ipv4/conf/tmp39801\u0000--prefix=/net/ipv4/neigh/tmp39801\u0000--prefix=/net/ipv6/conf/tmp39801\u0000--prefix=/net/ipv6/neigh/tmp39801",
          name: "/usr/lib/systemd/systemd-sysctl",
        },
        {
          arguments:
            "--prefix=/net/ipv4/conf/tmp6d895\u0000--prefix=/net/ipv4/neigh/tmp6d895\u0000--prefix=/net/ipv6/conf/tmp6d895\u0000--prefix=/net/ipv6/neigh/tmp6d895",
          name: "/usr/lib/systemd/systemd-sysctl",
        },
        {
          arguments:
            "--prefix=/net/ipv4/conf/tmp9bed3\u0000--prefix=/net/ipv4/neigh/tmp9bed3\u0000--prefix=/net/ipv6/conf/tmp9bed3\u0000--prefix=/net/ipv6/neigh/tmp9bed3",
          name: "/usr/lib/systemd/systemd-sysctl",
        },
        {
          arguments:
            "--prefix=/net/ipv4/conf/tmpd3661\u0000--prefix=/net/ipv4/neigh/tmpd3661\u0000--prefix=/net/ipv6/conf/tmpd3661\u0000--prefix=/net/ipv6/neigh/tmpd3661",
          name: "/usr/lib/systemd/systemd-sysctl",
        },
        {
          arguments:
            "--prefix=/net/ipv4/conf/tmpf335f\u0000--prefix=/net/ipv4/neigh/tmpf335f\u0000--prefix=/net/ipv6/conf/tmpf335f\u0000--prefix=/net/ipv6/neigh/tmpf335f",
          name: "/usr/lib/systemd/systemd-sysctl",
        },
        { name: "/usr/lib/udev/rename_device" },
        {
          arguments:
            "eks\u0000get-token\u0000--cluster-name\u0000df-tetragon-dev-ce-01\u0000--region\u0000us-west-2",
          connections: [
            {
              bytes_received: "1526695",
              bytes_sent: "709312",
              destination_name: "169.254.169.254",
              destination_port: "80",
            },
          ],
          name: "/usr/local/aws-cli/v2/2.23.0/dist/aws",
        },
        {
          arguments:
            "/usr/local/bundle/bin/fluentd\u0000--config\u0000/fluentd/etc/fluent.conf\u0000--plugin\u0000/fluentd/plugins",
          name: "/usr/local/bin/ruby",
        },
        {
          arguments: "--\u0000/bin/entrypoint.sh\u0000fluentd",
          name: "/usr/local/bin/tini",
        },
        {
          arguments:
            "--listed-in\u0000/etc/fstab:/proc/self/mountinfo\u0000--verbose\u0000--quiet-unsupported",
          name: "/usr/sbin/fstrim",
        },
        { arguments: "/etc/logrotate.conf", name: "/usr/sbin/logrotate" },
        { arguments: "--", name: "/usr/sbin/runc" },
        { arguments: "--r", name: "/usr/sbin/runc" },
        { arguments: "--ro", name: "/usr/sbin/runc" },
        { arguments: "--roo", name: "/usr/sbin/runc" },
        { arguments: "--root", name: "/usr/sbin/runc" },
        { arguments: "--root\u0000/ru", name: "/usr/sbin/runc" },
        { arguments: "--root\u0000/run/contai", name: "/usr/sbin/runc" },
        { arguments: "--root\u0000/run/contain", name: "/usr/sbin/runc" },
        {
          arguments: "--root\u0000/run/containerd/ru",
          name: "/usr/sbin/runc",
        },
        {
          arguments: "--root\u0000/run/containerd/runc/",
          name: "/usr/sbin/runc",
        },
        { arguments: "init", name: "/usr/sbin/runc" },
        { name: "/usr/sbin/sshd" },
        { name: "/usr/sbin/xtables-nft-multi" },
        {
          arguments: "-t\u0000mangle",
          name: "/usr/sbin/xtables-nft-multi",
        },
        {
          arguments:
            "-w\u00005\u0000-W\u0000100000\u0000-S\u0000KUBE-KUBELET-CANARY\u0000-t\u0000mangle",
          name: "/usr/sbin/xtables-nft-multi",
        },
        { arguments: "init" },
      ],
    },
    namespaces: [
      {
        name: "hubble-enterprise",
        workloads: [
          {
            kind: "DaemonSet",
            name: "hubble-enterprise",
            processes: [
              { name: "/usr/bin/hostname" },
              {
                arguments: "-Eascii-8bit:ascii-8bit\u0000-h",
                name: "/usr/local/bin/ruby",
              },
              {
                arguments:
                  "-Eascii-8bit:ascii-8bit\u0000/usr/local/bundle/bin/fluentd\u0000--config\u0000/fluentd/etc/fluent.conf\u0000--plugin\u0000/fluentd/plugins\u0000--under-supervisor",
                connections: [
                  {
                    bytes_received: "128",
                    bytes_sent: "232",
                    destination_name: "3.5.79.153",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "8473",
                    bytes_sent: "132931",
                    destination_name:
                      "al2023-repos-us-west-2-de612dc2.s3.dualstack.us-west-2.amazonaws.com",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "10869",
                    bytes_sent: "313095",
                    destination_name: "df-tetragon-dev-ce-01-logs.s3.us-west-2.amazonaws.com",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "158442606",
                    bytes_sent: "22800393316",
                    destination_name:
                      "hubble-timescape-ingester.hubble-timescape.svc.cluster.local",
                    destination_port: "4260",
                  },
                  {
                    bytes_received: "1204574",
                    bytes_sent: "469852",
                    destination_name: "sts.us-west-2.amazonaws.com",
                    destination_port: "443",
                  },
                ],
                name: "/usr/local/bin/ruby",
              },
            ],
          },
        ],
      },
      {
        name: "kube-system",
        workloads: [
          {
            kind: "DaemonSet",
            name: "cilium",
            processes: [
              {
                arguments: "--config-dir=/tmp/cilium/config-map",
                connections: [
                  {
                    bytes_received: "416",
                    bytes_sent: "468",
                    destination_name: "10.3.5.115",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "7683",
                    bytes_sent: "10077",
                    destination_name: "10.3.5.121",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "416",
                    bytes_sent: "468",
                    destination_name: "10.3.5.145",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "416",
                    bytes_sent: "468",
                    destination_name: "10.3.5.149",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "2276341",
                    bytes_sent: "2806403",
                    destination_name: "10.3.5.170",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "5078",
                    bytes_sent: "6822",
                    destination_name: "10.3.5.176",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "50792112",
                    bytes_sent: "15423766",
                    destination_name: "10.3.5.178",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "855",
                    bytes_sent: "985",
                    destination_name: "10.3.5.197",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "2280414",
                    bytes_sent: "2811184",
                    destination_name: "10.3.5.242",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "2274874",
                    bytes_sent: "2797847",
                    destination_name: "10.3.5.54",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "855",
                    bytes_sent: "984",
                    destination_name: "10.3.5.74",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "416",
                    bytes_sent: "468",
                    destination_name: "10.3.6.103",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "416",
                    bytes_sent: "468",
                    destination_name: "10.3.6.11",
                    destination_port: "4240",
                  },
                  {
                    bytes_sent: "300",
                    destination_name: "10.3.6.139",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "364",
                    bytes_sent: "416",
                    destination_name: "10.3.6.166",
                    destination_port: "4240",
                  },
                  {
                    bytes_sent: "624",
                    destination_name: "10.3.6.181",
                    destination_port: "4240",
                  },
                  {
                    destination_name: "10.3.6.228",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "416",
                    bytes_sent: "468",
                    destination_name: "10.3.6.229",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "416",
                    bytes_sent: "468",
                    destination_name: "10.3.6.233",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "2282342",
                    bytes_sent: "2807280",
                    destination_name: "10.3.6.50",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "2277889",
                    bytes_sent: "2801464",
                    destination_name: "10.3.6.97",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "2279133",
                    bytes_sent: "2809971",
                    destination_name: "10.3.7.151",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "2569",
                    bytes_sent: "3408",
                    destination_name: "10.3.7.56",
                    destination_port: "4240",
                  },
                  {
                    bytes_sent: "600",
                    destination_name: "10.3.8.128",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "855",
                    bytes_sent: "985",
                    destination_name: "10.3.8.221",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "2282014",
                    bytes_sent: "2806848",
                    destination_name: "10.3.8.33",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "855",
                    bytes_sent: "984",
                    destination_name: "10.3.8.68",
                    destination_port: "4240",
                  },
                  {
                    destination_name:
                      "3be81fd965b44e29ee37641b4d0f95cd.gr7.us-west-2.eks.amazonaws.com",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "13670338",
                    bytes_sent: "16847008",
                    destination_name: "ip-10-3-6-166.us-west-2.compute.internal",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "834",
                    bytes_sent: "1538",
                    destination_name:
                      "monitoring/Deployment:kube-prometheus-stack-kube-state-metrics",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "2273884",
                    bytes_sent: "2801220",
                    destination_name: "tetragon-tracing-demo/Pod:tls-weak-version",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "6879184",
                    bytes_sent: "8497286",
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "4240",
                  },
                ],
                name: "/usr/bin/cilium-agent",
              },
              { arguments: "--version", name: "/usr/bin/cilium-envoy" },
              {
                arguments:
                  "-l\u0000info\u0000-c\u0000/var/run/cilium/envoy/bootstrap.pb\u0000--base-id\u00000\u0000--log-format\u0000%t|%l|%n|%v",
                connections: [
                  {
                    bytes_received: "6339419",
                    bytes_sent: "544470",
                    destination_name: "monitoring/Deployment:kube-prometheus-stack-grafana",
                    destination_port: "3000",
                  },
                  {
                    bytes_received: "79495",
                    bytes_sent: "11999",
                    destination_name: "otel-demo/Deployment:otel-demo-frontendproxy",
                    destination_port: "8080",
                  },
                  {
                    bytes_received: "9037439",
                    bytes_sent: "44684",
                    destination_name: "tetragon/Deployment:tetragon-grafana",
                    destination_port: "3000",
                  },
                ],
                name: "/usr/bin/cilium-envoy",
              },
              {
                arguments:
                  "-l\u0000info\u0000-c\u0000/var/run/cilium/envoy/bootstrap.pb\u0000--base-id\u00000\u0000--log-format\u0000%t|%l|%n|%v",
                name: "/usr/bin/cilium-envoy-starter",
              },
              {
                arguments:
                  "--listen\u00004240\u0000--pidfile\u0000/var/run/cilium/state/health-endpoint.pid",
                name: "/usr/bin/cilium-health-responder",
              },
              {
                arguments:
                  "route\u0000add\u00000.0.0.0/0\u0000via\u000010.3.6.127\u0000mtu\u00009001\u0000dev\u0000cilium",
                name: "/usr/bin/ip",
              },
              {
                arguments: "route\u0000add\u000010.3.6.127/32\u0000dev\u0000cilium",
                name: "/usr/bin/ip",
              },
              { arguments: "ip6table_filter", name: "/usr/bin/kmod" },
              { arguments: "ip6table_mangle", name: "/usr/bin/kmod" },
              { arguments: "ip6table_raw", name: "/usr/bin/kmod" },
              { arguments: "iptable_filter", name: "/usr/bin/kmod" },
              { arguments: "iptable_mangle", name: "/usr/bin/kmod" },
              { arguments: "iptable_nat", name: "/usr/bin/kmod" },
              { arguments: "iptable_raw", name: "/usr/bin/kmod" },
              { arguments: "xt_socket", name: "/usr/bin/kmod" },
              {
                arguments: "-j\u0000feature\u0000probe",
                name: "/usr/local/bin/bpftool",
              },
              {
                arguments: "-j\u0000map\u0000show",
                name: "/usr/local/bin/bpftool",
              },
              {
                arguments: "-j\u0000prog\u0000show",
                name: "/usr/local/bin/bpftool",
              },
              { arguments: "--version", name: "/usr/local/bin/clang" },
              {
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wextra\u0000-Werr",
                name: "/usr/local/bin/clang",
              },
              {
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/021a44a71bc05dca5310a281b0d3f0ff3dc8826b9a971c4d5181106227b33562\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
                name: "/usr/local/bin/clang",
              },
              {
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/5b3dbd9108d33015665b46d2644ddd516757bd21bc329d7a5c2f5fdef7f747f6\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
                name: "/usr/local/bin/clang",
              },
              {
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/b11cf4d241118ac98d271fa7493b770b1f4163b462302ecd86d16c49ce728a6e\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
                name: "/usr/local/bin/clang",
              },
              {
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/c8f798a7bc0ccb8ad76327aff0ac642924c0f11f3de43a5c8c5e22950ccdae47\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
                name: "/usr/local/bin/clang",
              },
              {
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/ded9bea9e2f9e0d4241a96bc39fc43c89219c1c9689bbbd3b1d7887e967c40b6\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
                name: "/usr/local/bin/clang",
              },
              {
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/e1d18312bdce24effebf0ccd24a5fb63e41acc3aec5a5f9a17bbf0b059b3792a\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
                name: "/usr/local/bin/clang",
              },
              {
                arguments:
                  "create\u0000cilium_node_set_v4\u0000iphash\u0000family\u0000inet\u0000-exist",
                name: "/usr/sbin/ipset",
              },
              {
                arguments:
                  "create\u0000cilium_node_set_v6\u0000iphash\u0000family\u0000inet6\u0000-exist",
                name: "/usr/sbin/ipset",
              },
              {
                arguments: "list\u0000cilium_node_set_v4",
                name: "/usr/sbin/ipset",
              },
              {
                arguments: "list\u0000cilium_node_set_v6",
                name: "/usr/sbin/ipset",
              },
              { arguments: "restore", name: "/usr/sbin/ipset" },
              {
                arguments: "--version",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-t\u0000filter\u0000-S",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-t\u0000filter\u0000-S\u0000CILIUM_FORWARD",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-t\u0000filter\u0000-S\u0000CILIUM_INPUT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-t\u0000filter\u0000-S\u0000CILIUM_OUTPUT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-t\u0000filter\u0000-S\u0000OLD_CILIUM_FORWARD",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-t\u0000filter\u0000-S\u0000OLD_CILIUM_INPUT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-t\u0000filter\u0000-S\u0000OLD_CILIUM_OUTPUT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-t\u0000mangle\u0000-S",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-t\u0000mangle\u0000-S\u0000CILIUM_PRE_mangle",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-t\u0000mangle\u0000-S\u0000OLD_CILIUM_PRE_mangle",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-t\u0000nat\u0000-S",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-t\u0000nat\u0000-S\u0000CILIUM_POST_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-t\u0000nat\u0000-S\u0000OLD_CILIUM_POST_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-t\u0000raw\u0000-S",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-t\u0000raw\u0000-S\u0000CILIUM_OUTPUT_raw",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-t\u0000raw\u0000-S\u0000CILIUM_PRE_raw",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-t\u0000raw\u0000-S\u0000OLD_CILIUM_OUTPUT_raw",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-t\u0000raw\u0000-S\u0000OLD_CILIUM_PRE_raw",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-A\u0000CILIUM_FORWARD\u0000-i\u0000cilium_host\u0000-m\u0000comment\u0000--comment\u0000cilium: cluster->any on cilium_host forward accept (nodeport)\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-A\u0000CILIUM_FORWARD\u0000-i\u0000cilium_net\u0000-m\u0000comment\u0000--comment\u0000cilium: cluster->any on cilium_net forward accept (nodeport)\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-A\u0000CILIUM_FORWARD\u0000-i\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium: cluster->any on lxc+ forward accept\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-A\u0000CILIUM_FORWARD\u0000-i\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium: cluster->any on lxc+ forward accept (nodeport)\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-A\u0000CILIUM_FORWARD\u0000-o\u0000cilium_host\u0000-m\u0000comment\u0000--comment\u0000cilium: any->cluster on cilium_host forward accept\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-A\u0000CILIUM_FORWARD\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium: any->cluster on lxc+ forward accept\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-A\u0000CILIUM_INPUT\u0000-m\u0000mark\u0000--mark\u00000x00000200/0x00000f00\u0000-m\u0000comment\u0000--comment\u0000cilium: ACCEPT for proxy traffic\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-A\u0000CILIUM_OUTPUT\u0000-m\u0000mark\u0000!\u0000--mark\u00000x00000e00/0x00000f00\u0000-m\u0000mark\u0000!\u0000--mark\u00000x00000d00/0x00000f00",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-A\u0000CILIUM_OUTPUT\u0000-m\u0000mark\u0000--mark\u00000x00000800/0x00000e00\u0000-m\u0000comment\u0000--comment\u0000cilium: ACCEPT for l7 proxy upstream traffic\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-A\u0000CILIUM_OUTPUT\u0000-m\u0000mark\u0000--mark\u00000x00000a00/0x00000e00\u0000-m\u0000comment\u0000--comment\u0000cilium: ACCEPT for proxy traffic\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000FORWARD\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_FORWARD\u0000-j\u0000OLD_CILIUM_FORWARD",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000INPUT\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_INPUT\u0000-j\u0000OLD_CILIUM_INPUT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OLD_CILIUM_FORWARD\u0000-i\u0000cilium_host\u0000-m\u0000comment\u0000--comment\u0000cilium: cluster->any on cilium_host forward accept (nodeport)\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OLD_CILIUM_FORWARD\u0000-i\u0000cilium_net\u0000-m\u0000comment\u0000--comment\u0000cilium: cluster->any on cilium_net forward accept (nodeport)\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OLD_CILIUM_FORWARD\u0000-i\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium: cluster->any on lxc+ forward accept\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OLD_CILIUM_FORWARD\u0000-i\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium: cluster->any on lxc+ forward accept (nodeport)\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OLD_CILIUM_FORWARD\u0000-o\u0000cilium_host\u0000-m\u0000comment\u0000--comment\u0000cilium: any->cluster on cilium_host forward accept\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OLD_CILIUM_FORWARD\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium: any->cluster on lxc+ forward accept\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OLD_CILIUM_INPUT\u0000-m\u0000mark\u0000--mark\u00000x200/0xf00\u0000-m\u0000comment\u0000--comment\u0000cilium: ACCEPT for proxy traffic\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OLD_CILIUM_OUTPUT\u0000-m\u0000mark",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OLD_CILIUM_OUTPUT\u0000-m\u0000mark\u0000--mark\u00000x800/0xe00\u0000-m\u0000comment\u0000--comment\u0000cilium: ACCEPT for l7 proxy upstream traffic\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OLD_CILIUM_OUTPUT\u0000-m\u0000mark\u0000--mark\u00000xa00/0xe00\u0000-m\u0000comment\u0000--comment\u0000cilium: ACCEPT for proxy traffic\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OUTPUT\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_OUTPUT\u0000-j\u0000OLD_CILIUM_OUTPUT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-E\u0000CILIUM_FORWARD\u0000OLD_CILIUM_FORWARD",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-E\u0000CILIUM_INPUT\u0000OLD_CILIUM_INPUT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-E\u0000CILIUM_OUTPUT\u0000OLD_CILIUM_OUTPUT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000filter\u0000-F\u0000OLD_CILIUM_FORWARD",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000filter\u0000-F\u0000OLD_CILIUM_INPUT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000filter\u0000-F\u0000OLD_CILIUM_OUTPUT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-I\u0000FORWARD\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_FORWARD\u0000-j\u0000CILIUM_FORWARD",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-I\u0000INPUT\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_INPUT\u0000-j\u0000CILIUM_INPUT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-I\u0000OUTPUT\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_OUTPUT\u0000-j\u0000CILIUM_OUTPUT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000filter\u0000-N\u0000CILIUM_FORWARD",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000filter\u0000-N\u0000CILIUM_INPUT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000filter\u0000-N\u0000CILIUM_OUTPUT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000filter\u0000-S",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000filter\u0000-S\u0000CILIUM_FORWARD",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000filter\u0000-S\u0000CILIUM_INPUT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000filter\u0000-S\u0000CILIUM_OUTPUT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000filter\u0000-S\u0000OLD_CILIUM_FORWARD",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000filter\u0000-S\u0000OLD_CILIUM_INPUT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000filter\u0000-S\u0000OLD_CILIUM_OUTPUT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000filter\u0000-X\u0000OLD_CILIUM_FORWARD",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000filter\u0000-X\u0000OLD_CILIUM_INPUT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000filter\u0000-X\u0000OLD_CILIUM_OUTPUT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-i\u0000ens5\u0000-m\u0000comment\u0000--comment\u0000cilium: primary ENI\u0000-m\u0000addrtype\u0000--dst-type\u0000LOCAL\u0000--limit-iface-in\u0000-j\u0000CONNMARK\u0000--set-xmark\u00000x00000080/0x00000080",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-i\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium: primary ENI\u0000-j\u0000CONNMARK\u0000--restore-mark\u0000--nfmask\u00000x00000080\u0000--ctmask\u00000x00000080",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-m\u0000socket\u0000--transparent\u0000!\u0000-o\u0000lo\u0000-m\u0000mark\u0000!\u0000--mark\u00000x00000e00/0x00000f00\u0000-m\u0000mark\u0000!\u0000--mark\u00000x00000800/0x00000f00\u0000-m\u0000comment\u0000--comment\u0000cilium: any->pod redirect proxied traffic to host proxy\u0000-j\u0000MARK\u0000--set-mark\u00000x00000200",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xb39a0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000039603",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xf2460200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000018162",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xb39a0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000039603",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xf2460200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000018162",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000!\u0000-o\u0000lo\u0000-m\u0000socket\u0000--transparent\u0000-m\u0000mark\u0000!\u0000--mark\u00000xe00/0xf00\u0000-m\u0000mark\u0000!\u0000--mark\u00000x800/0xf00\u0000-m\u0000comment\u0000--comment\u0000cilium: any->pod redirect proxied traffic to host proxy\u0000-j\u0000MARK\u0000--set-xmark\u00000x200/0xffffffff",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-i\u0000ens5\u0000-m\u0000comment\u0000--comment\u0000cilium: primary ENI\u0000-m\u0000addrtype\u0000--dst-type\u0000LOCAL\u0000--limit-iface-in\u0000-j\u0000CONNMARK\u0000--set-xmark\u00000x80/0x80",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-i\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium: primary ENI\u0000-j\u0000CONNMARK\u0000--restore-mark\u0000--nfmask\u00000x80\u0000--ctmask\u00000x80",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xb39a0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000039603\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xf2460200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000018162\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xb39a0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000039603\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xf2460200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000018162\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000POSTROUTING\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_POST_mangle\u0000-j\u0000OLD_CILIUM_POST_mangle",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000PREROUTING\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_PRE_mangle\u0000-j\u0000OLD_CILIUM_PRE_mangle",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-E\u0000CILIUM_POST_mangle\u0000OLD_CILIUM_POST_mangle",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-E\u0000CILIUM_PRE_mangle\u0000OLD_CILIUM_PRE_mangle",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000mangle\u0000-F\u0000OLD_CILIUM_POST_mangle",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000mangle\u0000-F\u0000OLD_CILIUM_PRE_mangle",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-I\u0000POSTROUTING\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_POST_mangle\u0000-j\u0000CILIUM_POST_mangle",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-I\u0000PREROUTING\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_PRE_mangle\u0000-j\u0000CILIUM_PRE_mangle",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000mangle\u0000-N\u0000CILIUM_POST_mangle",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000mangle\u0000-N\u0000CILIUM_PRE_mangle",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000mangle\u0000-S",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000mangle\u0000-S\u0000CILIUM_POST_mangle",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000mangle\u0000-S\u0000CILIUM_PRE_mangle",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000mangle\u0000-S\u0000OLD_CILIUM_POST_mangle",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000mangle\u0000-S\u0000OLD_CILIUM_PRE_mangle",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000mangle\u0000-X\u0000OLD_CILIUM_POST_mangle",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000mangle\u0000-X\u0000OLD_CILIUM_PRE_mangle",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000mangle\u0000-n\u0000-L\u0000CILIUM_PRE_mangle",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-A\u0000CILIUM_POST_nat\u0000!\u0000-d\u000010.3.0.0/20\u0000-o\u0000ens+\u0000-m\u0000comment\u0000--comment\u0000cilium masquerade non-cluster\u0000-j\u0000MASQUERADE",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-A\u0000CILIUM_POST_nat\u0000-m\u0000mark\u0000--mark\u00000x00000a00/0x00000e00\u0000-m\u0000comment\u0000--comment\u0000exclude proxy return traffic from masquerade\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-A\u0000CILIUM_POST_nat\u0000-o\u0000ens+\u0000-m\u0000set\u0000--match-set\u0000cilium_node_set_v4\u0000dst\u0000-m\u0000comment\u0000--comment\u0000exclude traffic to cluster nodes from masquerade\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-A\u0000CILIUM_POST_nat\u0000-s\u0000127.0.0.1\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.6.127",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000OLD_CILIUM_POST_nat\u0000!\u0000-d\u000010.3.0.0/20\u0000-o\u0000ens+\u0000-m\u0000comment\u0000--comment\u0000cilium masquerade non-cluster\u0000-j\u0000MASQUERADE",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000OLD_CILIUM_POST_nat\u0000-m\u0000mark\u0000--mark\u00000xa00/0xe00\u0000-m\u0000comment\u0000--comment\u0000exclude proxy return traffic from masquerade\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000OLD_CILIUM_POST_nat\u0000-o\u0000ens+\u0000-m\u0000set\u0000--match-set\u0000cilium_node_set_v4\u0000dst\u0000-m\u0000comment\u0000--comment\u0000exclude traffic to cluster nodes from masquerade\u0000-j\u0000ACCEPT",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000OLD_CILIUM_POST_nat\u0000-s\u0000127.0.0.1/32\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.6.127",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000OUTPUT\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_OUTPUT_nat\u0000-j\u0000OLD_CILIUM_OUTPUT_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000POSTROUTING\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_POST_nat\u0000-j\u0000OLD_CILIUM_POST_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000PREROUTING\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_PRE_nat\u0000-j\u0000OLD_CILIUM_PRE_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-E\u0000CILIUM_OUTPUT_nat\u0000OLD_CILIUM_OUTPUT_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-E\u0000CILIUM_POST_nat\u0000OLD_CILIUM_POST_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-E\u0000CILIUM_PRE_nat\u0000OLD_CILIUM_PRE_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000nat\u0000-F\u0000OLD_CILIUM_OUTPUT_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000nat\u0000-F\u0000OLD_CILIUM_POST_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000nat\u0000-F\u0000OLD_CILIUM_PRE_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-I\u0000OUTPUT\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_OUTPUT_nat\u0000-j\u0000CILIUM_OUTPUT_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-I\u0000POSTROUTING\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_POST_nat\u0000-j\u0000CILIUM_POST_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-I\u0000PREROUTING\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_PRE_nat\u0000-j\u0000CILIUM_PRE_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000nat\u0000-N\u0000CILIUM_OUTPUT_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000nat\u0000-N\u0000CILIUM_POST_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000nat\u0000-N\u0000CILIUM_PRE_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000nat\u0000-S",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000nat\u0000-S\u0000CILIUM_OUTPUT_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000nat\u0000-S\u0000CILIUM_POST_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000nat\u0000-S\u0000CILIUM_PRE_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000nat\u0000-S\u0000OLD_CILIUM_OUTPUT_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000nat\u0000-S\u0000OLD_CILIUM_POST_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000nat\u0000-S\u0000OLD_CILIUM_PRE_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000nat\u0000-X\u0000OLD_CILIUM_OUTPUT_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000nat\u0000-X\u0000OLD_CILIUM_POST_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000nat\u0000-X\u0000OLD_CILIUM_PRE_nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-A\u0000CILIUM_OUTPUT_raw\u0000-o\u0000cilium_host\u0000-m\u0000mark\u0000--mark\u00000x00000800/0x00000e00\u0000-m\u0000comment\u0000--comment\u0000cilium: NOTRACK for L7 proxy upstream traffic\u0000-j\u0000CT\u0000--notrack",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-A\u0000CILIUM_OUTPUT_raw\u0000-o\u0000cilium_host\u0000-m\u0000mark\u0000--mark\u00000x00000a00/0xfffffeff\u0000-m\u0000comment\u0000--comment\u0000cilium: NOTRACK for proxy return traffic\u0000-j\u0000CT\u0000--notrack",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-A\u0000CILIUM_OUTPUT_raw\u0000-o\u0000lxc+\u0000-m\u0000mark\u0000--mark\u00000x00000800/0x00000e00\u0000-m\u0000comment\u0000--comment\u0000cilium: NOTRACK for L7 proxy upstream traffic\u0000-j\u0000CT\u0000--notrack",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-A\u0000CILIUM_OUTPUT_raw\u0000-o\u0000lxc+\u0000-m\u0000mark\u0000--mark\u00000x00000a00/0xfffffeff\u0000-m\u0000comment\u0000--comment\u0000cilium: NOTRACK for proxy return traffic\u0000-j\u0000CT\u0000--notrack",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-A\u0000CILIUM_PRE_raw\u0000-m\u0000mark\u0000--mark\u00000x00000200/0x00000f00\u0000-m\u0000comment\u0000--comment\u0000cilium: NOTRACK for proxy traffic\u0000-j\u0000CT\u0000--notrack",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-D\u0000OLD_CILIUM_OUTPUT_raw\u0000-o\u0000cilium_host\u0000-m\u0000mark\u0000--mark\u00000x800/0xe00\u0000-m\u0000comment\u0000--comment\u0000cilium: NOTRACK for L7 proxy upstream traffic\u0000-j\u0000CT\u0000--notrack",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-D\u0000OLD_CILIUM_OUTPUT_raw\u0000-o\u0000cilium_host\u0000-m\u0000mark\u0000--mark\u00000xa00/0xfffffeff\u0000-m\u0000comment\u0000--comment\u0000cilium: NOTRACK for proxy return traffic\u0000-j\u0000CT\u0000--notrack",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-D\u0000OLD_CILIUM_OUTPUT_raw\u0000-o\u0000lxc+\u0000-m\u0000mark\u0000--mark\u00000x800/0xe00\u0000-m\u0000comment\u0000--comment\u0000cilium: NOTRACK for L7 proxy upstream traffic\u0000-j\u0000CT\u0000--notrack",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-D\u0000OLD_CILIUM_OUTPUT_raw\u0000-o\u0000lxc+\u0000-m\u0000mark\u0000--mark\u00000xa00/0xfffffeff\u0000-m\u0000comment\u0000--comment\u0000cilium: NOTRACK for proxy return traffic\u0000-j\u0000CT\u0000--notrack",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-D\u0000OLD_CILIUM_PRE_raw\u0000-m\u0000mark\u0000--mark\u00000x200/0xf00\u0000-m\u0000comment\u0000--comment\u0000cilium: NOTRACK for proxy traffic\u0000-j\u0000CT\u0000--notrack",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-D\u0000OUTPUT\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_OUTPUT_raw\u0000-j\u0000OLD_CILIUM_OUTPUT_raw",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-D\u0000PREROUTING\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_PRE_raw\u0000-j\u0000OLD_CILIUM_PRE_raw",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-E\u0000CILIUM_OUTPUT_raw\u0000OLD_CILIUM_OUTPUT_raw",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-E\u0000CILIUM_PRE_raw\u0000OLD_CILIUM_PRE_raw",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000raw\u0000-F\u0000OLD_CILIUM_OUTPUT_raw",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000raw\u0000-F\u0000OLD_CILIUM_PRE_raw",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-I\u0000OUTPUT\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_OUTPUT_raw\u0000-j\u0000CILIUM_OUTPUT_raw",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-I\u0000PREROUTING\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_PRE_raw\u0000-j\u0000CILIUM_PRE_raw",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000raw\u0000-N\u0000CILIUM_OUTPUT_raw",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000raw\u0000-N\u0000CILIUM_PRE_raw",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000raw\u0000-S",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000raw\u0000-S\u0000CILIUM_OUTPUT_raw",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000raw\u0000-S\u0000CILIUM_PRE_raw",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000raw\u0000-S\u0000OLD_CILIUM_OUTPUT_raw",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000raw\u0000-S\u0000OLD_CILIUM_PRE_raw",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000raw\u0000-X\u0000OLD_CILIUM_OUTPUT_raw",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-t\u0000raw\u0000-X\u0000OLD_CILIUM_PRE_raw",
                name: "/usr/sbin/xtables-nft-multi",
              },
            ],
          },
          {
            kind: "DaemonSet",
            name: "cilium-node-init",
            processes: [
              { arguments: "30", name: "/bin/busybox" },
              {
                arguments:
                  "-t\u00001\u0000-m\u0000-u\u0000-i\u0000-n\u0000-p\u0000--\u0000stat\u0000/tmp/startup-script.kubernetes.io_81dc8a581b97e85076f03766446d2136",
                name: "/usr/bin/nsenter",
              },
              {
                arguments: "/tmp/startup-script.kubernetes.io_81dc8a581b97e85076f03766446d2136",
                name: "/usr/bin/stat",
              },
            ],
          },
          {
            kind: "DaemonSet",
            name: "ebs-csi-node",
            processes: [
              {
                arguments:
                  "--csi-address=/csi/csi.sock\u0000--kubelet-registration-path=/var/lib/kubelet/plugins/ebs.csi.aws.com/csi.sock\u0000--v=2",
                name: "/csi-node-driver-registrar",
              },
              {
                arguments:
                  "--kubelet-registration-path=/var/lib/kubelet/plugins/ebs.csi.aws.com/csi.sock\u0000--mode=kubelet-registration-probe",
                name: "/csi-node-driver-registrar",
              },
              {
                arguments: "--csi-address=/csi/csi.sock",
                name: "/livenessprobe",
              },
              {
                arguments:
                  "node\u0000--endpoint=unix:/csi/csi.sock\u0000--logging-format=text\u0000--v=2",
                connections: [
                  {
                    bytes_received: "273",
                    bytes_sent: "414",
                    destination_name: "172.20.0.1",
                    destination_port: "443",
                  },
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                  },
                ],
                name: "/usr/bin/aws-ebs-csi-driver",
              },
              {
                arguments: "-t\u0000ext4\u0000-o\u0000bind\u0000/var/lib/kub",
                name: "/usr/bin/mount",
              },
              {
                arguments: "-t\u0000ext4\u0000-o\u0000bind,remount\u0000/var/lib/kub",
                name: "/usr/bin/mount",
              },
              {
                arguments:
                  "-t\u0000ext4\u0000-o\u0000defaults\u0000/dev/nvme1n1\u0000/var/lib/kubelet/plugins/kubernetes.io/csi/ebs.csi.aws.com/4cad05a221786dee655713d4571951e859cfc9caf04ae3455a50909338be413d/globalmount",
                name: "/usr/bin/mount",
              },
              {
                arguments:
                  "-p\u0000-s\u0000TYPE\u0000-s\u0000PTTYPE\u0000-o\u0000export\u0000/dev/nvme1n1",
                name: "/usr/sbin/blkid",
              },
              {
                arguments: "--getro\u0000/dev/nvme1n1",
                name: "/usr/sbin/blockdev",
              },
              {
                arguments: "--getsize64\u0000/dev/nvme1n1",
                name: "/usr/sbin/blockdev",
              },
              {
                arguments: "-h\u0000/dev/nvme1n1",
                name: "/usr/sbin/dumpe2fs",
              },
              { arguments: "-a\u0000/dev/nvme1n1", name: "/usr/sbin/fsck" },
              {
                arguments: "-a\u0000/dev/nvme1n1",
                name: "/usr/sbin/fsck.ext4",
              },
            ],
          },
          {
            kind: "DaemonSet",
            name: "kube-proxy",
            processes: [
              {
                connections: [
                  {
                    bytes_received: "11752100",
                    bytes_sent: "2046320",
                    destination_name: "10.3.7.110",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "8103490",
                    bytes_sent: "1543493",
                    destination_name:
                      "3be81fd965b44e29ee37641b4d0f95cd.gr7.us-west-2.eks.amazonaws.com",
                    destination_port: "443",
                  },
                ],
                name: "/usr/local/bin/kube-proxy",
              },
              {
                arguments:
                  "-D\u0000--orig-dst\u0000172.20.0.10\u0000--dst-nat\u000010.3.5.212\u0000-p\u0000udp",
                name: "/usr/sbin/conntrack",
              },
              {
                arguments:
                  "-D\u0000--orig-dst\u0000172.20.0.10\u0000--dst-nat\u000010.3.6.45\u0000-p\u0000udp",
                name: "/usr/sbin/conntrack",
              },
              {
                arguments: "-t\u0000nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments: "-w\u00005\u0000-W\u0000100000\u0000--noflush\u0000--counters",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000FORWARD\u0000-t\u0000filter\u0000-m\u0000comment\u0000--comment\u0000kubernetes forwarding rules\u0000-j\u0000KUBE-FORWARD",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000FORWARD\u0000-t\u0000filter\u0000-m\u0000conntrack\u0000--ctstate\u0000NEW\u0000-m\u0000comment\u0000--comment\u0000kubernetes externally-visible service portals\u0000-j\u0000KUBE-EXTERNAL-SERVICES",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000FORWARD\u0000-t\u0000filter\u0000-m\u0000conntrack\u0000--ctstate\u0000NEW\u0000-m\u0000comment\u0000--comment\u0000kubernetes load balancer firewall\u0000-j\u0000KUBE-PROXY-FIREWALL",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000FORWARD\u0000-t\u0000filter\u0000-m\u0000conntrack\u0000--ctstate\u0000NEW\u0000-m\u0000comment\u0000--comment\u0000kubernetes service portals\u0000-j\u0000KUBE-SERVICES",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000INPUT\u0000-t\u0000filter\u0000-j\u0000KUBE-FIREWALL",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000INPUT\u0000-t\u0000filter\u0000-m\u0000comment\u0000--comment\u0000kubernetes health check service ports\u0000-j\u0000KUBE-NODEPORTS",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000INPUT\u0000-t\u0000filter\u0000-m\u0000conntrack\u0000--ctstate\u0000NEW\u0000-m\u0000comment\u0000--comment\u0000kubernetes externally-visible service portals\u0000-j\u0000KUBE-EXTERNAL-SERVICES",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000INPUT\u0000-t\u0000filter\u0000-m\u0000conntrack\u0000--ctstate\u0000NEW\u0000-m\u0000comment\u0000--comment\u0000kubernetes load balancer firewall\u0000-j\u0000KUBE-PROXY-FIREWALL",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000OUTPUT\u0000-t\u0000filter\u0000-j\u0000KUBE-FIREWALL",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000OUTPUT\u0000-t\u0000filter\u0000-m\u0000conntrack\u0000--ctstate\u0000NEW\u0000-m\u0000comment\u0000--comment\u0000kubernetes load balancer firewall\u0000-j\u0000KUBE-PROXY-FIREWALL",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000OUTPUT\u0000-t\u0000filter\u0000-m\u0000conntrack\u0000--ctstate\u0000NEW\u0000-m\u0000comment\u0000--comment\u0000kubernetes service portals\u0000-j\u0000KUBE-SERVICES",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000OUTPUT\u0000-t\u0000nat\u0000-m\u0000comment\u0000--comment\u0000kubernetes service portals\u0000-j\u0000KUBE-SERVICES",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000POSTROUTING\u0000-t\u0000nat\u0000-m\u0000comment\u0000--comment\u0000kubernetes postrouting rules\u0000-j\u0000KUBE-POSTROUTING",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000PREROUTING\u0000-t\u0000nat\u0000-m\u0000comment\u0000--comment\u0000kubernetes service portals\u0000-j\u0000KUBE-SERVICES",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-N\u0000KUBE-EXTERNAL-SERVICES\u0000-t\u0000filter",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-N\u0000KUBE-FIREWALL\u0000-t\u0000filter",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-N\u0000KUBE-FORWARD\u0000-t\u0000filter",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-N\u0000KUBE-NODEPORTS\u0000-t\u0000filter",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-N\u0000KUBE-POSTROUTING\u0000-t\u0000nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-N\u0000KUBE-PROXY-FIREWALL\u0000-t\u0000filter",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-N\u0000KUBE-SERVICES\u0000-t\u0000filter",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-N\u0000KUBE-SERVICES\u0000-t\u0000nat",
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-S\u0000KUBE-PROXY-CANARY\u0000-t\u0000mangle",
                name: "/usr/sbin/xtables-nft-multi",
              },
            ],
          },
        ],
      },
      {
        name: "kubeshark",
        workloads: [
          {
            kind: "DaemonSet",
            name: "kubeshark-worker-daemon-set",
            processes: [
              {
                connections: [
                  {
                    bytes_received: "18637494",
                    bytes_sent: "2404107",
                    destination_name: "172.20.0.1",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "15057315",
                    bytes_sent: "77672",
                    destination_name: "172.20.189.207",
                    destination_port: "80",
                  },
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "268070595",
                    bytes_sent: "2008696",
                    destination_name: "kubeshark-hub.kubeshark.svc.cluster.local",
                    destination_port: "80",
                  },
                ],
                name: "/app/tracer",

                in_init_tree: false,
              },
              {
                connections: [
                  {
                    bytes_received: "985740",
                    bytes_sent: "20326",
                    destination_name: "172.20.0.1",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "942434637",
                    bytes_sent: "414501",
                    destination_name: "172.20.189.207",
                    destination_port: "80",
                  },
                  {
                    bytes_received: "6319",
                    bytes_sent: "1338",
                    destination_name: "api.kubeshark.co",
                    destination_port: "443",
                  },
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "120",
                    bytes_sent: "180",
                    destination_name: "kubeshark-hub.kubeshark.svc.cluster.local",
                    destination_port: "80",
                  },
                ],
                name: "/app/worker",
              },
              {
                arguments:
                  "-i\u0000any\u0000-port\u000030001\u0000-metrics-port\u000049100\u0000-packet-capture\u0000best\u0000-unixsocket\u0000-servicemesh\u0000-procfs\u0000/hostproc\u0000-disable-ebpf\u0000-resolution-strategy\u0000auto",
                connections: [
                  {
                    bytes_received: "6371",
                    bytes_sent: "1345",
                    destination_name: "api.kubeshark.co",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "175485260",
                    bytes_sent: "146522880",
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "18197507184",
                    bytes_sent: "9051394",
                    destination_name: "kubeshark-hub.kubeshark.svc.cluster.local",
                    destination_port: "80",
                  },
                ],
                name: "/app/worker",
              },
              { arguments: "CLK_TCK", name: "/bin/getconf" },
              { arguments: "PAGESIZE", name: "/bin/getconf" },
            ],
          },
        ],
      },
      {
        name: "logging",
        workloads: [
          {
            kind: "DaemonSet",
            name: "promtail",
            processes: [
              {
                arguments:
                  "-config.file=/etc/promtail/promtail.yaml\u0000-client.external-labels=cluster=df-tetragon-dev-ce-01\u0000-config.expand-env=true",
                connections: [
                  {
                    bytes_received: "3304771",
                    bytes_sent: "2344319",
                    destination_name: "172.20.0.1",
                    destination_port: "443",
                  },
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                  },
                  {
                    bytes_sent: "60",
                    destination_name: "logs-prod3.grafana.net",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "48641647",
                    bytes_sent: "2699267412",
                    destination_name: "loki-gateway.logging.svc.cluster.local",
                    destination_port: "80",
                  },
                ],
                name: "/usr/bin/promtail",
              },
            ],
          },
        ],
      },
      {
        name: "monitoring",
        workloads: [
          {
            kind: "DaemonSet",
            name: "kube-prometheus-stack-prometheus-node-exporter",
            processes: [
              {
                arguments:
                  "--path.procfs=/host/proc\u0000--path.sysfs=/host/sys\u0000--path.rootfs=/host/root\u0000--path.udev.data=/host/root/run/udev/data\u0000--web.listen-address=[0.0.0.0]:9100\u0000--collector.filesystem.mount-points-exclude=^/(dev|proc|sys|var/lib/docker/.",
                name: "/bin/node_exporter",
              },
            ],
          },
          {
            kind: "StatefulSet",
            name: "prometheus-kube-prometheus-stack-prometheus",
            processes: [
              {
                arguments: "--",
                connections: [
                  {
                    bytes_received: "412919064",
                    bytes_sent: "13613469",
                    destination_name:
                      "3be81fd965b44e29ee37641b4d0f95cd.gr7.us-west-2.eks.amazonaws.com",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "67884830",
                    bytes_sent: "9342252",
                    destination_name: "alloy/Deployment:alloy",
                    destination_port: "12345",
                  },
                  {
                    bytes_received: "43544065",
                    bytes_sent: "8635348",
                    destination_name: "argocd/Deployment:argo-cd-argocd-applicationset-controller",
                    destination_port: "8080",
                  },
                  {
                    bytes_received: "31489457",
                    bytes_sent: "8635252",
                    destination_name: "argocd/Deployment:argo-cd-argocd-notifications-controller",
                    destination_port: "9001",
                  },
                  {
                    bytes_received: "42791024",
                    bytes_sent: "8633469",
                    destination_name: "argocd/Deployment:argo-cd-argocd-repo-server",
                    destination_port: "8084",
                  },
                  {
                    bytes_received: "76381806",
                    bytes_sent: "9343688",
                    destination_name: "argocd/StatefulSet:argo-cd-argocd-application-controller",
                    destination_port: "8082",
                  },
                  {
                    bytes_received: "62870484",
                    bytes_sent: "24729914",
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "235657217",
                    bytes_sent: "19396927",
                    destination_name: "ingress-nginx/Deployment:ingress-nginx-controller",
                    destination_port: "10254",
                  },
                  {
                    bytes_received: "5718334528",
                    bytes_sent: "103966684",
                    destination_name: "ip-10-3-6-166.us-west-2.compute.internal",
                    destination_port: "2112",
                  },
                  {
                    bytes_received: "1674926091",
                    bytes_sent: "70097364",
                    destination_name: "ip-10-3-6-166.us-west-2.compute.internal",
                    destination_port: "9100",
                  },
                  {
                    bytes_received: "723830437",
                    bytes_sent: "30149122",
                    destination_name: "ip-10-3-6-166.us-west-2.compute.internal",
                    destination_port: "9962",
                  },
                  {
                    bytes_received: "2682874159",
                    bytes_sent: "136397795",
                    destination_name: "ip-10-3-6-166.us-west-2.compute.internal",
                    destination_port: "9965",
                  },
                  {
                    bytes_received: "181704505",
                    bytes_sent: "29328174",
                    destination_name: "ip-10-3-6-166.us-west-2.compute.internal",
                    destination_port: "10249",
                  },
                  {
                    bytes_received: "36007057581",
                    bytes_sent: "978120218",
                    destination_name: "ip-10-3-6-166.us-west-2.compute.internal",
                    destination_port: "10250",
                  },
                  {
                    bytes_received: "1567813012",
                    bytes_sent: "32756815",
                    destination_name: "karpenter/Deployment:karpenter",
                    destination_port: "8080",
                  },
                  {
                    bytes_received: "6018009908",
                    bytes_sent: "110818231",
                    destination_name: "kube-system/DaemonSet:cilium",
                    destination_port: "2112",
                  },
                  {
                    bytes_received: "1477099888",
                    bytes_sent: "60178731",
                    destination_name: "kube-system/DaemonSet:cilium",
                    destination_port: "9962",
                  },
                  {
                    bytes_received: "600",
                    bytes_sent: "900",
                    destination_name: "kube-system/DaemonSet:cilium",
                    destination_port: "9965",
                  },
                  {
                    bytes_received: "362822194",
                    bytes_sent: "58583217",
                    destination_name: "kube-system/DaemonSet:cilium",
                    destination_port: "10249",
                  },
                  {
                    bytes_received: "3455263607",
                    bytes_sent: "97798089",
                    destination_name: "kube-system/DaemonSet:cilium",
                    destination_port: "10250",
                  },
                  {
                    bytes_received: "1956262955",
                    bytes_sent: "38028608",
                    destination_name: "kube-system/DaemonSet:cilium-node-init",
                    destination_port: "2112",
                  },
                  {
                    bytes_received: "725763136",
                    bytes_sent: "29982318",
                    destination_name: "kube-system/DaemonSet:cilium-node-init",
                    destination_port: "9962",
                  },
                  {
                    bytes_received: "347102707",
                    bytes_sent: "25391644",
                    destination_name: "kube-system/DaemonSet:cilium-node-init",
                    destination_port: "9965",
                  },
                  {
                    bytes_received: "181496559",
                    bytes_sent: "29288327",
                    destination_name: "kube-system/DaemonSet:cilium-node-init",
                    destination_port: "10249",
                  },
                  {
                    bytes_received: "3584987273",
                    bytes_sent: "108887193",
                    destination_name: "kube-system/DaemonSet:cilium-node-init",
                    destination_port: "10250",
                  },
                  {
                    bytes_received: "106369700",
                    bytes_sent: "54377335",
                    destination_name: "kube-system/Deployment:coredns",
                    destination_port: "9153",
                  },
                  {
                    bytes_received: "1482324690",
                    bytes_sent: "101829724",
                    destination_name: "logging/DaemonSet:promtail",
                    destination_port: "3101",
                  },
                  {
                    bytes_received: "151961747",
                    bytes_sent: "10051330",
                    destination_name: "logging/Deployment:loki-compactor",
                    destination_port: "3100",
                  },
                  {
                    bytes_received: "169410849",
                    bytes_sent: "10051557",
                    destination_name: "logging/Deployment:loki-distributor",
                    destination_port: "3100",
                  },
                  {
                    bytes_received: "278362359",
                    bytes_sent: "18682058",
                    destination_name: "logging/Deployment:loki-query-frontend",
                    destination_port: "3100",
                  },
                  {
                    bytes_received: "229642776",
                    bytes_sent: "11388632",
                    destination_name: "logging/StatefulSet:loki-ingester",
                    destination_port: "3100",
                  },
                  {
                    bytes_received: "195028981",
                    bytes_sent: "17255523",
                    destination_name: "logging/StatefulSet:loki-memcached-chunks",
                    destination_port: "9150",
                  },
                  {
                    bytes_received: "39897990",
                    bytes_sent: "7927012",
                    destination_name: "logging/StatefulSet:loki-memcached-frontend",
                    destination_port: "9150",
                  },
                  {
                    bytes_received: "317332990",
                    bytes_sent: "20059984",
                    destination_name: "logging/StatefulSet:loki-querier",
                    destination_port: "3100",
                  },
                  {
                    bytes_received: "345069116",
                    bytes_sent: "12683830",
                    destination_name: "monitoring/Deployment:kube-prometheus-stack-grafana",
                    destination_port: "3000",
                  },
                  {
                    bytes_received: "38315927193",
                    bytes_sent: "412764638",
                    destination_name:
                      "monitoring/Deployment:kube-prometheus-stack-kube-state-metrics",
                    destination_port: "8080",
                  },
                  {
                    bytes_received: "121118723",
                    bytes_sent: "10577638",
                    destination_name: "monitoring/Deployment:kube-prometheus-stack-operator",
                    destination_port: "10250",
                  },
                  {
                    bytes_received: "85459772",
                    bytes_sent: "9345237",
                    destination_name:
                      "monitoring/StatefulSet:alertmanager-kube-prometheus-stack-alertmanager",
                    destination_port: "8080",
                  },
                  {
                    bytes_received: "76209878",
                    bytes_sent: "48169023",
                    destination_name:
                      "monitoring/StatefulSet:alertmanager-kube-prometheus-stack-alertmanager",
                    destination_port: "9093",
                  },
                  {
                    bytes_received: "85649683",
                    bytes_sent: "9344804",
                    destination_name:
                      "monitoring/StatefulSet:prometheus-kube-prometheus-stack-prometheus",
                    destination_port: "8080",
                  },
                  {
                    bytes_received: "346468302",
                    bytes_sent: "12905875",
                    destination_name:
                      "monitoring/StatefulSet:prometheus-kube-prometheus-stack-prometheus",
                    destination_port: "9090",
                  },
                  {
                    bytes_received: "57436270",
                    bytes_sent: "8622413",
                    destination_name: "otel-collector/Deployment:opentelemetry-operator",
                    destination_port: "8080",
                  },
                  {
                    bytes_received: "115421141",
                    bytes_sent: "8718905",
                    destination_name: "otel-collector/Deployment:opentelemetry-operator",
                    destination_port: "8443",
                  },
                  {
                    bytes_received: "332435209",
                    bytes_sent: "5262176",
                    destination_name: "tenant-jobs/Pod:attacker-pod",
                    destination_port: "2112",
                  },
                  {
                    bytes_received: "10248520900",
                    bytes_sent: "219875347",
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "2112",
                  },
                  {
                    bytes_received: "955474933",
                    bytes_sent: "43900338",
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "9100",
                  },
                  {
                    bytes_received: "4479547949",
                    bytes_sent: "180788292",
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "9962",
                  },
                  {
                    bytes_received: "478601166",
                    bytes_sent: "47457858",
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "9963",
                  },
                  {
                    bytes_received: "1614423758",
                    bytes_sent: "102680267",
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "9965",
                  },
                  {
                    bytes_received: "1101061436",
                    bytes_sent: "176104137",
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "10249",
                  },
                  {
                    bytes_received: "19587125758",
                    bytes_sent: "591066194",
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "10250",
                  },
                  {
                    bytes_received: "143123895",
                    bytes_sent: "21617697",
                    destination_name: "tetragon/Deployment:tetragon-operator",
                    destination_port: "2113",
                  },
                ],
                name: "/bin/prometheus",
              },
              {
                arguments: "--listen-address=:8080\u0000--relo",
                connections: [
                  {
                    bytes_received: "578",
                    bytes_sent: "820",
                    destination_name: "127.0.0.1",
                    destination_port: "9090",
                  },
                ],
                name: "/bin/prometheus-config-reloader",
              },
              { arguments: "--wa", name: "/bin/prometheus-config-reloader" },
            ],
          },
        ],
      },
      {
        name: "otel-collector",
        workloads: [
          {
            kind: "DaemonSet",
            name: "otel-collector",
            processes: [
              {
                connections: [
                  {
                    bytes_received: "1310123585",
                    bytes_sent: "25869626",
                    destination_name: "10.3.6.166",
                    destination_port: "2112",
                  },
                  {
                    bytes_received: "970990",
                    bytes_sent: "99440",
                    destination_name: "172.20.170.76",
                    destination_port: "80",
                  },
                  {
                    bytes_received: "2066270",
                    bytes_sent: "32587583",
                    destination_name: "35.190.55.74",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "459021862",
                    bytes_sent: "8749575",
                    destination_name: "ip-10-3-6-166.us-west-2.compute.internal",
                    destination_port: "2112",
                  },
                  {
                    bytes_received: "830775996",
                    bytes_sent: "24617515",
                    destination_name: "ip-10-3-6-166.us-west-2.compute.internal",
                    destination_port: "10250",
                  },
                  {
                    bytes_received: "291718656",
                    bytes_sent: "29926676",
                    destination_name: "otel-targetallocator.otel-collector.svc.cluster.local",
                    destination_port: "80",
                  },
                  {
                    destination_name: "otlp-gateway-prod-us-central-0.grafana.net",
                    destination_port: "443",
                  },
                ],
                name: "/otelcol-contrib",
              },
            ],
          },
        ],
      },
      {
        name: "tetragon",
        workloads: [
          {
            kind: "DaemonSet",
            name: "tetragon",
            processes: [
              { name: "/bin/busybox" },
              {
                connections: [
                  {
                    bytes_received: "13564330",
                    bytes_sent: "5442862",
                    destination_name: "172.20.0.1",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "368",
                    bytes_sent: "300",
                    destination_name: "52.94.181.132",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "292193",
                    bytes_sent: "27176253",
                    destination_name: "54.188.97.27",
                    destination_port: "443",
                  },
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "285510",
                    bytes_sent: "25493397",
                    destination_name: "ingestion.us-west-2.dataplane.sonar.networking.aws.dev",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "9154",
                    bytes_sent: "4345",
                    destination_name: "sts.us-west-2.amazonaws.com",
                    destination_port: "443",
                  },
                ],
                name: "/usr/bin/tetragon",
              },
              {
                arguments:
                  "-hostMntNs\u00004026531841\u0000-scannerFifoPath\u0000/var/run/cilium/hubble/fs_scanner.sock\u0000-maxSizeFileDigest\u00001073741824\u0000-maxTimeoutFileDigest\u000030\u0000-logLevel\u0000info\u0000-logFormat\u0000text",
                name: "/var/lib/tetragon/tetragon-fs-scanner",
              },
              {
                arguments:
                  "/procRoot/1/ns/mnt\u0000/var/lib/tetragon/tetragon-fs-scanner\u0000-hostMntNs\u00004026531841\u0000-scannerFifoPath\u0000/var/run/cilium/hubble/fs_scanner.sock\u0000-maxSizeFileDigest\u00001073741824\u0000-maxTimeoutFileDigest\u000030\u0000-logLevel\u0000info\u0000-logFormat\u0000text",
                name: "/var/lib/tetragon/tetragon-runner",
              },
            ],
          },
        ],
      },
      {
        name: "vector",
        workloads: [
          {
            kind: "DaemonSet",
            name: "vector",
            processes: [
              {
                arguments: "--config-dir\u0000/etc/vector/",
                connections: [
                  {
                    destination_name: "172.20.1.197",
                    destination_port: "8080",
                  },
                  {
                    destination_name: "52.25.78.95",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "5209547",
                    bytes_sent: "683161518",
                    destination_name: "http-inputs.cisco-ngfwbu-valent.splunkcloud.com",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "57108273",
                    bytes_sent: "22759933871",
                    destination_name: "squash.tetragon.svc.cluster.local",
                    destination_port: "8080",
                  },
                ],
                name: "/usr/bin/vector",
              },
            ],
          },
        ],
      },
    ],
  },
};
