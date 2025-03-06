export const model = {
  application_model: {
    host: {
      processes: [
        {
          arguments: "/etc/update-motd.d/10-nvidia-eula",
          name: "/usr/bin/bash",
        },
        {
          arguments: "/etc/update-motd.d/70-available-updates",
          name: "/usr/bin/bash",
        },
        { arguments: "/usr/sbin/update-motd", name: "/usr/bin/bash" },
        { arguments: "/tmp/motd.part9jRcA", name: "/usr/bin/cat" },
        { arguments: "/tmp/motd.partJ9Hri", name: "/usr/bin/cat" },
        {
          arguments: "go+r\u0000/var/lib/update-motd/tmp.d2fwXjkimL",
          name: "/usr/bin/chmod",
        },
        { name: "/usr/bin/containerd" },
        {
          arguments:
            'function pline() { printf any?"%s\\n":"\\n%s\\n", $0; any=1; }\n         /newer release.*is available/  { sub("^ *", ""); pline(); }\n         /new v',
          name: "/usr/bin/gawk",
        },
        { arguments: "-Pzo\u0000.*Updates(.*\\n)*", name: "/usr/bin/grep" },
        { arguments: "-q\u0000kmod-nvidia", name: "/usr/bin/grep" },
        { arguments: "--fqdn", name: "/usr/bin/hostname" },
        { arguments: "-u", name: "/usr/bin/id" },
        {
          connections: [
            {
              bytes_received: "21688662",
              bytes_sent: "11578653",
              destination_name: "10.3.5.178",
              destination_port: "443",
            },
            {
              bytes_received: "3211488",
              bytes_sent: "3716232",
              destination_name: "127.0.0.1",
              destination_port: "9879",
            },
            {
              destination_name:
                "3BE81FD965B44E29EE37641B4D0F95CD.gr7.us-west-2.eks.amazonaws.com",
              destination_port: "443",
            },
            {
              bytes_received: "5361996",
              bytes_sent: "5516148",
              destination_name:
                "argocd/StatefulSet:argo-cd-argocd-application-controller",
              destination_port: "8082",
            },
            {
              bytes_received: "279111",
              bytes_sent: "394506",
              destination_name: "ip-10-3-7-199.us-west-2.compute.internal",
              destination_port: "6789",
            },
            {
              bytes_received: "36582201",
              bytes_sent: "9999516",
              destination_name: "ip-10-3-7-199.us-west-2.compute.internal",
              destination_port: "9100",
            },
            {
              bytes_received: "30403011",
              bytes_sent: "58047984",
              destination_name: "ip-10-3-7-199.us-west-2.compute.internal",
              destination_port: "30001",
            },
            {
              bytes_received: "5346153",
              bytes_sent: "5336301",
              destination_name: "kube-system/DaemonSet:ebs-csi-node",
              destination_port: "9808",
            },
            {
              bytes_received: "5489199",
              bytes_sent: "5245275",
              destination_name: "logging/DaemonSet:promtail",
              destination_port: "3101",
            },
            {
              bytes_received: "3002496",
              bytes_sent: "5789280",
              destination_name: "logging/StatefulSet:loki-memcached-chunks",
              destination_port: "11211",
            },
          ],
          name: "/usr/bin/kubelet",
        },
        { arguments: "--tmpdir\u0000motd.partXXXXX", name: "/usr/bin/mktemp" },
        {
          arguments: "--tmpdir=/var/lib/update-motd/",
          name: "/usr/bin/mktemp",
        },
        {
          arguments:
            "/var/lib/update-motd/tmp.d2fwXjkimL\u0000/var/lib/update-motd/motd",
          name: "/usr/bin/mv",
        },
        {
          arguments: "-e\u0000-o\u0000pid,ppid,state,command",
          name: "/usr/bin/ps",
        },
        {
          arguments: "/usr/bin/dnf\u0000--debuglevel\u00002\u0000updateinfo",
          connections: [
            {
              bytes_received: "36263",
              bytes_sent: "6437",
              destination_name:
                "al2023-repos-us-west-2-de612dc2.s3.dualstack.us-west-2.amazonaws.com",
              destination_port: "443",
            },
          ],
          name: "/usr/bin/python3.9",
        },
        {
          arguments: "/usr/bin/dnf\u0000check-release-update",
          connections: [
            {
              bytes_received: "539335",
              bytes_sent: "3395",
              destination_name:
                "al2023-repos-us-west-2-de612dc2.s3.dualstack.us-west-2.amazonaws.com",
              destination_port: "443",
            },
          ],
          name: "/usr/bin/python3.9",
        },
        { arguments: "-f\u0000/tmp/motd.part9jRcA", name: "/usr/bin/rm" },
        { arguments: "-f\u0000/tmp/motd.partJ9Hri", name: "/usr/bin/rm" },
        {
          arguments: "-q\u0000--quiet\u0000dnf-plugin-release-notification",
          name: "/usr/bin/rpm",
        },
        { arguments: "-qa", name: "/usr/bin/rpm" },
        {
          connections: [
            {
              bytes_received: "1212290",
              bytes_sent: "972124",
              destination_name: "169.254.169.254",
              destination_port: "80",
            },
            {
              bytes_received: "92680",
              bytes_sent: "113818",
              destination_name: "52.94.186.93",
              destination_port: "443",
            },
            {
              bytes_received: "14046",
              bytes_sent: "7548",
              destination_name: "ssm.us-west-2.amazonaws.com",
              destination_port: "443",
            },
            {
              bytes_received: "255366",
              bytes_sent: "293310",
              destination_name: "ssmmessages.us-west-2.amazonaws.com",
              destination_port: "443",
            },
          ],
          name: "/usr/bin/ssm-agent-worker",
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
          arguments:
            "30s\u0000/usr/bin/dnf\u0000--debuglevel\u00002\u0000updateinfo",
          name: "/usr/bin/timeout",
        },
        {
          arguments: "30s\u0000/usr/bin/dnf\u0000check-release-update",
          name: "/usr/bin/timeout",
        },
        { arguments: "-rs", name: "/usr/bin/uname" },
        {
          arguments:
            "eks\u0000get-token\u0000--cluster-name\u0000df-tetragon-dev-ce-01\u0000--region\u0000us-west-2",
          connections: [
            {
              bytes_received: "8844905",
              bytes_sent: "4123612",
              destination_name: "169.254.169.254",
              destination_port: "80",
            },
          ],
          name: "/usr/local/aws-cli/v2/2.23.0/dist/aws",
        },
        { arguments: "--", name: "/usr/sbin/runc" },
        { arguments: "--r", name: "/usr/sbin/runc" },
        { arguments: "--ro", name: "/usr/sbin/runc" },
        { arguments: "--roo", name: "/usr/sbin/runc" },
        { arguments: "--root", name: "/usr/sbin/runc" },
        { arguments: "init", name: "/usr/sbin/runc" },
        { name: "/usr/sbin/sshd" },
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
        name: "argocd",
        workloads: [
          {
            kind: "StatefulSet",
            name: "argo-cd-argocd-application-controller",
            processes: [
              {
                connections: [
                  {
                    bytes_received: "1624135098",
                    bytes_sent: "60934428",
                    destination_name: "172.20.0.1",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "586164",
                    bytes_sent: "102963420",
                    destination_name: "172.20.159.176",
                    destination_port: "6379",
                  },
                  {
                    destination_name:
                      "argo-cd-argocd-redis.argocd.svc.cluster.local",
                    destination_port: "6379",
                  },
                  {
                    bytes_received: "4101813801",
                    bytes_sent: "300587517",
                    destination_name:
                      "argo-cd-argocd-repo-server.argocd.svc.cluster.local",
                    destination_port: "8081",
                  },
                  {
                    bytes_received: "844153209",
                    bytes_sent: "28723917",
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                  },
                ],
                name: "/usr/local/bin/argocd",
              },
            ],
          },
        ],
      },
      {
        name: "hubble-enterprise",
        workloads: [
          {
            kind: "DaemonSet",
            name: "hubble-enterprise",
            processes: [
              {
                connections: [
                  {
                    bytes_received: "5548",
                    bytes_sent: "232604",
                    destination_name: "3.5.84.180",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "21950",
                    bytes_sent: "441902",
                    destination_name:
                      "al2023-repos-us-west-2-de612dc2.s3.dualstack.us-west-2.amazonaws.com",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "945660",
                    bytes_sent: "18648840",
                    destination_name:
                      "df-tetragon-dev-ce-01-logs.s3.us-west-2.amazonaws.com",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "36156208",
                    bytes_sent: "5289030718",
                    destination_name:
                      "hubble-timescape-ingester.hubble-timescape.svc.cluster.local",
                    destination_port: "4260",
                  },
                  {
                    bytes_received: "253960",
                    bytes_sent: "100228",
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
                connections: [
                  {
                    bytes_received: "748569",
                    bytes_sent: "922899",
                    destination_name: "10.3.5.114",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "748569",
                    bytes_sent: "922899",
                    destination_name: "10.3.5.170",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "748413",
                    bytes_sent: "922743",
                    destination_name: "10.3.5.197",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "748569",
                    bytes_sent: "922899",
                    destination_name: "10.3.5.227",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "748569",
                    bytes_sent: "922899",
                    destination_name: "10.3.5.242",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "748569",
                    bytes_sent: "920664",
                    destination_name: "10.3.5.54",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "748413",
                    bytes_sent: "920508",
                    destination_name: "10.3.5.74",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "748569",
                    bytes_sent: "920664",
                    destination_name: "10.3.5.92",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "748413",
                    bytes_sent: "922743",
                    destination_name: "10.3.6.166",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "748761",
                    bytes_sent: "923202",
                    destination_name: "10.3.6.177",
                    destination_port: "4240",
                  },
                  { destination_name: "10.3.6.228", destination_port: "4240" },
                  {
                    bytes_received: "748569",
                    bytes_sent: "922899",
                    destination_name: "10.3.6.236",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "748569",
                    bytes_sent: "920664",
                    destination_name: "10.3.6.50",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "748569",
                    bytes_sent: "920664",
                    destination_name: "10.3.6.97",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "16249350",
                    bytes_sent: "5043192",
                    destination_name: "10.3.7.110",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "1032258",
                    bytes_sent: "1380918",
                    destination_name: "10.3.7.151",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "748569",
                    bytes_sent: "922899",
                    destination_name: "10.3.7.199",
                    destination_port: "4240",
                  },
                  {
                    bytes_received: "748413",
                    bytes_sent: "922743",
                    destination_name: "10.3.8.221",
                    destination_port: "4240",
                  },
                  { destination_name: "10.3.8.33", destination_port: "4240" },
                  {
                    bytes_received: "748569",
                    bytes_sent: "920664",
                    destination_name: "10.3.8.67",
                    destination_port: "4240",
                  },
                  { destination_name: "10.3.8.68", destination_port: "4240" },
                  {
                    destination_name:
                      "3BE81FD965B44E29EE37641B4D0F95CD.gr7.us-west-2.eks.amazonaws.com",
                    destination_port: "443",
                  },
                  {
                    destination_name:
                      "ip-10-3-7-199.us-west-2.compute.internal",
                    destination_port: "4240",
                  },
                ],
                name: "/usr/bin/cilium-agent",
              },
              {
                connections: [
                  {
                    bytes_received: "4752",
                    bytes_sent: "15616",
                    destination_name:
                      "monitoring/Deployment:kube-prometheus-stack-grafana",
                    destination_port: "3000",
                  },
                  {
                    bytes_received: "78548",
                    bytes_sent: "1556",
                    destination_name:
                      "otel-demo/Deployment:otel-demo-frontendproxy",
                    destination_port: "8080",
                  },
                ],
                name: "/usr/bin/cilium-envoy",
              },
              {
                arguments: "--version",
                in_init_tree: false,
                name: "/usr/bin/cilium-envoy",
              },
              { in_init_tree: false, name: "/usr/bin/cilium-health-responder" },
              {
                arguments: "-j\u0000map\u0000show",
                in_init_tree: false,
                name: "/usr/local/bin/bpftool",
              },
              {
                arguments: "-j\u0000prog\u0000show",
                in_init_tree: false,
                name: "/usr/local/bin/bpftool",
              },
              {
                arguments:
                  "create\u0000cilium_node_set_v4\u0000iphash\u0000family\u0000inet\u0000-exist",
                in_init_tree: false,
                name: "/usr/sbin/ipset",
              },
              {
                arguments:
                  "create\u0000cilium_node_set_v6\u0000iphash\u0000family\u0000inet6\u0000-exist",
                in_init_tree: false,
                name: "/usr/sbin/ipset",
              },
              {
                arguments: "list\u0000cilium_node_set_v4",
                in_init_tree: false,
                name: "/usr/sbin/ipset",
              },
              {
                arguments: "list\u0000cilium_node_set_v6",
                in_init_tree: false,
                name: "/usr/sbin/ipset",
              },
              {
                arguments: "restore",
                in_init_tree: false,
                name: "/usr/sbin/ipset",
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
                arguments:
                  "/tmp/startup-script.kubernetes.io_81dc8a581b97e85076f03766446d2136",
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
                  "--kubelet-registration-path=/var/lib/kubelet/plugins/ebs.csi.aws.com/csi.sock\u0000--mode=kubelet-registration-probe",
                in_init_tree: false,
                name: "/csi-node-driver-registrar",
              },
              { in_init_tree: false, name: "/livenessprobe" },
            ],
          },
          {
            kind: "DaemonSet",
            name: "kube-proxy",
            processes: [
              {
                connections: [
                  {
                    bytes_received: "6690819",
                    bytes_sent: "1178022",
                    destination_name: "10.3.7.110",
                    destination_port: "443",
                  },
                  {
                    destination_name:
                      "3BE81FD965B44E29EE37641B4D0F95CD.gr7.us-west-2.eks.amazonaws.com",
                    destination_port: "443",
                  },
                ],
                name: "/usr/local/bin/kube-proxy",
              },
              {
                arguments: "-t\u0000nat",
                in_init_tree: false,
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000--noflush\u0000--counters",
                in_init_tree: false,
                name: "/usr/sbin/xtables-nft-multi",
              },
              {
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-S\u0000KUBE-PROXY-CANARY\u0000-t\u0000mangle",
                in_init_tree: false,
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
                    bytes_received: "356502",
                    bytes_sent: "51254",
                    destination_name: "172.20.0.1",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "3231528",
                    bytes_sent: "17598",
                    destination_name: "172.20.189.207",
                    destination_port: "80",
                  },
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                  },
                  {
                    destination_name:
                      "kubeshark-hub.kubeshark.svc.cluster.local",
                    destination_port: "80",
                  },
                ],
                name: "/app/tracer",
              },
              {
                connections: [
                  {
                    bytes_received: "3575655",
                    bytes_sent: "746778",
                    destination_name: "172.20.0.1",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "268380549",
                    bytes_sent: "149337",
                    destination_name: "172.20.189.207",
                    destination_port: "80",
                  },
                  {
                    bytes_received: "14258685",
                    bytes_sent: "3068187",
                    destination_name: "api.kubeshark.co",
                    destination_port: "443",
                  },
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                  },
                  {
                    destination_name:
                      "kubeshark-hub.kubeshark.svc.cluster.local",
                    destination_port: "80",
                  },
                ],
                name: "/app/worker",
              },
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
                connections: [
                  {
                    bytes_received: "1019622",
                    bytes_sent: "772995",
                    destination_name: "172.20.0.1",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "64218",
                    bytes_sent: "12095220",
                    destination_name: "172.20.143.71",
                    destination_port: "80",
                  },
                  {
                    bytes_received: "703692",
                    bytes_sent: "24700008",
                    destination_name: "34.120.86.103",
                    destination_port: "443",
                  },
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                  },
                  {
                    destination_name: "logs-prod3.grafana.net",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "17638566",
                    bytes_sent: "835311618",
                    destination_name: "loki-gateway.logging.svc.cluster.local",
                    destination_port: "80",
                  },
                ],
                name: "/usr/bin/promtail",
              },
            ],
          },
          {
            kind: "StatefulSet",
            name: "loki-memcached-chunks",
            processes: [
              {
                connections: [
                  {
                    bytes_received: "136649895",
                    bytes_sent: "2647191",
                    destination_name: "127.0.0.1",
                    destination_port: "11211",
                  },
                ],
                name: "/bin/memcached_exporter",
              },
              { in_init_tree: false, name: "/usr/local/bin/memcached" },
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
            processes: [{ in_init_tree: false, name: "/bin/node_exporter" }],
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
                    bytes_received: "512282958",
                    bytes_sent: "10989756",
                    destination_name: "10.3.7.199",
                    destination_port: "2112",
                  },
                  {
                    bytes_received: "350289147",
                    bytes_sent: "9960348",
                    destination_name: "10.3.7.199",
                    destination_port: "10250",
                  },
                  {
                    bytes_received: "96966291",
                    bytes_sent: "9845268",
                    destination_name: "172.20.170.76",
                    destination_port: "80",
                  },
                  {
                    bytes_received: "80112",
                    bytes_sent: "424497",
                    destination_name: "172.20.98.164",
                    destination_port: "80",
                  },
                  {
                    bytes_received: "1760448",
                    bytes_sent: "26360433",
                    destination_name: "35.190.55.74",
                    destination_port: "443",
                  },
                  {
                    destination_name:
                      "ip-10-3-7-199.us-west-2.compute.internal",
                    destination_port: "2112",
                  },
                  {
                    destination_name:
                      "ip-10-3-7-199.us-west-2.compute.internal",
                    destination_port: "10250",
                  },
                  {
                    destination_name:
                      "otel-collector/Service:otel-targetallocator",
                    destination_port: "80",
                  },
                  {
                    destination_name:
                      "otlp-gateway-prod-us-central-0.grafana.net",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "1559166",
                    bytes_sent: "8209053",
                    destination_name: "tempo-gateway.tempo.svc.cluster.local",
                    destination_port: "80",
                  },
                ],
                name: "/otelcol-contrib",
              },
            ],
          },
        ],
      },
      {
        name: "otel-demo",
        workloads: [
          {
            kind: "Deployment",
            name: "otel-demo-accountingservice",
            processes: [
              {
                connections: [
                  {
                    bytes_received: "2150644",
                    bytes_sent: "16383516",
                    destination_name: "10.3.7.199",
                    destination_port: "4318",
                  },
                  {
                    destination_name: "172.20.149.213",
                    destination_port: "9092",
                  },
                  {
                    bytes_received: "37979854",
                    bytes_sent: "34423714",
                    destination_name: "otel-demo/Service:otel-demo-kafka",
                    destination_port: "9092",
                  },
                ],
                name: "/usr/share/dotnet/dotnet",
              },
            ],
          },
        ],
      },
      {
        name: "tempo",
        workloads: [
          {
            kind: "Deployment",
            name: "tempo-query-frontend",
            processes: [
              {
                connections: [
                  {
                    bytes_received: "89400",
                    bytes_sent: "134100",
                    destination_name: "127.0.0.1",
                    destination_port: "5778",
                  },
                  {
                    bytes_received: "3113937",
                    bytes_sent: "904875",
                    destination_name:
                      "al2023-repos-us-west-2-de612dc2.s3.dualstack.us-west-2.amazonaws.com",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "5887146",
                    bytes_sent: "1750758",
                    destination_name:
                      "df-tetragon-dev-ce-01-logs.s3.us-west-2.amazonaws.com",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "41718",
                    bytes_sent: "26088",
                    destination_name: "stats.grafana.org",
                    destination_port: "443",
                  },
                  {
                    bytes_received: "664350",
                    bytes_sent: "267759",
                    destination_name: "sts.us-west-2.amazonaws.com",
                    destination_port: "443",
                  },
                ],
                name: "/tempo",
              },
            ],
          },
        ],
      },
      {
        name: "tenant-jobs",
        workloads: [
          {
            kind: "StatefulSet",
            name: "elasticsearch-master",
            processes: [
              { in_init_tree: false, name: "/usr/bin/bash" },
              {
                arguments:
                  "--output\u0000/dev/null\u0000-k\u0000-XGET\u0000-s\u0000-w\u0000%{http_code}\u0000http://127.0.0.1:9200/",
                connections: [
                  {
                    bytes_received: "24187867392",
                    bytes_sent: "7968804376",
                    destination_name: "127.0.0.1",
                    destination_port: "9200",
                  },
                ],
                name: "/usr/bin/curl",
              },
              {
                in_init_tree: false,
                name: "/usr/share/elasticsearch/jdk/bin/java",
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
              { in_init_tree: false, name: "/bin/busybox" },
              {
                connections: [
                  {
                    bytes_received: "1219701",
                    bytes_sent: "479250",
                    destination_name: "172.20.0.1",
                    destination_port: "443",
                  },
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                  },
                ],
                name: "/usr/bin/tetragon",
              },
              {
                arguments:
                  "-hostMntNs\u00004026531841\u0000-scannerFifoPath\u0000/var/run/cilium/hubble/fs_scanner.sock\u0000-maxSizeFileDigest\u00001073741824\u0000-maxTimeoutFileDigest\u000030\u0000-logLevel\u0000info\u0000-logFormat\u0000text",
                in_init_tree: false,
                name: "/var/lib/tetragon/tetragon-fs-scanner",
              },
              {
                arguments:
                  "/procRoot/1/ns/mnt\u0000/var/lib/tetragon/tetragon-fs-scanner\u0000-hostMntNs\u00004026531841\u0000-scannerFifoPath\u0000/var/run/cilium/hubble/fs_scanner.sock\u0000-maxSizeFileDigest\u00001073741824\u0000-maxTimeoutFileDigest\u000030\u0000-logLevel\u0000info\u0000-logFormat\u0000text",
                in_init_tree: false,
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
                connections: [
                  {
                    bytes_received: "269548",
                    bytes_sent: "199550226",
                    destination_name: "172.20.1.197",
                    destination_port: "8080",
                  },
                  { destination_name: "52.37.86.19", destination_port: "443" },
                  {
                    bytes_received: "12911368",
                    bytes_sent: "5099269386",
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
  cluster_name: "tetragon-dev",
  event_type: "application_model",
  node_name: "ip-10-3-7-199.us-west-2.compute.internal",
  time: "2025-01-24T12:39:36.110031508Z",
};
