export const model = {
  clusterName: "tetragon-dev",
  nodeName: "node-aws-1",
  application_model: {
    namespaces: [
      {
        name: "alloy",
        workloads: [
          {
            name: "alloy",
            kind: "Deployment",
            processes: [
              {
                name: "/configmap-reload",
                arguments:
                  "--volume-dir=/etc/alloy\u0000--webhook-url=http://localhost:12345/-/reload",
              },
              {
                name: "/usr/bin/alloy",
                arguments:
                  "run\u0000/etc/alloy/config.alloy\u0000--storage.path=/tmp/alloy\u0000--server.http.listen-addr=0.0.0.0:12345\u0000--server.http.ui-path-prefix=/\u0000--disable-reporting\u0000--stability.level=generally-available",
                connections: [
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "10899",
                    bytes_received: "303206",
                  },
                  {
                    destination_name: "ip-10-3-6-99.us-west-2.compute.internal",
                    destination_port: "6060",
                    bytes_sent: "191265",
                    bytes_received: "12400727",
                  },
                  {
                    destination_name:
                      "ip-10-3-8-128.us-west-2.compute.internal",
                    destination_port: "6060",
                    bytes_sent: "6047",
                    bytes_received: "353807",
                  },
                  {
                    destination_name: "ip-10-3-8-80.us-west-2.compute.internal",
                    destination_port: "6060",
                    bytes_sent: "2911",
                    bytes_received: "194895",
                  },
                  {
                    destination_name:
                      "monitoring/DaemonSet:prometheus-prometheus-node-exporter",
                    destination_port: "6060",
                    bytes_sent: "5436",
                    bytes_received: "352683",
                  },
                  {
                    destination_name: "profiles-prod-003.grafana.net",
                    destination_port: "443",
                    bytes_sent: "22962",
                    bytes_received: "5632",
                  },
                  {
                    destination_name:
                      "tetragon-tracing-demo/Pod:tls-weak-version",
                    destination_port: "6060",
                    bytes_sent: "422",
                    bytes_received: "8482",
                  },
                  {
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "6060",
                    bytes_sent: "12958",
                    bytes_received: "764236",
                  },
                ],
              },
            ],
          },
        ],
      },
      {
        name: "argocd",
        workloads: [
          {
            name: "argo-cd-argocd-applicationset-controller",
            kind: "Deployment",
            processes: [
              {
                name: "/usr/bin/tini",
                arguments:
                  "--\u0000/usr/local/bin/argocd-applicationset-controller\u0000--metrics-addr=:8080\u0000--probe-addr=:8081\u0000--webhook-addr=:7000",
              },
              {
                name: "/usr/local/bin/argocd",
                arguments:
                  "--metrics-addr=:8080\u0000--probe-addr=:8081\u0000--webhook-addr=:7000",
                connections: [
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "12828",
                    bytes_received: "289288",
                  },
                ],
              },
            ],
          },
          {
            name: "argo-cd-argocd-notifications-controller",
            kind: "Deployment",
            processes: [
              {
                name: "/usr/bin/tini",
                arguments:
                  "--\u0000/usr/local/bin/argocd-notifications\u0000--metrics-port=9001\u0000--loglevel=info\u0000--logformat=text\u0000--namespace=argocd\u0000--argocd-repo-server=argo-cd-argocd-repo-server:8081\u0000--secret-name=argocd-notifications-secret",
              },
              {
                name: "/usr/local/bin/argocd",
                arguments:
                  "--metrics-port=9001\u0000--loglevel=info\u0000--logformat=text\u0000--namespace=argocd\u0000--argocd-repo-server=argo-cd-argocd-repo-server:8081\u0000--secret-name=argocd-notifications-secret",
                connections: [
                  {
                    destination_name:
                      "argo-cd-argocd-repo-server.argocd.svc.cluster.local",
                    destination_port: "8081",
                    bytes_sent: "300",
                  },
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "7877",
                    bytes_received: "81114",
                  },
                ],
              },
            ],
          },
          {
            name: "argo-cd-argocd-repo-server",
            kind: "Deployment",
            processes: [
              {
                name: "/usr/bin/bash",
                arguments:
                  "-exc\u0000helm registry login quay.io --username $QUAY_USERNAME --password $QUAY_PASSWORD",
              },
              {
                name: "/usr/bin/cp",
                arguments:
                  "-n\u0000/usr/local/bin/argocd\u0000/var/run/argocd/argocd-cmp-server",
              },
              {
                name: "/usr/bin/dash",
                arguments:
                  "/usr/local/bin/gpg-wrapper.sh\u0000--no-permission-warning\u0000--list-secret-keys\u00000817C5A119C151A0",
              },
              {
                name: "/usr/bin/dash",
                arguments:
                  "/usr/local/bin/gpg-wrapper.sh\u0000--no-permission-warning\u0000--list-secret-keys\u0000AF7EADE71B451947",
              },
              {
                name: "/usr/bin/gpg",
                arguments: "--no-permission-warning\u0000--list-public-keys",
              },
              {
                name: "/usr/bin/gpg",
                arguments:
                  "--no-permission-warning\u0000--list-secret-keys\u00000817C5A119C151A0",
              },
              {
                name: "/usr/bin/gpg",
                arguments:
                  "--no-permission-warning\u0000--list-secret-keys\u0000AF7EADE71B451947",
              },
              {
                name: "/usr/bin/gpg",
                arguments:
                  "--no-permission-warning\u0000--logger-fd\u00001\u0000--batch\u0000--gen-key\u0000/tmp/gpg-key-recipe1102438465",
              },
              {
                name: "/usr/bin/gpg",
                arguments:
                  "--no-permission-warning\u0000--logger-fd\u00001\u0000--batch\u0000--gen-key\u0000/tmp/gpg-key-recipe3293188144",
              },
              {
                name: "/usr/bin/gpg",
                arguments:
                  "--no-permission-warning\u0000-a\u0000--export\u00000817C5A119C151A0",
              },
              {
                name: "/usr/bin/gpg",
                arguments:
                  "--no-permission-warning\u0000-a\u0000--export\u0000AF7EADE71B451947",
              },
              {
                name: "/usr/bin/gpg-agent",
                arguments:
                  "--homedir\u0000/app/config/gpg/keys\u0000--use-standard-socket\u0000--daemon",
              },
              {
                name: "/usr/bin/tini",
                arguments:
                  "--\u0000/usr/local/bin/argocd-repo-server\u0000--port=8081\u0000--metrics-port=8084",
              },
              {
                name: "/usr/local/bin/argocd",
                arguments: "--port=8081\u0000--metrics-port=8084",
                connections: [
                  {
                    destination_name: "::1",
                    destination_port: "8081",
                    bytes_sent: "3488",
                  },
                  {
                    destination_name:
                      "argo-cd-argocd-redis.argocd.svc.cluster.local",
                    destination_port: "6379",
                    bytes_sent: "928",
                    bytes_received: "39206",
                  },
                  {
                    destination_name: "github.com",
                    destination_port: "22",
                    bytes_sent: "23732",
                    bytes_received: "354991",
                  },
                ],
              },
              {
                name: "/usr/local/bin/helm",
                arguments:
                  "registry\u0000login\u0000quay.io\u0000--username\u0000isovalent-charts-dev+quay_chart_bot\u0000--password\u0000R0QC7BDRO14LQUK610HYEFYAI656922CLZ5CRMWDLWCY8KPP8GB52BNWUCICOBIW",
                connections: [
                  {
                    destination_name: "quay.io",
                    destination_port: "443",
                    bytes_sent: "4347",
                    bytes_received: "17257",
                  },
                ],
              },
            ],
          },
          {
            name: "argo-cd-argocd-server",
            kind: "Deployment",
            processes: [
              {
                name: "/usr/bin/tini",
                arguments:
                  "--\u0000/usr/local/bin/argocd-server\u0000--port=8080\u0000--metrics-port=8083\u0000--request-timeout=300s\u0000--repo-server-timeout-seconds=300",
              },
              {
                name: "/usr/local/bin/argocd",
                arguments:
                  "--port=8080\u0000--metrics-port=8083\u0000--request-timeout=300s\u0000--repo-server-timeout-seconds=300",
                connections: [
                  {
                    destination_name: "::1",
                    destination_port: "8080",
                    bytes_sent: "996",
                  },
                  {
                    destination_name:
                      "argo-cd-argocd-redis.argocd.svc.cluster.local",
                    destination_port: "6379",
                    bytes_sent: "2303",
                    bytes_received: "1580",
                  },
                  {
                    destination_name:
                      "argo-cd-argocd-repo-server.argocd.svc.cluster.local",
                    destination_port: "8081",
                    bytes_sent: "180",
                  },
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "17384",
                    bytes_received: "214902",
                  },
                ],
              },
            ],
          },
        ],
      },
      {
        name: "cert-manager",
        workloads: [
          {
            name: "cert-manager",
            kind: "Deployment",
            processes: [
              {
                name: "/app/cmd/controller/controller",
                arguments:
                  "--v=2\u0000--cluster-resource-namespace=cert-manager\u0000--leader-election-namespace=kube-system\u0000--acme-http01-solver-image=quay.io/jetstack/cert-manager-acmesolver:v1.12.2\u0000--max-concurrent-challenges=60\u0000--dns01-recursive-nameservers-only=true",
                connections: [
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "31800",
                    bytes_received: "849180",
                  },
                ],
              },
            ],
          },
          {
            name: "cert-manager-webhook",
            kind: "Deployment",
            processes: [
              {
                name: "/app/cmd/webhook/webhook",
                arguments:
                  "--v=2\u0000--secure-port=10250\u0000--dynamic-serving-ca-secret-n",
                connections: [
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "8091",
                    bytes_received: "155993",
                  },
                ],
              },
            ],
          },
        ],
      },
      {
        name: "clickhouse-operator",
        workloads: [
          {
            name: "clickhouse-operator-altinity-clickhouse-operator",
            kind: "Deployment",
            processes: [
              {
                name: "/clickhouse-operator",
                arguments: "-logtostderr=true\u0000-v=1",
                connections: [
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "77834",
                    bytes_received: "682918",
                  },
                ],
              },
              {
                name: "/metrics-exporter",
                arguments: "-logtostderr=true\u0000-v=1",
                connections: [
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "3190",
                    bytes_received: "5493",
                  },
                ],
              },
            ],
          },
        ],
      },
      {
        name: "dex",
        workloads: [
          {
            name: "dex",
            kind: "Deployment",
            processes: [
              {
                name: "/usr/local/bin/dex",
                arguments:
                  "serve\u0000--web-http-addr\u00000.0.0.0:5556\u0000--telemetry-addr\u00000.0.0.0:5558\u0000/tmp/dex.config.yaml-1512490321",
              },
              {
                name: "/usr/local/bin/docker-entrypoint",
                arguments:
                  "dex\u0000serve\u0000--web-http-addr\u00000.0.0.0:5556\u0000--telemetry-addr\u00000.0.0.0:5558\u0000/etc/dex/config.yaml",
              },
              {
                name: "/usr/local/bin/gomplate",
                arguments:
                  "-f\u0000/etc/dex/config.yaml\u0000-o\u0000/tmp/dex.config.yaml-1512490321",
              },
            ],
          },
        ],
      },
      {
        name: "hubble-enterprise",
        workloads: [
          {
            name: "hubble-enterprise",
            kind: "DaemonSet",
            processes: [
              { name: "/usr/bin/hostname" },
              {
                name: "/usr/local/bin/ruby",
                connections: [
                  {
                    destination_name: "172.20.98.128",
                    destination_port: "4260",
                    bytes_sent: "156",
                    bytes_received: "251",
                  },
                  {
                    destination_name: "52.92.200.26",
                    destination_port: "443",
                  },
                  {
                    destination_name: "52.94.181.132",
                    destination_port: "443",
                  },
                  {
                    destination_name: "52.94.181.70",
                    destination_port: "443",
                    bytes_sent: "104",
                    bytes_received: "104",
                  },
                  {
                    destination_name: "52.94.185.55",
                    destination_port: "443",
                  },
                  {
                    destination_name:
                      "al2023-repos-us-west-2-de612dc2.s3.dualstack.us-west-2.amazonaws.com",
                    destination_port: "443",
                  },
                  {
                    destination_name:
                      "df-tetragon-dev-ce-01-grafana-tempo.s3.dualstack.us-west-2.amazonaws.com",
                    destination_port: "443",
                  },
                  {
                    destination_name:
                      "df-tetragon-dev-ce-01-logs.s3.us-west-2.amazonaws.com",
                    destination_port: "443",
                  },
                  {
                    destination_name:
                      "hubble-timescape-ingester.hubble-timescape.svc.cluster.local",
                    destination_port: "4260",
                  },
                  {
                    destination_name: "sts.us-west-2.amazonaws.com",
                    destination_port: "443",
                  },
                ],
              },
              {
                name: "/usr/local/bin/ruby",
                arguments: "-Eascii-8bit:ascii-8bit\u0000-h",
              },
              {
                name: "/usr/local/bin/ruby",
                arguments:
                  "-Eascii-8bit:ascii-8bit\u0000/usr/local/bundle/bin/fluentd\u0000--config\u0000/fluentd/etc/fluent.conf\u0000--plugin\u0000/fluentd/plugins\u0000--under-supervisor",
                connections: [
                  {
                    destination_name: "172.20.98.128",
                    destination_port: "4260",
                    bytes_sent: "156",
                    bytes_received: "251",
                  },
                  {
                    destination_name: "52.119.163.221",
                    destination_port: "443",
                    bytes_sent: "309195",
                    bytes_received: "11686",
                  },
                  {
                    destination_name: "52.94.185.153",
                    destination_port: "443",
                  },
                  {
                    destination_name: "52.94.185.55",
                    destination_port: "443",
                  },
                  {
                    destination_name: "54.240.252.193",
                    destination_port: "443",
                    bytes_sent: "104",
                    bytes_received: "184",
                  },
                  {
                    destination_name:
                      "al2023-repos-us-west-2-de612dc2.s3.dualstack.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "213781",
                    bytes_received: "64087",
                  },
                  {
                    destination_name:
                      "df-tetragon-dev-ce-01-grafana-tempo.s3.dualstack.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "168755",
                    bytes_received: "8109",
                  },
                  {
                    destination_name:
                      "df-tetragon-dev-ce-01-logs.s3.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "424070",
                    bytes_received: "11722",
                  },
                  {
                    destination_name:
                      "hubble-timescape-ingester.hubble-timescape.svc.cluster.local",
                    destination_port: "4260",
                    bytes_sent: "102852381",
                    bytes_received: "490434",
                  },
                  {
                    destination_name:
                      "prod-registry-k8s-io-us-west-2.s3.dualstack.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "1448700",
                    bytes_received: "50329",
                  },
                  {
                    destination_name:
                      "prod-us-west-2-starport-layer-bucket.s3.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "192190",
                    bytes_received: "8213",
                  },
                  {
                    destination_name: "sts.us-west-2.amazonaws.com",
                    destination_port: "443",
                  },
                ],
              },
            ],
          },
        ],
      },
      {
        name: "hubble-timescape",
        workloads: [
          {
            name: "hubble-timescape-lite",
            kind: "StatefulSet",
            processes: [
              {
                name: "/usr/bin/grpc_health_probe",
                arguments: "-addr=localhost:4244",
                connections: [
                  {
                    destination_name: "127.0.0.1",
                    destination_port: "4244",
                    bytes_sent: "19750",
                    bytes_received: "14017",
                  },
                  {
                    destination_name: "::1",
                    destination_port: "4244",
                    bytes_sent: "9490699",
                  },
                ],
              },
              {
                name: "/usr/bin/grpc_health_probe",
                arguments:
                  "-addr=localhost:4244\u0000-connect-timeout=5m\u0000-rpc-timeout=1m",
                connections: [
                  {
                    destination_name: "127.0.0.1",
                    destination_port: "4244",
                    bytes_sent: "170752",
                    bytes_received: "40987",
                  },
                  {
                    destination_name: "::1",
                    destination_port: "4244",
                    bytes_sent: "245592",
                  },
                ],
              },
              {
                name: "/usr/bin/hubble-timescape",
                arguments: "run",
                connections: [
                  {
                    destination_name: "127.0.0.1",
                    destination_port: "9000",
                    bytes_sent: "70277918",
                    bytes_received: "3554991",
                  },
                  {
                    destination_name: "::1",
                    destination_port: "9000",
                    bytes_sent: "5809130272",
                    bytes_received: "40712800979",
                  },
                ],
              },
            ],
          },
        ],
      },
      {
        name: "kube-system",
        workloads: [
          {
            name: "cilium",
            kind: "DaemonSet",
            processes: [
              {
                name: "/usr/bin/cilium-agent",
                connections: [
                  {
                    destination_name: "10.3.5.124",
                    destination_port: "4240",
                    bytes_sent: "52",
                    bytes_received: "52",
                  },
                  {
                    destination_name: "10.3.5.125",
                    destination_port: "4240",
                    bytes_sent: "522",
                    bytes_received: "366",
                  },
                  {
                    destination_name: "10.3.5.185",
                    destination_port: "4240",
                    bytes_sent: "52",
                    bytes_received: "52",
                  },
                  {
                    destination_name: "10.3.5.197",
                    destination_port: "4240",
                    bytes_sent: "52",
                    bytes_received: "52",
                  },
                  {
                    destination_name: "10.3.5.215",
                    destination_port: "4240",
                    bytes_sent: "52",
                    bytes_received: "52",
                  },
                  {
                    destination_name: "10.3.5.231",
                    destination_port: "4240",
                    bytes_sent: "52",
                    bytes_received: "52",
                  },
                  {
                    destination_name: "10.3.5.39",
                    destination_port: "4240",
                  },
                  {
                    destination_name: "10.3.5.72",
                    destination_port: "4240",
                  },
                  {
                    destination_name: "10.3.5.74",
                    destination_port: "4240",
                    bytes_sent: "52",
                    bytes_received: "52",
                  },
                  {
                    destination_name: "10.3.6.14",
                    destination_port: "4240",
                    bytes_sent: "52",
                    bytes_received: "52",
                  },
                  {
                    destination_name: "10.3.6.166",
                    destination_port: "4240",
                    bytes_sent: "52",
                    bytes_received: "52",
                  },
                  {
                    destination_name: "10.3.6.179",
                    destination_port: "4240",
                    bytes_sent: "52",
                    bytes_received: "52",
                  },
                  {
                    destination_name: "10.3.6.198",
                    destination_port: "4240",
                    bytes_sent: "52",
                    bytes_received: "52",
                  },
                  {
                    destination_name: "10.3.6.204",
                    destination_port: "4240",
                    bytes_sent: "317",
                    bytes_received: "239",
                  },
                  {
                    destination_name: "10.3.6.35",
                    destination_port: "4240",
                    bytes_sent: "52",
                    bytes_received: "52",
                  },
                  {
                    destination_name: "10.3.6.50",
                    destination_port: "4240",
                    bytes_sent: "316",
                    bytes_received: "239",
                  },
                  {
                    destination_name: "10.3.6.9",
                    destination_port: "4240",
                    bytes_sent: "52",
                    bytes_received: "52",
                  },
                  {
                    destination_name: "10.3.7.155",
                    destination_port: "4240",
                    bytes_sent: "52",
                    bytes_received: "52",
                  },
                  {
                    destination_name: "10.3.7.172",
                    destination_port: "4240",
                    bytes_sent: "52",
                    bytes_received: "52",
                  },
                  {
                    destination_name: "10.3.7.177",
                    destination_port: "443",
                  },
                  {
                    destination_name: "10.3.8.154",
                    destination_port: "4240",
                    bytes_sent: "52",
                    bytes_received: "52",
                  },
                  {
                    destination_name: "10.3.8.156",
                    destination_port: "4240",
                    bytes_sent: "317",
                    bytes_received: "239",
                  },
                  {
                    destination_name: "10.3.8.221",
                    destination_port: "4240",
                    bytes_sent: "52",
                    bytes_received: "52",
                  },
                  {
                    destination_name: "10.3.8.222",
                    destination_port: "4240",
                  },
                  {
                    destination_name: "10.3.8.68",
                    destination_port: "4240",
                  },
                  {
                    destination_name: "169.254.169.254",
                    destination_port: "80",
                    bytes_sent: "4106",
                    bytes_received: "3688",
                  },
                  {
                    destination_name:
                      "3BE81FD965B44E29EE37641B4D0F95CD.gr7.us-west-2.eks.amazonaws.com",
                    destination_port: "443",
                  },
                  {
                    destination_name:
                      "3be81fd965b44e29ee37641b4d0f95cd.gr7.us-west-2.eks.amazonaws.com",
                    destination_port: "443",
                  },
                  {
                    destination_name:
                      "ip-10-3-8-154.us-west-2.compute.internal",
                    destination_port: "4240",
                    bytes_sent: "3220",
                    bytes_received: "2296",
                  },
                  {
                    destination_name:
                      "monitoring/DaemonSet:prometheus-prometheus-node-exporter",
                    destination_port: "4240",
                    bytes_sent: "316",
                    bytes_received: "239",
                  },
                  {
                    destination_name:
                      "tetragon-tracing-demo/Pod:tls-weak-version",
                    destination_port: "4240",
                    bytes_sent: "522",
                    bytes_received: "366",
                  },
                  {
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "4240",
                  },
                ],
              },
              {
                name: "/usr/bin/cilium-agent",
                arguments: "--config-dir=/tmp/cilium/config-map",
                connections: [
                  {
                    destination_name: "10.3.5.124",
                    destination_port: "4240",
                    bytes_sent: "5445",
                    bytes_received: "4327",
                  },
                  {
                    destination_name: "10.3.5.125",
                    destination_port: "4240",
                    bytes_sent: "1147",
                    bytes_received: "493",
                  },
                  {
                    destination_name: "10.3.5.148",
                    destination_port: "4240",
                    bytes_sent: "4018",
                    bytes_received: "2650",
                  },
                  {
                    destination_name: "10.3.5.160",
                    destination_port: "4240",
                    bytes_sent: "5445",
                    bytes_received: "4327",
                  },
                  {
                    destination_name: "10.3.5.197",
                    destination_port: "4240",
                    bytes_sent: "6397",
                    bytes_received: "5175",
                  },
                  {
                    destination_name: "10.3.5.250",
                    destination_port: "4240",
                    bytes_sent: "300",
                  },
                  {
                    destination_name: "10.3.5.39",
                    destination_port: "4240",
                    bytes_sent: "496",
                    bytes_received: "239",
                  },
                  {
                    destination_name: "10.3.5.72",
                    destination_port: "4240",
                    bytes_sent: "2228",
                    bytes_received: "1714",
                  },
                  {
                    destination_name: "10.3.6.14",
                    destination_port: "4240",
                    bytes_sent: "8692",
                    bytes_received: "6193",
                  },
                  {
                    destination_name: "10.3.6.204",
                    destination_port: "4240",
                    bytes_sent: "942",
                    bytes_received: "366",
                  },
                  {
                    destination_name: "10.3.6.228",
                    destination_port: "4240",
                    bytes_sent: "300",
                  },
                  {
                    destination_name: "10.3.6.35",
                    destination_port: "4240",
                    bytes_sent: "6064",
                    bytes_received: "4907",
                  },
                  {
                    destination_name: "10.3.6.40",
                    destination_port: "4240",
                    bytes_sent: "300",
                  },
                  {
                    destination_name: "10.3.6.50",
                    destination_port: "4240",
                    bytes_sent: "820",
                    bytes_received: "366",
                  },
                  {
                    destination_name: "10.3.6.8",
                    destination_port: "443",
                    bytes_sent: "232838",
                    bytes_received: "4563706",
                  },
                  {
                    destination_name: "10.3.6.9",
                    destination_port: "4240",
                    bytes_sent: "6431",
                    bytes_received: "5183",
                  },
                  {
                    destination_name: "10.3.7.172",
                    destination_port: "4240",
                    bytes_sent: "522",
                    bytes_received: "366",
                  },
                  {
                    destination_name: "10.3.7.177",
                    destination_port: "443",
                    bytes_sent: "71181",
                    bytes_received: "712277",
                  },
                  {
                    destination_name: "10.3.7.203",
                    destination_port: "4240",
                    bytes_sent: "4737",
                    bytes_received: "3395",
                  },
                  {
                    destination_name: "10.3.8.127",
                    destination_port: "4240",
                    bytes_sent: "1382",
                    bytes_received: "678",
                  },
                  {
                    destination_name: "10.3.8.156",
                    destination_port: "4240",
                    bytes_sent: "1035",
                    bytes_received: "493",
                  },
                  {
                    destination_name: "10.3.8.162",
                    destination_port: "4240",
                    bytes_sent: "317",
                    bytes_received: "239",
                  },
                  {
                    destination_name: "10.3.8.222",
                    destination_port: "4240",
                    bytes_sent: "4414",
                    bytes_received: "3530",
                  },
                  {
                    destination_name: "10.3.8.50",
                    destination_port: "4240",
                    bytes_sent: "1032",
                    bytes_received: "493",
                  },
                  {
                    destination_name: "10.3.8.68",
                    destination_port: "4240",
                    bytes_sent: "6228",
                    bytes_received: "5019",
                  },
                  {
                    destination_name: "169.254.169.254",
                    destination_port: "80",
                    bytes_sent: "8264",
                    bytes_received: "7372",
                  },
                  {
                    destination_name:
                      "3BE81FD965B44E29EE37641B4D0F95CD.gr7.us-west-2.eks.amazonaws.com",
                    destination_port: "443",
                  },
                  {
                    destination_name:
                      "ip-10-3-5-195.us-west-2.compute.internal",
                    destination_port: "4240",
                    bytes_sent: "317",
                    bytes_received: "239",
                  },
                  {
                    destination_name:
                      "ip-10-3-5-215.us-west-2.compute.internal",
                    destination_port: "4240",
                    bytes_sent: "1504",
                    bytes_received: "1192",
                  },
                  {
                    destination_name:
                      "ip-10-3-5-231.us-west-2.compute.internal",
                    destination_port: "4240",
                    bytes_sent: "34191",
                    bytes_received: "27353",
                  },
                  {
                    destination_name:
                      "ip-10-3-6-166.us-west-2.compute.internal",
                    destination_port: "4240",
                    bytes_sent: "33699",
                    bytes_received: "27017",
                  },
                  {
                    destination_name:
                      "ip-10-3-6-198.us-west-2.compute.internal",
                    destination_port: "4240",
                    bytes_sent: "19592",
                    bytes_received: "15640",
                  },
                  {
                    destination_name: "ip-10-3-6-44.us-west-2.compute.internal",
                    destination_port: "4240",
                    bytes_sent: "784",
                    bytes_received: "655",
                  },
                  {
                    destination_name: "ip-10-3-6-99.us-west-2.compute.internal",
                    destination_port: "4240",
                    bytes_sent: "21011",
                    bytes_received: "14416",
                  },
                  {
                    destination_name:
                      "ip-10-3-8-128.us-west-2.compute.internal",
                    destination_port: "4240",
                    bytes_sent: "990",
                    bytes_received: "782",
                  },
                  {
                    destination_name: "ip-10-3-8-80.us-west-2.compute.internal",
                    destination_port: "4240",
                    bytes_sent: "832",
                    bytes_received: "678",
                  },
                  {
                    destination_name: "kube-system/DaemonSet:ebs-csi-node",
                    destination_port: "4240",
                    bytes_sent: "300",
                  },
                  {
                    destination_name:
                      "monitoring/DaemonSet:prometheus-prometheus-node-exporter",
                    destination_port: "4240",
                    bytes_sent: "522",
                    bytes_received: "366",
                  },
                  {
                    destination_name:
                      "tetragon-tracing-demo/Pod:tls-weak-version",
                    destination_port: "4240",
                    bytes_sent: "522",
                    bytes_received: "366",
                  },
                  {
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "4240",
                    bytes_sent: "44492",
                    bytes_received: "30413",
                  },
                ],
              },
              {
                name: "/usr/bin/cilium-envoy",
                connections: [
                  {
                    destination_name:
                      "monitoring/Deployment:prometheus-grafana",
                    destination_port: "3000",
                    bytes_sent: "2144",
                    bytes_received: "480",
                  },
                  {
                    destination_name:
                      "otel-demo/Deployment:otel-demo-frontendproxy",
                    destination_port: "8080",
                    bytes_sent: "7633",
                    bytes_received: "754480",
                  },
                  {
                    destination_name: "tetragon/Deployment:tetragon-grafana",
                    destination_port: "3000",
                    bytes_sent: "8685",
                    bytes_received: "3987029",
                  },
                ],
              },
              { name: "/usr/bin/cilium-envoy", arguments: "--version" },
              {
                name: "/usr/bin/cilium-envoy",
                arguments:
                  "-l\u0000info\u0000-c\u0000/var/run/cilium/envoy/bootstrap.pb\u0000--base-id\u00000\u0000--log-format\u0000%t|%l|%n|%v",
                connections: [
                  {
                    destination_name:
                      "monitoring/Deployment:prometheus-grafana",
                    destination_port: "3000",
                    bytes_sent: "2143",
                    bytes_received: "480",
                  },
                  {
                    destination_name:
                      "otel-demo/Deployment:otel-demo-frontendproxy",
                    destination_port: "8080",
                    bytes_sent: "603",
                    bytes_received: "77223",
                  },
                  {
                    destination_name: "tetragon/Deployment:tetragon-grafana",
                    destination_port: "3000",
                    bytes_sent: "833",
                    bytes_received: "45430",
                  },
                ],
              },
              {
                name: "/usr/bin/cilium-envoy-starter",
                arguments:
                  "-l\u0000info\u0000-c\u0000/var/run/cilium/envoy/bootstrap.pb\u0000--base-id\u00000\u0000--log-format\u0000%t|%l|%n|%v",
              },
              { name: "/usr/bin/cilium-health-responder" },
              {
                name: "/usr/bin/cilium-health-responder",
                arguments:
                  "--listen\u00004240\u0000--pidfile\u0000/var/run/cilium/state/health-endpoint.pid",
              },
              {
                name: "/usr/bin/ip",
                arguments:
                  "route\u0000add\u00000.0.0.0/0\u0000via\u000010.3.5.108\u0000mtu\u00009001\u0000dev\u0000cilium",
              },
              {
                name: "/usr/bin/ip",
                arguments:
                  "route\u0000add\u00000.0.0.0/0\u0000via\u000010.3.5.128\u0000mtu\u00009001\u0000dev\u0000cilium",
              },
              {
                name: "/usr/bin/ip",
                arguments:
                  "route\u0000add\u00000.0.0.0/0\u0000via\u000010.3.5.157\u0000mtu\u00009001\u0000dev\u0000cilium",
              },
              {
                name: "/usr/bin/ip",
                arguments:
                  "route\u0000add\u00000.0.0.0/0\u0000via\u000010.3.6.148\u0000mtu\u00009001\u0000dev\u0000cilium",
              },
              {
                name: "/usr/bin/ip",
                arguments:
                  "route\u0000add\u00000.0.0.0/0\u0000via\u000010.3.6.197\u0000mtu\u00009001\u0000dev\u0000cilium",
              },
              {
                name: "/usr/bin/ip",
                arguments:
                  "route\u0000add\u00000.0.0.0/0\u0000via\u000010.3.6.205\u0000mtu\u00009001\u0000dev\u0000cilium",
              },
              {
                name: "/usr/bin/ip",
                arguments:
                  "route\u0000add\u00000.0.0.0/0\u0000via\u000010.3.6.65\u0000mtu\u00009001\u0000dev\u0000cilium",
              },
              {
                name: "/usr/bin/ip",
                arguments:
                  "route\u0000add\u00000.0.0.0/0\u0000via\u000010.3.8.134\u0000mtu\u00009001\u0000dev\u0000cilium",
              },
              {
                name: "/usr/bin/ip",
                arguments:
                  "route\u0000add\u00000.0.0.0/0\u0000via\u000010.3.8.157\u0000mtu\u00009001\u0000dev\u0000cilium",
              },
              {
                name: "/usr/bin/ip",
                arguments:
                  "route\u0000add\u00000.0.0.0/0\u0000via\u000010.3.8.74\u0000mtu\u00009001\u0000dev\u0000cilium",
              },
              {
                name: "/usr/bin/ip",
                arguments:
                  "route\u0000add\u000010.3.5.108/32\u0000dev\u0000cilium",
              },
              {
                name: "/usr/bin/ip",
                arguments:
                  "route\u0000add\u000010.3.5.128/32\u0000dev\u0000cilium",
              },
              {
                name: "/usr/bin/ip",
                arguments:
                  "route\u0000add\u000010.3.5.157/32\u0000dev\u0000cilium",
              },
              {
                name: "/usr/bin/ip",
                arguments:
                  "route\u0000add\u000010.3.6.148/32\u0000dev\u0000cilium",
              },
              {
                name: "/usr/bin/ip",
                arguments:
                  "route\u0000add\u000010.3.6.197/32\u0000dev\u0000cilium",
              },
              {
                name: "/usr/bin/ip",
                arguments:
                  "route\u0000add\u000010.3.6.205/32\u0000dev\u0000cilium",
              },
              {
                name: "/usr/bin/ip",
                arguments:
                  "route\u0000add\u000010.3.6.65/32\u0000dev\u0000cilium",
              },
              {
                name: "/usr/bin/ip",
                arguments:
                  "route\u0000add\u000010.3.8.134/32\u0000dev\u0000cilium",
              },
              {
                name: "/usr/bin/ip",
                arguments:
                  "route\u0000add\u000010.3.8.157/32\u0000dev\u0000cilium",
              },
              {
                name: "/usr/bin/ip",
                arguments:
                  "route\u0000add\u000010.3.8.74/32\u0000dev\u0000cilium",
              },
              { name: "/usr/bin/kmod", arguments: "ip6table_filter" },
              { name: "/usr/bin/kmod", arguments: "ip6table_mangle" },
              { name: "/usr/bin/kmod", arguments: "ip6table_raw" },
              { name: "/usr/bin/kmod", arguments: "iptable_filter" },
              { name: "/usr/bin/kmod", arguments: "iptable_mangle" },
              { name: "/usr/bin/kmod", arguments: "iptable_nat" },
              { name: "/usr/bin/kmod", arguments: "iptable_raw" },
              { name: "/usr/bin/kmod", arguments: "xt_socket" },
              {
                name: "/usr/local/bin/bpftool",
                arguments: "-j\u0000feature\u0000probe",
              },
              {
                name: "/usr/local/bin/bpftool",
                arguments: "-j\u0000map\u0000show",
              },
              {
                name: "/usr/local/bin/bpftool",
                arguments: "-j\u0000prog\u0000show",
              },
              { name: "/usr/local/bin/clang", arguments: "--version" },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wextra\u0000-Werr",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/011c500c0313e2365f676f546bffb4a558ef2c66fb91e8f1b7ea42ef2b6ba0b4\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/0656c4fb43229365330b209450b651e8a67dfd1c29734858ef98100099a31268\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/0e360f2c80217cd7680c1d472e05b8286a7648cb2122e890eecea4d2c99de5e2\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/0e512f667f85e780da5eaaa37e5b9a578b2eb976824f593aa765710469b41104\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/0f042e56b1986054c47c310592d9ee2156c8b3555fb9d1347fff9f4ee4115efc\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/127787e58a2bdbef6bedf2aff50b96666eb5110ec5c43b0cd76443afe839c4aa\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/18de8078b19e23c2ce462e8a4e527a222551b647b57980a63e632566cd2da7f3\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/1dd301dbdbb0b57ac4b1d656244c17837a6abaf147dc3d5c64dee5d106ce8d78\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/1de50b993ee709b8d2d67f31dfb05f3740c85c2092ea5c206625c7773fe5b86c\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/229dea6d80c52b236d20a258d4e84a96fe6e996bbcdc2d149ea4b99b7a247af8\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/2cd5aa9b55094e6a03f811e779892ccac694d97d9866a8d22a94dfa8625dc08d\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/335e6b83d7d405c4a5036bd6c4ca93ae9fcd4cba5c35cf1d57cc01198d52bc5a\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/3aedfd3aa599161fe90b92f6d4dbbb3291aecbb9d69024d2e4a9d89f6abf0072\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/3be84c9712f0dcfd142dc2ffe356a00bc588eda53a0d176d0f685c007ac640c0\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/3edc27b6650f02dae23552cdfadb77288d04d9a7889dc1e00a04927425994fc9\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/4e0c7d3e4caab3ed7f846cc97accbdac734f94f5475549429d9c6088b1a3ea4a\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/4f0e82242966e3e09b8fc3718bc31623df5f4b39f801ed01524d45a9c8578866\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/52284e270f139d85f2019f7b62671b06aadad3a9bd034a01d3e8e3a056760e5b\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/545bf5596bda91c31b8e72f73ea6a3ade2a917511113666ea303f9ad61e039a9\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/58f85527e7c6285184e2ea62db3cee35414bdc893ff64561218c59d3170bfe23\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/59f412cd91d8c9be0e4f07317c154c5d842fa08a4782e5270874a79173d13ab7\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/5a8d8ccd79e3bb937d435ab6163d76e6b613dbf84c953fbc6630b53a98e7fe94\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/5adc42eb01363b0cbab2abf5a814f4e64affbed1265fd84bc0c3031f58716429\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/5c38677dd178a8dbc4ea20045f25bd3578f9c5f6052fa8c51671558bb32a7562\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/5d733c99e158860f8c5e28e0571ad99f42692544de2910fe35cf6db5edf17e96\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/6288e90dcbb7496b9a8acc5cc4b2961fd075a10b73661ae8189bb5a8a64f04be\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/653ecbe8c5baa4803d47c905616980f5ec1e49e5875ee18fcb4e321ada109950\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/679c4ea25fbe07196549455ca16d5d8b253845b31ccb0ce6c8fc824cc26d50b2\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/7bc46ffa331fa4ad6d50b8fb8e8e58e383403192648c0b9018e3de04a857ff80\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/802c188923e941214e26e1d215b6b8228d188725877b021480574799ce0c4770\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/8e1ee126f4e736d2ba8902d3cf1ed49b39670814795a15d58a6401ba27a022dc\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/99dbc514dfdca0eab188cc70382178635649ad67f108ba83108c64178974511a\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/9c4a0ea30324180a23246b5cfed700842ce4cb09c9c831a83a9caa20feee051d\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/a59fd1b3e11311a3ee5a0937028526f9b77566ccab03550a3c4bde8f4d40ede2\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/a7f26e0ea454dd246cecb0696006bcd36e966b0b7b8b53b1e07963f1ddd25b79\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/ad6c97b5c065b6e81741b78a84c3dc79916146cf2ea39cdb61f9323fecc14233\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/b773c8639e4aa09da0cb9f2b14b381d06342558c0182ed5db65bd1c3a84bb3e4\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/c09ff35dcd7500bf9a81b9761d8d1dd38cdabd1db43787342c9623332a0a9635\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/c535fb457079cff9e2a19d924a35a43e39327f01272420487d8369c0f28f1a34\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/c560ec7f1c3e6d0d0fad2bd3d08ccc6d356e37d9610ed99234874db0c91d230b\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/c8f798a7bc0ccb8ad76327aff0ac642924c0f11f3de43a5c8c5e22950ccdae47\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/d1f96750e1fd04c6b9d4b0b8fc482f4e3f86da423042a8ee2d8e63fee253f65d\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/d27f3f9c2ff418d5415b00adbcd9ed80f8246f757d65233782fc73ebfb70995f\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/d55b98053e2e75d59ca4a8de727ac56d6b2cc708482407380ed07ca4f5ff22d7\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/d5ec3a8b43d6101df01d528bbc6d2c6026e7d926ff6129676c5a4844d3dc0825\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/dd87d0a521f8d8c5e7af9b9880b810541c6cc8800614bb48b9b49d6553fc6e21\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/e1d18312bdce24effebf0ccd24a5fb63e41acc3aec5a5f9a17bbf0b059b3792a\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/e397b02af73b82fc9c8cb418bf2a2bee1d3583b79b2c4988981c43419cdbf431\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/e537b0b189b84279f78fbc50629b3ccb321b2dc0da1732ac96a4ff6309e02a51\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/ea92177015fed994a45af81ca74791a75ef9c74be2b046bd216c085c77868a05\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/eb69db5119dae66a11dc14fa2d87c9eb1ca6e2260005d9c6a509a9c3bea3593e\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/eff8e510919784250ad98358239c543a29b022efc2a1c090a0b2e3eab192b550\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/f1e6b6be096e0d64c1ca495928e7922888941e4f76bec7353f67957c97a9e979\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/fd8d0c3177aae8119ec2aa581f6a9ce9a15f8fa46a897d025de7bf2e3869e124\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/fdda050fa924347b21a440b1d7086919f240dc57b2a6d8f79ab0f508e2894394\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wex",
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals\u0000-I/var/run/cilium/state/templates/fea7337bdfbaa72e5a78bf80573e46f727e49168a6e5628e29af2b3569dc4e82\u0000-I/var/lib/cilium/bpf\u0000-I/var/lib/cilium/bpf/include\u0000-g\u0000-O2\u0000--target=bpf\u0000-std=gnu89\u0000-nostdinc\u0000-Wall\u0000-Wext",
              },
              {
                name: "/usr/sbin/ipset",
                arguments:
                  "create\u0000cilium_node_set_v4\u0000iphash\u0000family\u0000inet\u0000-exist",
              },
              {
                name: "/usr/sbin/ipset",
                arguments:
                  "create\u0000cilium_node_set_v6\u0000iphash\u0000family\u0000inet6\u0000-exist",
              },
              {
                name: "/usr/sbin/ipset",
                arguments: "list\u0000cilium_node_set_v4",
              },
              {
                name: "/usr/sbin/ipset",
                arguments: "list\u0000cilium_node_set_v6",
              },
              { name: "/usr/sbin/ipset", arguments: "restore" },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "--version",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t\u0000filter\u0000-S",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t\u0000filter\u0000-S\u0000CILIUM_FORWARD",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t\u0000filter\u0000-S\u0000CILIUM_INPUT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t\u0000filter\u0000-S\u0000CILIUM_OUTPUT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t\u0000filter\u0000-S\u0000OLD_CILIUM_FORWARD",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t\u0000filter\u0000-S\u0000OLD_CILIUM_INPUT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t\u0000filter\u0000-S\u0000OLD_CILIUM_OUTPUT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t\u0000mangle\u0000-S",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t\u0000mangle\u0000-S\u0000CILIUM_PRE_mangle",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t\u0000mangle\u0000-S\u0000OLD_CILIUM_PRE_mangle",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t\u0000nat\u0000-S",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t\u0000nat\u0000-S\u0000CILIUM_POST_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t\u0000nat\u0000-S\u0000OLD_CILIUM_POST_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t\u0000raw\u0000-S",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t\u0000raw\u0000-S\u0000CILIUM_OUTPUT_raw",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t\u0000raw\u0000-S\u0000CILIUM_PRE_raw",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t\u0000raw\u0000-S\u0000OLD_CILIUM_OUTPUT_raw",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t\u0000raw\u0000-S\u0000OLD_CILIUM_PRE_raw",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-A\u0000CILIUM_FORWARD\u0000-i\u0000cilium_host\u0000-m\u0000comment\u0000--comment\u0000cilium: cluster->any on cilium_host forward accept (nodeport)\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-A\u0000CILIUM_FORWARD\u0000-i\u0000cilium_net\u0000-m\u0000comment\u0000--comment\u0000cilium: cluster->any on cilium_net forward accept (nodeport)\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-A\u0000CILIUM_FORWARD\u0000-i\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium: cluster->any on lxc+ forward accept\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-A\u0000CILIUM_FORWARD\u0000-i\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium: cluster->any on lxc+ forward accept (nodeport)\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-A\u0000CILIUM_FORWARD\u0000-o\u0000cilium_host\u0000-m\u0000comment\u0000--comment\u0000cilium: any->cluster on cilium_host forward accept\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-A\u0000CILIUM_FORWARD\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium: any->cluster on lxc+ forward accept\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-A\u0000CILIUM_INPUT\u0000-m\u0000mark\u0000--mark\u00000x00000200/0x00000f00\u0000-m\u0000comment\u0000--comment\u0000cilium: ACCEPT for proxy traffic\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-A\u0000CILIUM_OUTPUT\u0000-m\u0000mark\u0000!\u0000--mark\u00000x00000e00/0x00000f00\u0000-m\u0000mark\u0000!\u0000--mark\u00000x00000d00/0x00000f00",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-A\u0000CILIUM_OUTPUT\u0000-m\u0000mark\u0000--mark\u00000x00000800/0x00000e00\u0000-m\u0000comment\u0000--comment\u0000cilium: ACCEPT for l7 proxy upstream traffic\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-A\u0000CILIUM_OUTPUT\u0000-m\u0000mark\u0000--mark\u00000x00000a00/0x00000e00\u0000-m\u0000comment\u0000--comment\u0000cilium: ACCEPT for proxy traffic\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000FORWARD\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_FORWARD\u0000-j\u0000OLD_CILIUM_FORWARD",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000INPUT\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_INPUT\u0000-j\u0000OLD_CILIUM_INPUT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OLD_CILIUM_FORWARD\u0000-i\u0000cilium_host\u0000-m\u0000comment\u0000--comment\u0000cilium: cluster->any on cilium_host forward accept (nodeport)\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OLD_CILIUM_FORWARD\u0000-i\u0000cilium_net\u0000-m\u0000comment\u0000--comment\u0000cilium: cluster->any on cilium_net forward accept (nodeport)\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OLD_CILIUM_FORWARD\u0000-i\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium: cluster->any on lxc+ forward accept\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OLD_CILIUM_FORWARD\u0000-i\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium: cluster->any on lxc+ forward accept (nodeport)\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OLD_CILIUM_FORWARD\u0000-o\u0000cilium_host\u0000-m\u0000comment\u0000--comment\u0000cilium: any->cluster on cilium_host forward accept\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OLD_CILIUM_FORWARD\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium: any->cluster on lxc+ forward accept\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OLD_CILIUM_INPUT\u0000-m\u0000mark\u0000--mark\u00000x200/0xf00\u0000-m\u0000comment\u0000--comment\u0000cilium: ACCEPT for proxy traffic\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OLD_CILIUM_OUTPUT\u0000-m\u0000mark",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OLD_CILIUM_OUTPUT\u0000-m\u0000mark\u0000--mark\u00000x800/0xe00\u0000-m\u0000comment\u0000--comment\u0000cilium: ACCEPT for l7 proxy upstream traffic\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OLD_CILIUM_OUTPUT\u0000-m\u0000mark\u0000--mark\u00000xa00/0xe00\u0000-m\u0000comment\u0000--comment\u0000cilium: ACCEPT for proxy traffic\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-D\u0000OUTPUT\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_OUTPUT\u0000-j\u0000OLD_CILIUM_OUTPUT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-E\u0000CILIUM_FORWARD\u0000OLD_CILIUM_FORWARD",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-E\u0000CILIUM_INPUT\u0000OLD_CILIUM_INPUT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-E\u0000CILIUM_OUTPUT\u0000OLD_CILIUM_OUTPUT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-F\u0000OLD_CILIUM_FORWARD",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-F\u0000OLD_CILIUM_INPUT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-F\u0000OLD_CILIUM_OUTPUT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-I\u0000FORWARD\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_FORWARD\u0000-j\u0000CILIUM_FORWARD",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-I\u0000INPUT\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_INPUT\u0000-j\u0000CILIUM_INPUT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-I\u0000OUTPUT\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_OUTPUT\u0000-j\u0000CILIUM_OUTPUT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-N\u0000CILIUM_FORWARD",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-N\u0000CILIUM_INPUT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-N\u0000CILIUM_OUTPUT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w\u00005\u0000-t\u0000filter\u0000-S",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-S\u0000CILIUM_FORWARD",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-S\u0000CILIUM_INPUT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-S\u0000CILIUM_OUTPUT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-S\u0000OLD_CILIUM_FORWARD",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-S\u0000OLD_CILIUM_INPUT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-S\u0000OLD_CILIUM_OUTPUT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-X\u0000OLD_CILIUM_FORWARD",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-X\u0000OLD_CILIUM_INPUT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000filter\u0000-X\u0000OLD_CILIUM_OUTPUT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-i\u0000ens5\u0000-m\u0000comment\u0000--comment\u0000cilium: primary ENI\u0000-m\u0000addrtype\u0000--dst-type\u0000LOCAL\u0000--limit-iface-in\u0000-j\u0000CONNMARK\u0000--set-xmark\u00000x00000080/0x00000080",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-i\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium: primary ENI\u0000-j\u0000CONNMARK\u0000--restore-mark\u0000--nfmask\u00000x00000080\u0000--ctmask\u00000x00000080",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-m\u0000socket\u0000--transparent\u0000!\u0000-o\u0000lo\u0000-m\u0000mark\u0000!\u0000--mark\u00000x00000e00/0x00000f00\u0000-m\u0000mark\u0000!\u0000--mark\u00000x00000800/0x00000f00\u0000-m\u0000comment\u0000--comment\u0000cilium: any->pod redirect proxied traffic to host proxy\u0000-j\u0000MARK\u0000--set-mark\u00000x00000200",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000x26360200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000013862",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000x2baa0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000043563",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000x5b2f0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000012123",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000x5bb40200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000046171",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000x5e2d0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000011614",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000x61a30200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000041825",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000x67a80200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000043111",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000x83ab0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000043907",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000x982c0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000011416",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xa4370200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000014244",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xb3a10200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000041395",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xbf8a0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000035519",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xc0340200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000013504",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xc1a50200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000042433",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xcda10200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000041421",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xcf3c0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000015567",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xda2f0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000012250",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xe2420200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000017122",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xf84c0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000019704",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xf9b60200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000046841",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000x26360200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000013862",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000x2baa0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000043563",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000x5b2f0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000012123",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000x5bb40200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000046171",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000x5e2d0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000011614",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000x61a30200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000041825",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000x67a80200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000043111",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000x83ab0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000043907",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000x982c0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000011416",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xa4370200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000014244",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xb3a10200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000041395",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xbf8a0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000035519",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xc0340200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000013504",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xc1a50200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000042433",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xcda10200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000041421",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xcf3c0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000015567",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xda2f0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000012250",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xe2420200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000017122",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xf84c0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000019704",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-A\u0000CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xf9b60200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--tproxy-mark\u00000x200\u0000--on-ip\u0000127.0.0.1\u0000--on-port\u000046841",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000!\u0000-o\u0000lo\u0000-m\u0000socket\u0000--transparent\u0000-m\u0000mark\u0000!\u0000--mark\u00000xe00/0xf00\u0000-m\u0000mark\u0000!\u0000--mark\u00000x800/0xf00\u0000-m\u0000comment\u0000--comment\u0000cilium: any->pod redirect proxied traffic to host proxy\u0000-j\u0000MARK\u0000--set-xmark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-i\u0000ens5\u0000-m\u0000comment\u0000--comment\u0000cilium: primary ENI\u0000-m\u0000addrtype\u0000--dst-type\u0000LOCAL\u0000--limit-iface-in\u0000-j\u0000CONNMARK\u0000--set-xmark\u00000x80/0x80",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-i\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium: primary ENI\u0000-j\u0000CONNMARK\u0000--restore-mark\u0000--nfmask\u00000x80\u0000--ctmask\u00000x80",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000x26360200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000013862\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000x2baa0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000043563\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000x5b2f0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000012123\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000x5bb40200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000046171\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000x5e2d0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000011614\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000x61a30200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000041825\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000x67a80200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000043111\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000x83ab0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000043907\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000x982c0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000011416\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xa4370200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000014244\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xb3a10200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000041395\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xbf8a0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000035519\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xc0340200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000013504\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xc1a50200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000042433\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xcda10200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000041421\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xcf3c0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000015567\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xda2f0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000012250\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xe2420200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000017122\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xf84c0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000019704\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000tcp\u0000-m\u0000mark\u0000--mark\u00000xf9b60200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000046841\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000x26360200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000013862\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000x2baa0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000043563\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000x5b2f0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000012123\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000x5bb40200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000046171\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000x5e2d0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000011614\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000x61a30200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000041825\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000x67a80200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000043111\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000x83ab0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000043907\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000x982c0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000011416\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xa4370200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000014244\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xb3a10200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000041395\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xbf8a0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000035519\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xc0340200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000013504\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xc1a50200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000042433\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xcda10200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000041421\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xcf3c0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000015567\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xda2f0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000012250\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xe2420200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000017122\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xf84c0200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host kube-system/cilium-ingress/listener proxy\u0000-j\u0000TPROXY\u0000--on-port\u000019704\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000OLD_CILIUM_PRE_mangle\u0000-p\u0000udp\u0000-m\u0000mark\u0000--mark\u00000xf9b60200\u0000-m\u0000comment\u0000--comment\u0000cilium: TPROXY to host cilium-dns-egress proxy\u0000-j\u0000TPROXY\u0000--on-port\u000046841\u0000--on-ip\u0000127.0.0.1\u0000--tproxy-mark\u00000x200/0xffffffff",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000POSTROUTING\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_POST_mangle\u0000-j\u0000OLD_CILIUM_POST_mangle",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-D\u0000PREROUTING\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_PRE_mangle\u0000-j\u0000OLD_CILIUM_PRE_mangle",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-E\u0000CILIUM_POST_mangle\u0000OLD_CILIUM_POST_mangle",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-E\u0000CILIUM_PRE_mangle\u0000OLD_CILIUM_PRE_mangle",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-F\u0000OLD_CILIUM_POST_mangle",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-F\u0000OLD_CILIUM_PRE_mangle",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-I\u0000POSTROUTING\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_POST_mangle\u0000-j\u0000CILIUM_POST_mangle",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-I\u0000PREROUTING\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_PRE_mangle\u0000-j\u0000CILIUM_PRE_mangle",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-N\u0000CILIUM_POST_mangle",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-N\u0000CILIUM_PRE_mangle",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w\u00005\u0000-t\u0000mangle\u0000-S",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-S\u0000CILIUM_POST_mangle",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-S\u0000CILIUM_PRE_mangle",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-S\u0000OLD_CILIUM_POST_mangle",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-S\u0000OLD_CILIUM_PRE_mangle",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-X\u0000OLD_CILIUM_POST_mangle",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-X\u0000OLD_CILIUM_PRE_mangle",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000mangle\u0000-n\u0000-L\u0000CILIUM_PRE_mangle",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-A\u0000CILIUM_POST_nat\u0000!\u0000-d\u000010.3.0.0/20\u0000-o\u0000ens+\u0000-m\u0000comment\u0000--comment\u0000cilium masquerade non-cluster\u0000-j\u0000MASQUERADE",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-A\u0000CILIUM_POST_nat\u0000-m\u0000mark\u0000--mark\u00000x00000a00/0x00000e00\u0000-m\u0000comment\u0000--comment\u0000exclude proxy return traffic from masquerade\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-A\u0000CILIUM_POST_nat\u0000-o\u0000ens+\u0000-m\u0000set\u0000--match-set\u0000cilium_node_set_v4\u0000dst\u0000-m\u0000comment\u0000--comment\u0000exclude traffic to cluster nodes from masquerade\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-A\u0000CILIUM_POST_nat\u0000-s\u0000127.0.0.1\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.5.108",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-A\u0000CILIUM_POST_nat\u0000-s\u0000127.0.0.1\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.5.128",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-A\u0000CILIUM_POST_nat\u0000-s\u0000127.0.0.1\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.5.157",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-A\u0000CILIUM_POST_nat\u0000-s\u0000127.0.0.1\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.6.148",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-A\u0000CILIUM_POST_nat\u0000-s\u0000127.0.0.1\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.6.197",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-A\u0000CILIUM_POST_nat\u0000-s\u0000127.0.0.1\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.6.205",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-A\u0000CILIUM_POST_nat\u0000-s\u0000127.0.0.1\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.6.65",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-A\u0000CILIUM_POST_nat\u0000-s\u0000127.0.0.1\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.8.134",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-A\u0000CILIUM_POST_nat\u0000-s\u0000127.0.0.1\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.8.157",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-A\u0000CILIUM_POST_nat\u0000-s\u0000127.0.0.1\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.8.74",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000OLD_CILIUM_POST_nat\u0000!\u0000-d\u000010.3.0.0/20\u0000-o\u0000ens+\u0000-m\u0000comment\u0000--comment\u0000cilium masquerade non-cluster\u0000-j\u0000MASQUERADE",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000OLD_CILIUM_POST_nat\u0000-m\u0000mark\u0000--mark\u00000xa00/0xe00\u0000-m\u0000comment\u0000--comment\u0000exclude proxy return traffic from masquerade\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000OLD_CILIUM_POST_nat\u0000-o\u0000ens+\u0000-m\u0000set\u0000--match-set\u0000cilium_node_set_v4\u0000dst\u0000-m\u0000comment\u0000--comment\u0000exclude traffic to cluster nodes from masquerade\u0000-j\u0000ACCEPT",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000OLD_CILIUM_POST_nat\u0000-s\u0000127.0.0.1/32\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.5.108",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000OLD_CILIUM_POST_nat\u0000-s\u0000127.0.0.1/32\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.5.128",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000OLD_CILIUM_POST_nat\u0000-s\u0000127.0.0.1/32\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.5.157",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000OLD_CILIUM_POST_nat\u0000-s\u0000127.0.0.1/32\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.6.148",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000OLD_CILIUM_POST_nat\u0000-s\u0000127.0.0.1/32\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.6.197",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000OLD_CILIUM_POST_nat\u0000-s\u0000127.0.0.1/32\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.6.205",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000OLD_CILIUM_POST_nat\u0000-s\u0000127.0.0.1/32\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.6.65",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000OLD_CILIUM_POST_nat\u0000-s\u0000127.0.0.1/32\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.8.134",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000OLD_CILIUM_POST_nat\u0000-s\u0000127.0.0.1/32\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.8.157",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000OLD_CILIUM_POST_nat\u0000-s\u0000127.0.0.1/32\u0000-o\u0000lxc+\u0000-m\u0000comment\u0000--comment\u0000cilium host->cluster from 127.0.0.1 masquerade\u0000-j\u0000SNAT\u0000--to-source\u000010.3.8.74",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000OUTPUT\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_OUTPUT_nat\u0000-j\u0000OLD_CILIUM_OUTPUT_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000POSTROUTING\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_POST_nat\u0000-j\u0000OLD_CILIUM_POST_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-D\u0000PREROUTING\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_PRE_nat\u0000-j\u0000OLD_CILIUM_PRE_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-E\u0000CILIUM_OUTPUT_nat\u0000OLD_CILIUM_OUTPUT_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-E\u0000CILIUM_POST_nat\u0000OLD_CILIUM_POST_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-E\u0000CILIUM_PRE_nat\u0000OLD_CILIUM_PRE_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-F\u0000OLD_CILIUM_OUTPUT_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-F\u0000OLD_CILIUM_POST_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-F\u0000OLD_CILIUM_PRE_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-I\u0000OUTPUT\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_OUTPUT_nat\u0000-j\u0000CILIUM_OUTPUT_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-I\u0000POSTROUTING\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_POST_nat\u0000-j\u0000CILIUM_POST_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-I\u0000PREROUTING\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_PRE_nat\u0000-j\u0000CILIUM_PRE_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-N\u0000CILIUM_OUTPUT_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-N\u0000CILIUM_POST_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-N\u0000CILIUM_PRE_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w\u00005\u0000-t\u0000nat\u0000-S",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-S\u0000CILIUM_OUTPUT_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-S\u0000CILIUM_POST_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-S\u0000CILIUM_PRE_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-S\u0000OLD_CILIUM_OUTPUT_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-S\u0000OLD_CILIUM_POST_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-S\u0000OLD_CILIUM_PRE_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-X\u0000OLD_CILIUM_OUTPUT_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-X\u0000OLD_CILIUM_POST_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000nat\u0000-X\u0000OLD_CILIUM_PRE_nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-A\u0000CILIUM_OUTPUT_raw\u0000-o\u0000cilium_host\u0000-m\u0000mark\u0000--mark\u00000x00000800/0x00000e00\u0000-m\u0000comment\u0000--comment\u0000cilium: NOTRACK for L7 proxy upstream traffic\u0000-j\u0000CT\u0000--notrack",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-A\u0000CILIUM_OUTPUT_raw\u0000-o\u0000cilium_host\u0000-m\u0000mark\u0000--mark\u00000x00000a00/0xfffffeff\u0000-m\u0000comment\u0000--comment\u0000cilium: NOTRACK for proxy return traffic\u0000-j\u0000CT\u0000--notrack",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-A\u0000CILIUM_OUTPUT_raw\u0000-o\u0000lxc+\u0000-m\u0000mark\u0000--mark\u00000x00000800/0x00000e00\u0000-m\u0000comment\u0000--comment\u0000cilium: NOTRACK for L7 proxy upstream traffic\u0000-j\u0000CT\u0000--notrack",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-A\u0000CILIUM_OUTPUT_raw\u0000-o\u0000lxc+\u0000-m\u0000mark\u0000--mark\u00000x00000a00/0xfffffeff\u0000-m\u0000comment\u0000--comment\u0000cilium: NOTRACK for proxy return traffic\u0000-j\u0000CT\u0000--notrack",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-A\u0000CILIUM_PRE_raw\u0000-m\u0000mark\u0000--mark\u00000x00000200/0x00000f00\u0000-m\u0000comment\u0000--comment\u0000cilium: NOTRACK for proxy traffic\u0000-j\u0000CT\u0000--notrack",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-D\u0000OLD_CILIUM_OUTPUT_raw\u0000-o\u0000cilium_host\u0000-m\u0000mark\u0000--mark\u00000x800/0xe00\u0000-m\u0000comment\u0000--comment\u0000cilium: NOTRACK for L7 proxy upstream traffic\u0000-j\u0000CT\u0000--notrack",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-D\u0000OLD_CILIUM_OUTPUT_raw\u0000-o\u0000cilium_host\u0000-m\u0000mark\u0000--mark\u00000xa00/0xfffffeff\u0000-m\u0000comment\u0000--comment\u0000cilium: NOTRACK for proxy return traffic\u0000-j\u0000CT\u0000--notrack",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-D\u0000OLD_CILIUM_OUTPUT_raw\u0000-o\u0000lxc+\u0000-m\u0000mark\u0000--mark\u00000x800/0xe00\u0000-m\u0000comment\u0000--comment\u0000cilium: NOTRACK for L7 proxy upstream traffic\u0000-j\u0000CT\u0000--notrack",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-D\u0000OLD_CILIUM_OUTPUT_raw\u0000-o\u0000lxc+\u0000-m\u0000mark\u0000--mark\u00000xa00/0xfffffeff\u0000-m\u0000comment\u0000--comment\u0000cilium: NOTRACK for proxy return traffic\u0000-j\u0000CT\u0000--notrack",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-D\u0000OLD_CILIUM_PRE_raw\u0000-m\u0000mark\u0000--mark\u00000x200/0xf00\u0000-m\u0000comment\u0000--comment\u0000cilium: NOTRACK for proxy traffic\u0000-j\u0000CT\u0000--notrack",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-D\u0000OUTPUT\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_OUTPUT_raw\u0000-j\u0000OLD_CILIUM_OUTPUT_raw",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-D\u0000PREROUTING\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_PRE_raw\u0000-j\u0000OLD_CILIUM_PRE_raw",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-E\u0000CILIUM_OUTPUT_raw\u0000OLD_CILIUM_OUTPUT_raw",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-E\u0000CILIUM_PRE_raw\u0000OLD_CILIUM_PRE_raw",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-F\u0000OLD_CILIUM_OUTPUT_raw",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-F\u0000OLD_CILIUM_PRE_raw",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-I\u0000OUTPUT\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_OUTPUT_raw\u0000-j\u0000CILIUM_OUTPUT_raw",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-I\u0000PREROUTING\u0000-m\u0000comment\u0000--comment\u0000cilium-feeder: CILIUM_PRE_raw\u0000-j\u0000CILIUM_PRE_raw",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-N\u0000CILIUM_OUTPUT_raw",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-N\u0000CILIUM_PRE_raw",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w\u00005\u0000-t\u0000raw\u0000-S",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-S\u0000CILIUM_OUTPUT_raw",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-S\u0000CILIUM_PRE_raw",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-S\u0000OLD_CILIUM_OUTPUT_raw",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-S\u0000OLD_CILIUM_PRE_raw",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-X\u0000OLD_CILIUM_OUTPUT_raw",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-t\u0000raw\u0000-X\u0000OLD_CILIUM_PRE_raw",
              },
            ],
          },
          {
            name: "cilium-node-init",
            kind: "DaemonSet",
            processes: [
              { name: "/bin/busybox", arguments: "30" },
              {
                name: "/usr/bin/nsenter",
                arguments:
                  "-t\u00001\u0000-m\u0000-u\u0000-i\u0000-n\u0000-p\u0000--\u0000stat\u0000/tmp/startup-script.kubernetes.io_81dc8a581b97e85076f03766446d2136",
              },
              {
                name: "/usr/bin/stat",
                arguments:
                  "/tmp/startup-script.kubernetes.io_81dc8a581b97e85076f03766446d2136",
              },
            ],
          },
          {
            name: "ebs-csi-node",
            kind: "DaemonSet",
            processes: [
              {
                name: "/csi-node-driver-registrar",
                arguments:
                  "--csi-address=/csi/csi.sock\u0000--kubelet-registration-path=/var/lib/kubelet/plugins/ebs.csi.aws.com/csi.sock\u0000--v=2",
              },
              {
                name: "/csi-node-driver-registrar",
                arguments:
                  "--kubelet-registration-path=/var/lib/kubelet/plugins/ebs.csi.aws.com/csi.sock\u0000--mode=kubelet-registration-probe",
              },
              { name: "/livenessprobe" },
              {
                name: "/livenessprobe",
                arguments: "--csi-address=/csi/csi.sock",
              },
              {
                name: "/usr/bin/aws-ebs-csi-driver",
                arguments:
                  "node\u0000--endpoint=unix:/csi/csi.sock\u0000--logging-format=text\u0000--v=2",
                connections: [
                  {
                    destination_name: "169.254.169.254",
                    destination_port: "80",
                    bytes_sent: "3014",
                    bytes_received: "3903",
                  },
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "2866",
                    bytes_received: "12732",
                  },
                ],
              },
              {
                name: "/usr/bin/mount",
                arguments: "-t\u0000ext4\u0000-o\u0000bind\u0000/var/lib/kub",
              },
              {
                name: "/usr/bin/mount",
                arguments:
                  "-t\u0000ext4\u0000-o\u0000bind,remount\u0000/var/lib/kub",
              },
              {
                name: "/usr/bin/mount",
                arguments:
                  "-t\u0000ext4\u0000-o\u0000defaults\u0000/dev/nvme1n1\u0000/var/lib/kubelet/plugins/kubernetes.io/csi/ebs.csi.aws.com/49ae77e1c2494c7f14548b1836355d10603fb52e8671874e1c3a003be2f2836c/globalmount",
              },
              {
                name: "/usr/bin/mount",
                arguments:
                  "-t\u0000ext4\u0000-o\u0000defaults\u0000/dev/nvme1n1\u0000/var/lib/kubelet/plugins/kubernetes.io/csi/ebs.csi.aws.com/835b4d85b60f806c384213df06a69db3d1c6eaf5fb577b6c65c63bf77dec7205/globalmount",
              },
              {
                name: "/usr/bin/mount",
                arguments:
                  "-t\u0000ext4\u0000-o\u0000defaults\u0000/dev/nvme1n1\u0000/var/lib/kubelet/plugins/kubernetes.io/csi/ebs.csi.aws.com/8bf68760b655791cbcb5ce15af21142959fc3fa0256fd86e14cfa4177730c279/globalmount",
              },
              {
                name: "/usr/bin/mount",
                arguments:
                  "-t\u0000ext4\u0000-o\u0000defaults\u0000/dev/nvme1n1\u0000/var/lib/kubelet/plugins/kubernetes.io/csi/ebs.csi.aws.com/abc806825eb8675f8e4921bfaad9db33947519624c002906f719d435fdcb4c84/globalmount",
              },
              {
                name: "/usr/bin/mount",
                arguments:
                  "-t\u0000ext4\u0000-o\u0000defaults\u0000/dev/nvme1n1\u0000/var/lib/kubelet/plugins/kubernetes.io/csi/ebs.csi.aws.com/c327d7ca10f3be4d266f7dc23e0700af8f50448884d095ed7fb8e4df2bda90ab/globalmount",
              },
              {
                name: "/usr/bin/mount",
                arguments:
                  "-t\u0000ext4\u0000-o\u0000defaults\u0000/dev/nvme2n1\u0000/var/lib/kubelet/plugins/kubernetes.io/csi/ebs.csi.aws.com/a4799c4978c00bcf3dee4453aefb928c7e1be669df2a25a3eb226dc2b7d4534d/globalmount",
              },
              {
                name: "/usr/bin/mount",
                arguments:
                  "-t\u0000ext4\u0000-o\u0000defaults\u0000/dev/nvme2n1\u0000/var/lib/kubelet/plugins/kubernetes.io/csi/ebs.csi.aws.com/d3b3cbcd7407a0cb2bd7c224b1e89347dcbe2eb3a787271b52b51d64fd84ecc3/globalmount",
              },
              {
                name: "/usr/bin/umount",
                arguments:
                  "/var/lib/kubelet/plugins/kubernetes.io/csi/ebs.csi.aws.com/835b4d85b60f806c384213df06a69db3d1c6eaf5fb577b6c65c63bf77dec7205/globalmount",
              },
              {
                name: "/usr/bin/umount",
                arguments:
                  "/var/lib/kubelet/plugins/kubernetes.io/csi/ebs.csi.aws.com/a4799c4978c00bcf3dee4453aefb928c7e1be669df2a25a3eb226dc2b7d4534d/globalmount",
              },
              {
                name: "/usr/bin/umount",
                arguments:
                  "/var/lib/kubelet/pods/c2370d91-6e9d-4b5b-b423-32f019cb3b00/volumes/kubernetes.io~csi/pvc-ab6b2375-f6c8-4db7-b8fe-fccb572c7bba/mount",
              },
              {
                name: "/usr/bin/umount",
                arguments:
                  "/var/lib/kubelet/pods/df66ebde-972b-419f-8b86-3ed6530dd871/volumes/kubernetes.io~csi/pvc-ee499bc5-4b28-4b00-b747-d09e4da18cce/mount",
              },
              {
                name: "/usr/sbin/blkid",
                arguments:
                  "-p\u0000-s\u0000TYPE\u0000-s\u0000PTTYPE\u0000-o\u0000export\u0000/dev/nvme1n1",
              },
              {
                name: "/usr/sbin/blkid",
                arguments:
                  "-p\u0000-s\u0000TYPE\u0000-s\u0000PTTYPE\u0000-o\u0000export\u0000/dev/nvme2n1",
              },
              {
                name: "/usr/sbin/blkid",
                arguments:
                  "-p\u0000-s\u0000TYPE\u0000-s\u0000PTTYPE\u0000-o\u0000export\u0000/dev/nvme3n1",
              },
              {
                name: "/usr/sbin/blockdev",
                arguments: "--getro\u0000/dev/nvme1n1",
              },
              {
                name: "/usr/sbin/blockdev",
                arguments: "--getro\u0000/dev/nvme2n1",
              },
              {
                name: "/usr/sbin/blockdev",
                arguments: "--getsize64\u0000/dev/nvme1n1",
              },
              {
                name: "/usr/sbin/blockdev",
                arguments: "--getsize64\u0000/dev/nvme2n1",
              },
              {
                name: "/usr/sbin/dumpe2fs",
                arguments: "-h\u0000/dev/nvme1n1",
              },
              {
                name: "/usr/sbin/dumpe2fs",
                arguments: "-h\u0000/dev/nvme2n1",
              },
              { name: "/usr/sbin/fsck", arguments: "-a\u0000/dev/nvme1n1" },
              { name: "/usr/sbin/fsck", arguments: "-a\u0000/dev/nvme2n1" },
              {
                name: "/usr/sbin/fsck.ext4",
                arguments: "-a\u0000/dev/nvme1n1",
              },
              {
                name: "/usr/sbin/fsck.ext4",
                arguments: "-a\u0000/dev/nvme2n1",
              },
            ],
          },
          {
            name: "kube-proxy",
            kind: "DaemonSet",
            processes: [
              {
                name: "/usr/local/bin/kube-proxy",
                connections: [
                  {
                    destination_name: "10.3.6.8",
                    destination_port: "443",
                    bytes_sent: "36731",
                    bytes_received: "805433",
                  },
                  {
                    destination_name: "10.3.7.177",
                    destination_port: "443",
                  },
                  {
                    destination_name:
                      "3BE81FD965B44E29EE37641B4D0F95CD.gr7.us-west-2.eks.amazonaws.com",
                    destination_port: "443",
                  },
                  {
                    destination_name:
                      "3be81fd965b44e29ee37641b4d0f95cd.gr7.us-west-2.eks.amazonaws.com",
                    destination_port: "443",
                  },
                ],
              },
              {
                name: "/usr/sbin/conntrack",
                arguments:
                  "-D\u0000--orig-dst\u0000172.20.0.10\u0000--dst-nat\u000010.3.5.115\u0000-p\u0000udp",
              },
              {
                name: "/usr/sbin/conntrack",
                arguments:
                  "-D\u0000--orig-dst\u0000172.20.0.10\u0000--dst-nat\u000010.3.5.57\u0000-p\u0000udp",
              },
              {
                name: "/usr/sbin/conntrack",
                arguments:
                  "-D\u0000--orig-dst\u0000172.20.0.10\u0000--dst-nat\u000010.3.6.119\u0000-p\u0000udp",
              },
              {
                name: "/usr/sbin/conntrack",
                arguments:
                  "-D\u0000--orig-dst\u0000172.20.0.10\u0000--dst-nat\u000010.3.7.10\u0000-p\u0000udp",
              },
              {
                name: "/usr/sbin/conntrack",
                arguments:
                  "-D\u0000--orig-dst\u0000172.20.0.10\u0000--dst-nat\u000010.3.8.251\u0000-p\u0000udp",
              },
              {
                name: "/usr/sbin/conntrack",
                arguments:
                  "-D\u0000--orig-dst\u0000172.20.0.10\u0000--dst-nat\u000010.3.8.64\u0000-p\u0000udp",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t\u0000nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000--noflush\u0000--counters",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000FORWARD\u0000-t\u0000filter\u0000-m\u0000comment\u0000--comment\u0000kubernetes forwarding rules\u0000-j\u0000KUBE-FORWARD",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000FORWARD\u0000-t\u0000filter\u0000-m\u0000conntrack\u0000--ctstate\u0000NEW\u0000-m\u0000comment\u0000--comment\u0000kubernetes externally-visible service portals\u0000-j\u0000KUBE-EXTERNAL-SERVICES",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000FORWARD\u0000-t\u0000filter\u0000-m\u0000conntrack\u0000--ctstate\u0000NEW\u0000-m\u0000comment\u0000--comment\u0000kubernetes load balancer firewall\u0000-j\u0000KUBE-PROXY-FIREWALL",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000FORWARD\u0000-t\u0000filter\u0000-m\u0000conntrack\u0000--ctstate\u0000NEW\u0000-m\u0000comment\u0000--comment\u0000kubernetes service portals\u0000-j\u0000KUBE-SERVICES",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000INPUT\u0000-t\u0000filter\u0000-j\u0000KUBE-FIREWALL",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000INPUT\u0000-t\u0000filter\u0000-m\u0000comment\u0000--comment\u0000kubernetes health check service ports\u0000-j\u0000KUBE-NODEPORTS",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000INPUT\u0000-t\u0000filter\u0000-m\u0000conntrack\u0000--ctstate\u0000NEW\u0000-m\u0000comment\u0000--comment\u0000kubernetes externally-visible service portals\u0000-j\u0000KUBE-EXTERNAL-SERVICES",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000INPUT\u0000-t\u0000filter\u0000-m\u0000conntrack\u0000--ctstate\u0000NEW\u0000-m\u0000comment\u0000--comment\u0000kubernetes load balancer firewall\u0000-j\u0000KUBE-PROXY-FIREWALL",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000OUTPUT\u0000-t\u0000filter\u0000-j\u0000KUBE-FIREWALL",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000OUTPUT\u0000-t\u0000filter\u0000-m\u0000conntrack\u0000--ctstate\u0000NEW\u0000-m\u0000comment\u0000--comment\u0000kubernetes load balancer firewall\u0000-j\u0000KUBE-PROXY-FIREWALL",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000OUTPUT\u0000-t\u0000filter\u0000-m\u0000conntrack\u0000--ctstate\u0000NEW\u0000-m\u0000comment\u0000--comment\u0000kubernetes service portals\u0000-j\u0000KUBE-SERVICES",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000OUTPUT\u0000-t\u0000nat\u0000-m\u0000comment\u0000--comment\u0000kubernetes service portals\u0000-j\u0000KUBE-SERVICES",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000POSTROUTING\u0000-t\u0000nat\u0000-m\u0000comment\u0000--comment\u0000kubernetes postrouting rules\u0000-j\u0000KUBE-POSTROUTING",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-C\u0000PREROUTING\u0000-t\u0000nat\u0000-m\u0000comment\u0000--comment\u0000kubernetes service portals\u0000-j\u0000KUBE-SERVICES",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-N\u0000KUBE-EXTERNAL-SERVICES\u0000-t\u0000filter",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-N\u0000KUBE-FIREWALL\u0000-t\u0000filter",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-N\u0000KUBE-FORWARD\u0000-t\u0000filter",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-N\u0000KUBE-NODEPORTS\u0000-t\u0000filter",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-N\u0000KUBE-POSTROUTING\u0000-t\u0000nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-N\u0000KUBE-PROXY-FIREWALL\u0000-t\u0000filter",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-N\u0000KUBE-SERVICES\u0000-t\u0000filter",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-N\u0000KUBE-SERVICES\u0000-t\u0000nat",
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w\u00005\u0000-W\u0000100000\u0000-S\u0000KUBE-PROXY-CANARY\u0000-t\u0000mangle",
              },
            ],
          },
          {
            name: "coredns",
            kind: "Deployment",
            processes: [
              {
                name: "/coredns",
                arguments: "-conf\u0000/etc/coredns/Corefile",
                connections: [
                  {
                    destination_name: "127.0.0.1",
                    destination_port: "8080",
                    bytes_sent: "4120",
                    bytes_received: "3340",
                  },
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "6070",
                    bytes_received: "120162",
                  },
                ],
              },
            ],
          },
          {
            name: "ebs-csi-controller",
            kind: "Deployment",
            processes: [
              {
                name: "/csi-attacher",
                arguments:
                  "--csi-address=/var/lib/csi/sockets/pluginproxy/csi.sock\u0000--v=2\u0000--leader-election=true",
                connections: [
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "2323",
                    bytes_received: "4213",
                  },
                ],
              },
              {
                name: "/csi-provisioner",
                arguments:
                  "--csi-address=/var/lib/csi/sockets/pluginproxy/csi.sock\u0000--v=2\u0000--feature-gates=Topology=true\u0000--extra-create-metadata\u0000--leader-election=true\u0000--default-fstype=ext4",
                connections: [
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "2359",
                    bytes_received: "4190",
                  },
                ],
              },
              {
                name: "/csi-resizer",
                arguments:
                  "--csi-address=/var/lib/csi/sockets/pluginproxy/csi.sock\u0000--v=2\u0000--handle-volume-inuse-error=false\u0000--leader-election=true",
                connections: [
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "2317",
                    bytes_received: "4196",
                  },
                ],
              },
              {
                name: "/csi-snapshotter",
                arguments:
                  "--csi-address=/var/lib/csi/sockets/pluginproxy/csi.sock\u0000--leader-election=true\u0000--extra-create-metadata",
                connections: [
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "2379",
                    bytes_received: "4300",
                  },
                ],
              },
              {
                name: "/livenessprobe",
                arguments: "--csi-address=/csi/csi.sock",
              },
              {
                name: "/usr/bin/aws-ebs-csi-driver",
                arguments:
                  "controller\u0000--endpoint=unix:///var/lib/csi/sockets/pluginproxy/csi.sock\u0000--k8s-tag-cluster-id=df-tetragon-dev-ce-01\u0000--logging-format=text\u0000--user-agent-extra=eks\u0000--v=2",
              },
            ],
          },
          {
            name: "hubble-ui",
            kind: "Deployment",
            processes: [
              { name: "/bin/busybox", arguments: "-V" },
              { name: "/bin/busybox", arguments: "-c\u0000-" },
              {
                name: "/bin/busybox",
                arguments: "-d\u0000:\u0000-f\u00002",
              },
              { name: "/bin/busybox", arguments: "-d \u0000-f\u00001" },
              {
                name: "/bin/busybox",
                arguments: "-p\u0000/etc/nginx/conf.d/.",
              },
              {
                name: "/bin/busybox",
                arguments:
                  "-q\u0000listen  \\[::]\\:8080;\u0000/etc/nginx/conf.d/default.conf",
              },
              {
                name: "/bin/busybox",
                arguments:
                  "/docker-entrypoint.d/\u0000-follow\u0000-type\u0000f\u0000-print",
              },
              {
                name: "/bin/busybox",
                arguments:
                  "/docker-entrypoint.d/\u0000-mindepth\u00001\u0000-maxdepth\u00001\u0000-type\u0000f\u0000-print\u0000-quit",
              },
              {
                name: "/bin/busybox",
                arguments:
                  "/docker-entrypoint.d/10-listen-on-ipv6-by-default.sh",
              },
              {
                name: "/bin/busybox",
                arguments: "/docker-entrypoint.d/20-envsubst-on-templates.sh",
              },
              {
                name: "/bin/busybox",
                arguments: "/docker-entrypoint.d/30-tune-worker-processes.sh",
              },
              {
                name: "/bin/busybox",
                arguments:
                  "/docker-entrypoint.sh\u0000nginx\u0000-g\u0000daemon off;",
              },
              {
                name: "/bin/busybox",
                arguments: "/etc/nginx/conf.d/default.conf",
              },
              {
                name: "/bin/busybox",
                arguments:
                  "/etc/nginx/templates\u0000-follow\u0000-type\u0000f\u0000-name\u0000*.template\u0000-print",
              },
              {
                name: "/bin/busybox",
                arguments:
                  "/etc/nginx/templates\u0000-name\u0000*.stream-template\u0000-print\u0000-quit",
              },
              {
                name: "/bin/busybox",
                arguments:
                  'END { for (name in ENVIRON) { print ( name ~ // ) ? name : "" } }',
              },
              { name: "/bin/busybox", arguments: "default.conf.template" },
              {
                name: "/bin/busybox",
                arguments: "etc/nginx/conf.d/default.conf",
              },
              { name: "/sbin/apk", arguments: "manifest\u0000nginx" },
              { name: "/usr/bin/backend" },
              {
                name: "/usr/bin/oauth2-proxy",
                arguments:
                  "--http-address=0.0.0.0:4180\u0000--config=/etc/oauth2_proxy/oauth2_proxy.cfg",
                connections: [
                  {
                    destination_name: "auth.isovalent.com",
                    destination_port: "443",
                    bytes_sent: "1255",
                    bytes_received: "7788",
                  },
                ],
              },
              { name: "/usr/local/bin/envsubst" },
              { name: "/usr/sbin/nginx", arguments: "-g\u0000daemon off;" },
            ],
          },
          {
            name: "onepassword-connect",
            kind: "Deployment",
            processes: [
              {
                name: "/bin/connect-api",
                connections: [
                  {
                    destination_name: "127.0.0.1",
                    destination_port: "5778",
                    bytes_sent: "600",
                    bytes_received: "400",
                  },
                  {
                    destination_name: "::1",
                    destination_port: "11221",
                    bytes_sent: "137902",
                    bytes_received: "66939",
                  },
                  {
                    destination_name: "isovalent.1password.com",
                    destination_port: "443",
                    bytes_sent: "19082",
                    bytes_received: "155851",
                  },
                ],
              },
              {
                name: "/bin/connect-sync",
                connections: [
                  {
                    destination_name: "127.0.0.1",
                    destination_port: "11220",
                    bytes_sent: "32066",
                    bytes_received: "24766",
                  },
                  {
                    destination_name: "::1",
                    destination_port: "11220",
                    bytes_sent: "80",
                  },
                  {
                    destination_name: "b5n.1password.com",
                    destination_port: "443",
                    bytes_sent: "3220",
                    bytes_received: "8837",
                  },
                  {
                    destination_name: "f.1passwordusercontent.com",
                    destination_port: "443",
                    bytes_sent: "4474",
                    bytes_received: "16637",
                  },
                  {
                    destination_name: "isovalent.1password.com",
                    destination_port: "443",
                    bytes_sent: "17854",
                    bytes_received: "288602",
                  },
                ],
              },
            ],
          },
        ],
      },
      {
        name: "kubernetes-event-exporter",
        workloads: [
          {
            name: "kubernetes-event-exporter",
            kind: "Deployment",
            processes: [
              {
                name: "/opt/bitnami/kubernetes-event-exporter/bin/kubernetes-event-exporter",
                arguments: "-conf=/data/config.yaml",
                connections: [
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "119272",
                    bytes_received: "3485920",
                  },
                ],
              },
            ],
          },
        ],
      },
      {
        name: "kubeshark",
        workloads: [
          {
            name: "kubeshark-worker-daemon-set",
            kind: "DaemonSet",
            processes: [
              {
                name: "/app/tracer",
                connections: [
                  {
                    destination_name: "172.20.0.1",
                    destination_port: "443",
                    bytes_sent: "13004",
                    bytes_received: "830929",
                  },
                  {
                    destination_name: "172.20.189.207",
                    destination_port: "80",
                    bytes_sent: "36031",
                    bytes_received: "7861614",
                  },
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                  },
                  {
                    destination_name:
                      "kubeshark-hub.kubeshark.svc.cluster.local",
                    destination_port: "80",
                    bytes_sent: "9278",
                    bytes_received: "1665446",
                  },
                  {
                    destination_name: "kubeshark/Service:kubeshark-hub",
                    destination_port: "80",
                    bytes_sent: "682",
                    bytes_received: "145712",
                  },
                ],
              },
              {
                name: "/app/worker",
                connections: [
                  {
                    destination_name: "172.20.0.1",
                    destination_port: "443",
                    bytes_sent: "13492",
                    bytes_received: "830032",
                  },
                  {
                    destination_name: "172.20.189.207",
                    destination_port: "80",
                    bytes_sent: "153217",
                    bytes_received: "481168871",
                  },
                  {
                    destination_name: "api.kubeshark.co",
                    destination_port: "443",
                    bytes_sent: "1340",
                    bytes_received: "6371",
                  },
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                  },
                  {
                    destination_name:
                      "kubeshark-hub.kubeshark.svc.cluster.local",
                    destination_port: "80",
                    bytes_sent: "48230",
                    bytes_received: "83120624",
                  },
                  {
                    destination_name: "kubeshark/Service:kubeshark-hub",
                    destination_port: "80",
                    bytes_sent: "3807",
                    bytes_received: "10565862",
                  },
                ],
              },
              {
                name: "/app/worker",
                arguments:
                  "-i\u0000any\u0000-port\u000030001\u0000-metrics-port\u000049100\u0000-packet-capture\u0000best\u0000-unixsocket\u0000-servicemesh\u0000-procfs\u0000/hostproc\u0000-disable-ebpf\u0000-resolution-strategy\u0000auto",
                connections: [
                  {
                    destination_name: "api.kubeshark.co",
                    destination_port: "443",
                    bytes_sent: "1338",
                    bytes_received: "6371",
                  },
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "5199",
                    bytes_received: "46708",
                  },
                  {
                    destination_name: "kubernetes.default.svc.cluster.local",
                    destination_port: "443",
                    bytes_sent: "44747190",
                    bytes_received: "45653879",
                  },
                  {
                    destination_name:
                      "kubeshark-hub.kubeshark.svc.cluster.local",
                    destination_port: "80",
                  },
                ],
              },
              { name: "/bin/getconf", arguments: "CLK_TCK" },
              { name: "/bin/getconf", arguments: "PAGESIZE" },
            ],
          },
        ],
      },
      {
        name: "logging",
        workloads: [
          {
            name: "promtail",
            kind: "DaemonSet",
            processes: [
              {
                name: "/usr/bin/promtail",
                connections: [
                  {
                    destination_name: "172.20.0.1",
                    destination_port: "443",
                  },
                  {
                    destination_name: "172.20.143.71",
                    destination_port: "80",
                    bytes_sent: "1248546",
                    bytes_received: "5365",
                  },
                  {
                    destination_name: "34.120.86.103",
                    destination_port: "443",
                  },
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                  },
                  {
                    destination_name: "logging/Service:loki-gateway",
                    destination_port: "80",
                  },
                  {
                    destination_name: "logs-prod3.grafana.net",
                    destination_port: "443",
                  },
                  {
                    destination_name: "loki-gateway.logging.svc.cluster.local",
                    destination_port: "80",
                    bytes_sent: "67152",
                    bytes_received: "742",
                  },
                ],
              },
              {
                name: "/usr/bin/promtail",
                arguments:
                  "-config.file=/etc/promtail/promtail.yaml\u0000-client.external-labels=cluster=df-tetragon-dev-ce-01\u0000-config.expand-env=true",
                connections: [
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "8741",
                    bytes_received: "188715",
                  },
                  {
                    destination_name: "logs-prod3.grafana.net",
                    destination_port: "443",
                    bytes_sent: "9733010",
                    bytes_received: "365390",
                  },
                  {
                    destination_name: "loki-gateway.logging.svc.cluster.local",
                    destination_port: "80",
                    bytes_sent: "11056715",
                    bytes_received: "141339",
                  },
                ],
              },
            ],
          },
          {
            name: "loki-ingester",
            kind: "StatefulSet",
            processes: [
              { name: "/bin/busybox", arguments: "-m" },
              { name: "/bin/busybox", arguments: "-r" },
              { name: "/bin/busybox", arguments: "-s" },
              {
                name: "/usr/bin/loki",
                arguments:
                  "-config.file=/etc/loki/config/config.yaml\u0000-target=ingester",
                connections: [
                  {
                    destination_name: "127.0.0.1",
                    destination_port: "5778",
                    bytes_sent: "60",
                    bytes_received: "40",
                  },
                  {
                    destination_name:
                      "loki-memberlist.logging.svc.cluster.local",
                    destination_port: "7946",
                    bytes_sent: "3578",
                    bytes_received: "3279",
                  },
                  {
                    destination_name:
                      "loki-memcached-chunks-1.loki-memcached-chunks.logging.svc.cluster.local",
                    destination_port: "11211",
                    bytes_sent: "66765491",
                    bytes_received: "72293360",
                  },
                  {
                    destination_name: "s3.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "67081022",
                    bytes_received: "402692",
                  },
                  {
                    destination_name: "stats.grafana.org",
                    destination_port: "443",
                    bytes_sent: "4034",
                    bytes_received: "4474",
                  },
                  {
                    destination_name: "sts.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "2808",
                    bytes_received: "8862",
                  },
                ],
              },
            ],
          },
          {
            name: "loki-memcached-chunks",
            kind: "StatefulSet",
            processes: [
              {
                name: "/bin/busybox",
                arguments:
                  "/usr/local/bin/docker-entrypoint.sh\u0000-m 2048\u0000-I 32m",
              },
              {
                name: "/bin/memcached_exporter",
                arguments:
                  "--memcached.address=localhost:11211\u0000--web.listen-address=0.0.0.0:9150",
                connections: [
                  {
                    destination_name: "127.0.0.1",
                    destination_port: "11211",
                    bytes_sent: "473",
                    bytes_received: "4466",
                  },
                ],
              },
              {
                name: "/usr/local/bin/memcached",
                arguments: "-m 2048\u0000-I 32m",
              },
            ],
          },
          {
            name: "loki-querier",
            kind: "StatefulSet",
            processes: [
              { name: "/bin/busybox", arguments: "-m" },
              { name: "/bin/busybox", arguments: "-r" },
              { name: "/bin/busybox", arguments: "-s" },
              {
                name: "/usr/bin/loki",
                arguments:
                  "-config.file=/etc/loki/config/config.yaml\u0000-target=querier",
                connections: [
                  {
                    destination_name: "127.0.0.1",
                    destination_port: "5778",
                    bytes_sent: "1020",
                    bytes_received: "680",
                  },
                  {
                    destination_name:
                      "loki-memberlist.logging.svc.cluster.local",
                    destination_port: "7946",
                    bytes_sent: "532016",
                    bytes_received: "212839",
                  },
                  {
                    destination_name:
                      "loki-query-frontend-headless.logging.svc.cluster.local",
                    destination_port: "9095",
                    bytes_sent: "14831",
                    bytes_received: "12149",
                  },
                  {
                    destination_name: "s3.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "64041",
                    bytes_received: "6916174",
                  },
                  {
                    destination_name: "stats.grafana.org",
                    destination_port: "443",
                    bytes_sent: "2791",
                    bytes_received: "4422",
                  },
                  {
                    destination_name: "sts.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "5860",
                    bytes_received: "18052",
                  },
                ],
              },
            ],
          },
        ],
      },
      {
        name: "minio-operator",
        workloads: [
          {
            name: "minio-operator",
            kind: "Deployment",
            processes: [
              {
                name: "/minio-operator",
                arguments: "controller",
                connections: [
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "510711",
                    bytes_received: "22581803",
                  },
                ],
              },
            ],
          },
        ],
      },
      {
        name: "monitoring",
        workloads: [
          {
            name: "prometheus-prometheus-node-exporter",
            kind: "DaemonSet",
            processes: [{ name: "/bin/node_exporter" }],
          },
          {
            name: "prometheus-adapter",
            kind: "Deployment",
            processes: [
              {
                name: "/adapter",
                arguments:
                  "/adapter\u0000--secure-port=6443\u0000--cert-dir=/tmp/cert\u0000--logtostderr=true\u0000--prometheus-url=http://prometheus-kube-prometheus-prometheus.monitoring.svc.cluster.local:9090\u0000--metrics-relist-interval=1m\u0000--v=4\u0000--config=/etc/adapter/config.yaml",
                connections: [
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "17317",
                    bytes_received: "142825",
                  },
                ],
              },
            ],
          },
          {
            name: "prometheus-grafana",
            kind: "Deployment",
            processes: [
              { name: "/bin/bash", arguments: "-e\u0000/run.sh" },
              { name: "/bin/busybox" },
              {
                name: "/bin/busybox",
                arguments:
                  "-c\u0000mkdir -p /var/lib/grafana/dashboards/default && /bin/sh -x /etc/grafana/download_dashboards.sh",
              },
              {
                name: "/bin/busybox",
                arguments: "-p\u0000/var/lib/grafana/dashboards/argocd",
              },
              {
                name: "/bin/busybox",
                arguments: "-p\u0000/var/lib/grafana/dashboards/default",
              },
              {
                name: "/bin/busybox",
                arguments: "-p\u0000/var/lib/grafana/dashboards/ingress-nginx",
              },
              {
                name: "/bin/busybox",
                arguments: "-r\u0000s/([^=]*)__FILE=.*/\\1/g",
              },
              {
                name: "/bin/busybox",
                arguments: "-x\u0000/etc/grafana/download_dashboards.sh",
              },
              {
                name: "/bin/busybox",
                arguments:
                  '/-- .* --/! s/"datasource":.*,/"datasource": "prometheus",/g',
              },
              { name: "/bin/busybox", arguments: "^GF_[^=]\\+__FILE=.\\+" },
              {
                name: "/bin/chown",
                arguments: "-R\u0000472:472\u0000/var/lib/grafana",
              },
              {
                name: "/usr/bin/curl",
                arguments:
                  "-skf\u0000--connect-timeout\u000060\u0000--max-time\u000060\u0000-H\u0000Accept: application/json\u0000-H\u0000Content-Type: application/json;charset=UTF-8\u0000https://grafana.com/api/dashboards/13500/revisions/1/download",
                connections: [
                  {
                    destination_name: "grafana.com",
                    destination_port: "443",
                    bytes_sent: "2463",
                    bytes_received: "62844",
                  },
                ],
              },
              {
                name: "/usr/bin/curl",
                arguments:
                  "-skf\u0000--connect-timeout\u000060\u0000--max-time\u000060\u0000-H\u0000Accept: application/json\u0000-H\u0000Content-Type: application/json;charset=UTF-8\u0000https://grafana.com/api/dashboards/14192/revisions/4/download",
                connections: [
                  {
                    destination_name: "grafana.com",
                    destination_port: "443",
                    bytes_sent: "4595",
                    bytes_received: "329275",
                  },
                ],
              },
              {
                name: "/usr/bin/curl",
                arguments:
                  "-skf\u0000--connect-timeout\u000060\u0000--max-time\u000060\u0000-H\u0000Accept: application/json\u0000-H\u0000Content-Type: application/json;charset=UTF-8\u0000https://grafana.com/api/dashboards/14765/revisions/3/download",
                connections: [
                  {
                    destination_name: "grafana.com",
                    destination_port: "443",
                    bytes_sent: "2255",
                    bytes_received: "50712",
                  },
                ],
              },
              {
                name: "/usr/bin/curl",
                arguments:
                  "-skf\u0000--connect-timeout\u000060\u0000--max-time\u000060\u0000-H\u0000Accept: application/json\u0000-H\u0000Content-Type: application/json;charset=UTF-8\u0000https://grafana.com/api/dashboards/16677/revisions/2/download",
                connections: [
                  {
                    destination_name: "grafana.com",
                    destination_port: "443",
                    bytes_sent: "2047",
                    bytes_received: "29699",
                  },
                ],
              },
              {
                name: "/usr/bin/curl",
                arguments:
                  "-skf\u0000--connect-timeout\u000060\u0000--max-time\u000060\u0000-H\u0000Accept: application/json\u0000-H\u0000Content-Type: application/json;charset=UTF-8\u0000https://grafana.com/api/dashboards/19974/revisions/2/download",
                connections: [
                  {
                    destination_name: "grafana.com",
                    destination_port: "443",
                    bytes_sent: "2047",
                    bytes_received: "30222",
                  },
                ],
              },
              {
                name: "/usr/bin/curl",
                arguments:
                  "-skf\u0000--connect-timeout\u000060\u0000--max-time\u000060\u0000-H\u0000Accept: application/json\u0000-H\u0000Content-Type: application/json;charset=UTF-8\u0000https://grafana.com/api/dashboards/19975/revisions/2/download",
                connections: [
                  {
                    destination_name: "grafana.com",
                    destination_port: "443",
                    bytes_sent: "2151",
                    bytes_received: "10781",
                  },
                ],
              },
              {
                name: "/usr/bin/curl",
                arguments:
                  "-skf\u0000--connect-timeout\u000060\u0000--max-time\u000060\u0000-H\u0000Accept: application/json\u0000-H\u0000Content-Type: application/json;charset=UTF-8\u0000https://grafana.com/api/dashboards/19993/revisions/2/download",
                connections: [
                  {
                    destination_name: "grafana.com",
                    destination_port: "443",
                    bytes_sent: "2359",
                    bytes_received: "33521",
                  },
                ],
              },
              {
                name: "/usr/bin/curl",
                arguments:
                  "-skf\u0000--connect-timeout\u000060\u0000--max-time\u000060\u0000-H\u0000Accept: application/json\u0000-H\u0000Content-Type: application/json;charset=UTF-8\u0000https://grafana.com/api/dashboards/20510/revisions/1/download",
                connections: [
                  {
                    destination_name: "grafana.com",
                    destination_port: "443",
                    bytes_sent: "1891",
                    bytes_received: "23411",
                  },
                ],
              },
              {
                name: "/usr/local/bin/python3.12",
                arguments: "-u\u0000/app/sidecar.py",
              },
              {
                name: "/usr/share/grafana/bin/grafana",
                arguments:
                  "cli\u0000--pluginsDir\u0000/var/lib/grafana/plugins\u0000plugins\u0000install\u0000grafana-clickhouse-datasource",
                connections: [
                  {
                    destination_name: "grafana.com",
                    destination_port: "443",
                    bytes_sent: "1382",
                    bytes_received: "32665",
                  },
                ],
              },
              {
                name: "/usr/share/grafana/bin/grafana",
                arguments:
                  "cli\u0000--pluginsDir\u0000/var/lib/grafana/plugins\u0000plugins\u0000install\u0000isovalent-hubble-datasource",
                connections: [
                  {
                    destination_name: "grafana.com",
                    destination_port: "443",
                    bytes_sent: "1068",
                    bytes_received: "5685",
                  },
                ],
              },
              {
                name: "/usr/share/grafana/bin/grafana",
                arguments:
                  "cli\u0000--pluginsDir\u0000/var/lib/grafana/plugins\u0000plugins\u0000install\u0000isovalent-hubbleprocessancestry-panel",
                connections: [
                  {
                    destination_name: "grafana.com",
                    destination_port: "443",
                    bytes_sent: "1078",
                    bytes_received: "5933",
                  },
                ],
              },
              {
                name: "/usr/share/grafana/bin/grafana",
                arguments:
                  "server\u0000--homepath=/usr/share/grafana\u0000--config=/etc/g",
                connections: [
                  {
                    destination_name: "grafana.com",
                    destination_port: "443",
                    bytes_sent: "3802",
                    bytes_received: "17054",
                  },
                  {
                    destination_name:
                      "prometheus-kube-prometheus-prometheus.monitoring.svc.cluster.local",
                    destination_port: "9090",
                    bytes_sent: "10488",
                    bytes_received: "51613",
                  },
                  {
                    destination_name: "secure.gravatar.com",
                    destination_port: "443",
                    bytes_sent: "1275",
                    bytes_received: "5353",
                  },
                  {
                    destination_name: "stats.grafana.org",
                    destination_port: "443",
                    bytes_sent: "8845",
                    bytes_received: "4847",
                  },
                ],
              },
              {
                name: "/var/lib/grafana/plugins/grafana-clickhouse-datasource/gpx_clickhouse_linux_amd64",
              },
              {
                name: "/var/lib/grafana/plugins/isovalent-hubble-datasource/gpx_hubble_linux_amd64",
              },
            ],
          },
          {
            name: "prometheus-kube-state-metrics",
            kind: "Deployment",
            processes: [
              {
                name: "/kube-state-metrics",
                arguments:
                  "--port=8080\u0000--telemetry-port=8081\u0000--port=8080\u0000--resources=certificatesigningrequests,configmaps,cronjobs,daemonsets,deployments,endpoints,horizontalpodautoscalers,ingresses,jobs,leases,limitranges,mutatingwebhookconf",
                connections: [
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "1205270",
                    bytes_received: "33238063",
                  },
                ],
              },
            ],
          },
          {
            name: "alertmanager-prometheus-kube-prometheus-alertmanager",
            kind: "StatefulSet",
            processes: [
              {
                name: "/bin/alertmanager",
                arguments: "--config.file=/etc",
              },
              {
                name: "/bin/prometheus-config-reloader",
                arguments:
                  "--listen-address=:8080\u0000--reload-url=http://127.0.0.1:9093/-/reload\u0000--config-file=/etc/alertmanager/config/alertmanager.yaml.gz\u0000--config-envsubst-file=/etc/alertmanager/config_out/alertmanager.env.yaml\u0000--watched-dir=/etc/alertmanager/config",
                connections: [
                  {
                    destination_name: "127.0.0.1",
                    destination_port: "9093",
                    bytes_sent: "984",
                    bytes_received: "795",
                  },
                ],
              },
              {
                name: "/bin/prometheus-config-reloader",
                arguments:
                  "--watch-interval=0\u0000--listen-address=:8081\u0000--config-file=/etc/alertmanager/config/alertmanager.yaml.gz\u0000--config-envsubst-file=/etc/alertmanager/config_out/alertmanager.env.yaml\u0000--watched-dir=/etc/alertmanager/config",
              },
            ],
          },
          {
            name: "prometheus-prometheus-kube-prometheus-prometheus",
            kind: "StatefulSet",
            processes: [
              {
                name: "/bin/prometheus",
                arguments: "--web.c",
                connections: [
                  {
                    destination_name: "10.3.6.8",
                    destination_port: "443",
                    bytes_sent: "613678",
                    bytes_received: "19320077",
                  },
                  {
                    destination_name: "10.3.7.177",
                    destination_port: "443",
                    bytes_sent: "606440",
                    bytes_received: "18940507",
                  },
                  {
                    destination_name:
                      "3BE81FD965B44E29EE37641B4D0F95CD.gr7.us-west-2.eks.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "12585998",
                    bytes_received: "389869864",
                  },
                  {
                    destination_name: "alloy/Deployment:alloy",
                    destination_port: "12345",
                    bytes_sent: "30024",
                    bytes_received: "310505",
                  },
                  {
                    destination_name:
                      "argocd/Deployment:argo-cd-argocd-applicationset-controller",
                    destination_port: "8080",
                    bytes_sent: "17026",
                    bytes_received: "109174",
                  },
                  {
                    destination_name:
                      "argocd/Deployment:argo-cd-argocd-notifications-controller",
                    destination_port: "9001",
                    bytes_sent: "25796",
                    bytes_received: "142755",
                  },
                  {
                    destination_name:
                      "argocd/Deployment:argo-cd-argocd-repo-server",
                    destination_port: "8084",
                    bytes_sent: "15246",
                    bytes_received: "93643",
                  },
                  {
                    destination_name:
                      "argocd/StatefulSet:argo-cd-argocd-application-controller",
                    destination_port: "8082",
                    bytes_sent: "16866",
                    bytes_received: "170343",
                  },
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "430172",
                    bytes_received: "13303949",
                  },
                  {
                    destination_name:
                      "ingress-nginx/Deployment:ingress-nginx-controller",
                    destination_port: "10254",
                    bytes_sent: "36716",
                    bytes_received: "417142",
                  },
                  {
                    destination_name:
                      "ip-10-3-6-166.us-west-2.compute.internal",
                    destination_port: "2112",
                    bytes_sent: "161737",
                    bytes_received: "7311225",
                  },
                  {
                    destination_name:
                      "ip-10-3-6-166.us-west-2.compute.internal",
                    destination_port: "9100",
                    bytes_sent: "183270",
                    bytes_received: "5547758",
                  },
                  {
                    destination_name:
                      "ip-10-3-6-166.us-west-2.compute.internal",
                    destination_port: "9962",
                    bytes_sent: "120886",
                    bytes_received: "3580062",
                  },
                  {
                    destination_name:
                      "ip-10-3-6-166.us-west-2.compute.internal",
                    destination_port: "9965",
                    bytes_sent: "212808",
                    bytes_received: "3032795",
                  },
                  {
                    destination_name:
                      "ip-10-3-6-166.us-west-2.compute.internal",
                    destination_port: "10249",
                    bytes_sent: "259380",
                    bytes_received: "1758774",
                  },
                  {
                    destination_name:
                      "ip-10-3-6-166.us-west-2.compute.internal",
                    destination_port: "10250",
                    bytes_sent: "1003722",
                    bytes_received: "32326263",
                  },
                  {
                    destination_name: "ip-10-3-6-44.us-west-2.compute.internal",
                    destination_port: "2112",
                    bytes_sent: "2334",
                    bytes_received: "92079",
                  },
                  {
                    destination_name: "ip-10-3-6-44.us-west-2.compute.internal",
                    destination_port: "9100",
                    bytes_sent: "662",
                    bytes_received: "15893",
                  },
                  {
                    destination_name: "ip-10-3-6-44.us-west-2.compute.internal",
                    destination_port: "9962",
                    bytes_sent: "1212",
                    bytes_received: "33049",
                  },
                  {
                    destination_name: "ip-10-3-6-44.us-west-2.compute.internal",
                    destination_port: "9965",
                    bytes_sent: "1004",
                    bytes_received: "9865",
                  },
                  {
                    destination_name: "ip-10-3-6-44.us-west-2.compute.internal",
                    destination_port: "10249",
                    bytes_sent: "3976",
                    bytes_received: "26287",
                  },
                  {
                    destination_name: "ip-10-3-6-44.us-west-2.compute.internal",
                    destination_port: "10250",
                    bytes_sent: "10680",
                    bytes_received: "148563",
                  },
                  {
                    destination_name: "karpenter/Deployment:karpenter",
                    destination_port: "8080",
                    bytes_sent: "131117",
                    bytes_received: "7691905",
                  },
                  {
                    destination_name: "kube-system/DaemonSet:cilium",
                    destination_port: "2112",
                    bytes_sent: "59420",
                    bytes_received: "2498529",
                  },
                  {
                    destination_name: "kube-system/DaemonSet:cilium",
                    destination_port: "9962",
                    bytes_sent: "48826",
                    bytes_received: "1416108",
                  },
                  {
                    destination_name: "kube-system/DaemonSet:cilium",
                    destination_port: "9965",
                    bytes_sent: "420",
                    bytes_received: "280",
                  },
                  {
                    destination_name: "kube-system/DaemonSet:cilium",
                    destination_port: "10249",
                    bytes_sent: "110358",
                    bytes_received: "747249",
                  },
                  {
                    destination_name: "kube-system/DaemonSet:cilium-node-init",
                    destination_port: "2112",
                    bytes_sent: "118093",
                    bytes_received: "6070774",
                  },
                  {
                    destination_name: "kube-system/DaemonSet:cilium-node-init",
                    destination_port: "9962",
                    bytes_sent: "80049",
                    bytes_received: "2314513",
                  },
                  {
                    destination_name: "kube-system/DaemonSet:cilium-node-init",
                    destination_port: "9965",
                    bytes_sent: "1140",
                    bytes_received: "760",
                  },
                  {
                    destination_name: "kube-system/DaemonSet:cilium-node-init",
                    destination_port: "10249",
                    bytes_sent: "188062",
                    bytes_received: "1271133",
                  },
                  {
                    destination_name: "kube-system/DaemonSet:kube-proxy",
                    destination_port: "2112",
                    bytes_sent: "60",
                    bytes_received: "40",
                  },
                  {
                    destination_name: "kube-system/DaemonSet:kube-proxy",
                    destination_port: "9962",
                    bytes_sent: "120",
                    bytes_received: "80",
                  },
                  {
                    destination_name: "kube-system/DaemonSet:kube-proxy",
                    destination_port: "9965",
                    bytes_sent: "60",
                    bytes_received: "40",
                  },
                  {
                    destination_name: "kube-system/DaemonSet:kube-proxy",
                    destination_port: "10249",
                    bytes_sent: "60",
                    bytes_received: "40",
                  },
                  {
                    destination_name: "kube-system/Deployment:coredns",
                    destination_port: "9153",
                    bytes_sent: "231940",
                    bytes_received: "485553",
                  },
                  {
                    destination_name:
                      "kubeshark/DaemonSet:kubeshark-worker-daemon-set",
                    destination_port: "2112",
                    bytes_sent: "60",
                    bytes_received: "40",
                  },
                  {
                    destination_name:
                      "kubeshark/DaemonSet:kubeshark-worker-daemon-set",
                    destination_port: "9962",
                    bytes_sent: "60",
                    bytes_received: "40",
                  },
                  {
                    destination_name:
                      "kubeshark/DaemonSet:kubeshark-worker-daemon-set",
                    destination_port: "9965",
                    bytes_sent: "60",
                    bytes_received: "40",
                  },
                  {
                    destination_name:
                      "kubeshark/DaemonSet:kubeshark-worker-daemon-set",
                    destination_port: "10249",
                    bytes_sent: "2045",
                    bytes_received: "13075",
                  },
                  {
                    destination_name: "logging/DaemonSet:promtail",
                    destination_port: "3101",
                    bytes_sent: "342848",
                    bytes_received: "7067874",
                  },
                  {
                    destination_name: "logging/Deployment:loki-compactor",
                    destination_port: "3100",
                    bytes_sent: "29213",
                    bytes_received: "629341",
                  },
                  {
                    destination_name: "logging/Deployment:loki-distributor",
                    destination_port: "3100",
                    bytes_sent: "33709",
                    bytes_received: "799967",
                  },
                  {
                    destination_name: "logging/Deployment:loki-query-frontend",
                    destination_port: "3100",
                    bytes_sent: "66066",
                    bytes_received: "1370480",
                  },
                  {
                    destination_name: "logging/StatefulSet:loki-ingester",
                    destination_port: "3100",
                    bytes_sent: "40892",
                    bytes_received: "1155901",
                  },
                  {
                    destination_name:
                      "logging/StatefulSet:loki-memcached-chunks",
                    destination_port: "9150",
                    bytes_sent: "52048",
                    bytes_received: "655591",
                  },
                  {
                    destination_name:
                      "logging/StatefulSet:loki-memcached-frontend",
                    destination_port: "9150",
                    bytes_sent: "23186",
                    bytes_received: "164930",
                  },
                  {
                    destination_name: "logging/StatefulSet:loki-querier",
                    destination_port: "3100",
                    bytes_sent: "62711",
                    bytes_received: "1416741",
                  },
                  {
                    destination_name:
                      "monitoring/DaemonSet:prometheus-prometheus-node-exporter",
                    destination_port: "2112",
                    bytes_sent: "818",
                    bytes_received: "27516",
                  },
                  {
                    destination_name:
                      "monitoring/DaemonSet:prometheus-prometheus-node-exporter",
                    destination_port: "9962",
                    bytes_sent: "662",
                    bytes_received: "16548",
                  },
                  {
                    destination_name:
                      "monitoring/DaemonSet:prometheus-prometheus-node-exporter",
                    destination_port: "9965",
                    bytes_sent: "558",
                    bytes_received: "4383",
                  },
                  {
                    destination_name:
                      "monitoring/DaemonSet:prometheus-prometheus-node-exporter",
                    destination_port: "10249",
                    bytes_sent: "2044",
                    bytes_received: "13199",
                  },
                  {
                    destination_name:
                      "monitoring/DaemonSet:prometheus-prometheus-node-exporter",
                    destination_port: "10250",
                    bytes_sent: "3816",
                    bytes_received: "59410",
                  },
                  {
                    destination_name:
                      "monitoring/Deployment:prometheus-kube-prometheus-operator",
                    destination_port: "10250",
                    bytes_sent: "31592",
                    bytes_received: "431314",
                  },
                  {
                    destination_name:
                      "monitoring/Deployment:prometheus-kube-state-metrics",
                    destination_port: "8080",
                    bytes_sent: "2045368",
                    bytes_received: "201665851",
                  },
                  {
                    destination_name:
                      "monitoring/StatefulSet:alertmanager-prometheus-kube-prometheus-alertmanager",
                    destination_port: "8080",
                    bytes_sent: "26629",
                    bytes_received: "180138",
                  },
                  {
                    destination_name:
                      "monitoring/StatefulSet:alertmanager-prometheus-kube-prometheus-alertmanager",
                    destination_port: "9093",
                    bytes_sent: "227461",
                    bytes_received: "357090",
                  },
                  {
                    destination_name:
                      "monitoring/StatefulSet:prometheus-prometheus-kube-prometheus-prometheus",
                    destination_port: "8080",
                    bytes_sent: "26972",
                    bytes_received: "180530",
                  },
                  {
                    destination_name:
                      "monitoring/StatefulSet:prometheus-prometheus-kube-prometheus-prometheus",
                    destination_port: "9090",
                    bytes_sent: "47200",
                    bytes_received: "1687782",
                  },
                  {
                    destination_name: "otel-collector/DaemonSet:otel-collector",
                    destination_port: "2112",
                    bytes_sent: "47323",
                    bytes_received: "2614192",
                  },
                  {
                    destination_name: "otel-collector/DaemonSet:otel-collector",
                    destination_port: "9962",
                    bytes_sent: "35201",
                    bytes_received: "1014834",
                  },
                  {
                    destination_name: "otel-collector/DaemonSet:otel-collector",
                    destination_port: "9965",
                    bytes_sent: "300",
                    bytes_received: "200",
                  },
                  {
                    destination_name: "otel-collector/DaemonSet:otel-collector",
                    destination_port: "10249",
                    bytes_sent: "81340",
                    bytes_received: "549935",
                  },
                  {
                    destination_name: "otel-collector/DaemonSet:otel-collector",
                    destination_port: "10250",
                    bytes_sent: "154497",
                    bytes_received: "4853735",
                  },
                  {
                    destination_name:
                      "otel-collector/Deployment:opentelemetry-operator",
                    destination_port: "8080",
                    bytes_sent: "30492",
                    bytes_received: "292666",
                  },
                  {
                    destination_name:
                      "otel-collector/Deployment:opentelemetry-operator",
                    destination_port: "8443",
                    bytes_sent: "23912",
                    bytes_received: "296403",
                  },
                  {
                    destination_name:
                      "tetragon-tracing-demo/Pod:tls-weak-version",
                    destination_port: "9100",
                    bytes_sent: "715",
                    bytes_received: "17502",
                  },
                  {
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "2112",
                    bytes_sent: "608886",
                    bytes_received: "37651200",
                  },
                  {
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "9100",
                    bytes_sent: "229697",
                    bytes_received: "7073854",
                  },
                  {
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "9962",
                    bytes_sent: "348094",
                    bytes_received: "9593294",
                  },
                  {
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "9963",
                    bytes_sent: "90863",
                    bytes_received: "1151052",
                  },
                  {
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "9965",
                    bytes_sent: "332803",
                    bytes_received: "8334867",
                  },
                  {
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "10249",
                    bytes_sent: "672763",
                    bytes_received: "4568601",
                  },
                  {
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "10250",
                    bytes_sent: "2378352",
                    bytes_received: "80458009",
                  },
                  {
                    destination_name: "tetragon/Deployment:tetragon-operator",
                    destination_port: "2113",
                    bytes_sent: "39906",
                    bytes_received: "350059",
                  },
                ],
              },
              {
                name: "/bin/prometheus-config-reloader",
                arguments: "--listen-address=:8080\u0000--reload-ur",
                connections: [
                  {
                    destination_name: "127.0.0.1",
                    destination_port: "9090",
                    bytes_sent: "880",
                    bytes_received: "618",
                  },
                ],
              },
              {
                name: "/bin/prometheus-config-reloader",
                arguments: "--watch-i",
              },
            ],
          },
        ],
      },
      {
        name: "otel-collector",
        workloads: [
          {
            name: "otel-collector",
            kind: "DaemonSet",
            processes: [
              {
                name: "/otelcol-contrib",
                connections: [
                  {
                    destination_name: "10.3.5.195",
                    destination_port: "2112",
                    bytes_sent: "1827",
                    bytes_received: "56450",
                  },
                  {
                    destination_name: "10.3.5.215",
                    destination_port: "2112",
                    bytes_sent: "1827",
                    bytes_received: "56821",
                  },
                  {
                    destination_name: "10.3.5.231",
                    destination_port: "2112",
                    bytes_sent: "88258",
                    bytes_received: "3947300",
                  },
                  {
                    destination_name: "10.3.6.166",
                    destination_port: "2112",
                    bytes_sent: "36126",
                    bytes_received: "1468563",
                  },
                  {
                    destination_name: "10.3.6.166",
                    destination_port: "10250",
                    bytes_sent: "26331",
                    bytes_received: "906136",
                  },
                  {
                    destination_name: "10.3.6.198",
                    destination_port: "2112",
                    bytes_sent: "11913",
                    bytes_received: "441462",
                  },
                  {
                    destination_name: "10.3.6.44",
                    destination_port: "2112",
                    bytes_sent: "1824",
                    bytes_received: "51847",
                  },
                  {
                    destination_name: "10.3.6.99",
                    destination_port: "2112",
                    bytes_sent: "1824",
                    bytes_received: "57420",
                  },
                  {
                    destination_name: "10.3.8.128",
                    destination_port: "2112",
                    bytes_sent: "1218",
                    bytes_received: "35557",
                  },
                  {
                    destination_name: "10.3.8.154",
                    destination_port: "2112",
                    bytes_sent: "1218",
                    bytes_received: "36157",
                  },
                  {
                    destination_name: "10.3.8.154",
                    destination_port: "10250",
                    bytes_sent: "104",
                  },
                  {
                    destination_name: "10.3.8.80",
                    destination_port: "2112",
                    bytes_sent: "1164",
                    bytes_received: "33218",
                  },
                  {
                    destination_name: "172.20.170.76",
                    destination_port: "80",
                    bytes_sent: "11280",
                    bytes_received: "107440",
                  },
                  {
                    destination_name: "35.190.55.74",
                    destination_port: "443",
                    bytes_sent: "10936831",
                    bytes_received: "962888",
                  },
                  {
                    destination_name:
                      "ip-10-3-5-215.us-west-2.compute.internal",
                    destination_port: "10250",
                    bytes_sent: "13767",
                    bytes_received: "410715",
                  },
                  {
                    destination_name:
                      "ip-10-3-5-231.us-west-2.compute.internal",
                    destination_port: "10250",
                    bytes_sent: "75047",
                    bytes_received: "2579019",
                  },
                  {
                    destination_name:
                      "ip-10-3-6-166.us-west-2.compute.internal",
                    destination_port: "2112",
                    bytes_sent: "49949",
                    bytes_received: "2191637",
                  },
                  {
                    destination_name:
                      "ip-10-3-6-166.us-west-2.compute.internal",
                    destination_port: "10250",
                    bytes_sent: "36814",
                    bytes_received: "1185063",
                  },
                  {
                    destination_name:
                      "ip-10-3-6-198.us-west-2.compute.internal",
                    destination_port: "2112",
                    bytes_sent: "46777",
                    bytes_received: "1940083",
                  },
                  {
                    destination_name:
                      "ip-10-3-6-198.us-west-2.compute.internal",
                    destination_port: "10250",
                    bytes_sent: "50780",
                    bytes_received: "1539952",
                  },
                  {
                    destination_name: "ip-10-3-6-44.us-west-2.compute.internal",
                    destination_port: "10250",
                    bytes_sent: "3596",
                    bytes_received: "60121",
                  },
                  {
                    destination_name: "ip-10-3-6-99.us-west-2.compute.internal",
                    destination_port: "2112",
                  },
                  {
                    destination_name: "ip-10-3-6-99.us-west-2.compute.internal",
                    destination_port: "10250",
                    bytes_sent: "3196",
                    bytes_received: "40322",
                  },
                  {
                    destination_name:
                      "ip-10-3-8-128.us-west-2.compute.internal",
                    destination_port: "10250",
                    bytes_sent: "4903",
                    bytes_received: "105917",
                  },
                  {
                    destination_name:
                      "ip-10-3-8-154.us-west-2.compute.internal",
                    destination_port: "2112",
                  },
                  {
                    destination_name:
                      "ip-10-3-8-154.us-west-2.compute.internal",
                    destination_port: "10250",
                  },
                  {
                    destination_name: "ip-10-3-8-80.us-west-2.compute.internal",
                    destination_port: "10250",
                    bytes_sent: "5446",
                    bytes_received: "128462",
                  },
                  {
                    destination_name:
                      "monitoring/DaemonSet:prometheus-prometheus-node-exporter",
                    destination_port: "2112",
                    bytes_sent: "4791",
                    bytes_received: "163612",
                  },
                  {
                    destination_name:
                      "monitoring/DaemonSet:prometheus-prometheus-node-exporter",
                    destination_port: "10250",
                    bytes_sent: "3640",
                    bytes_received: "62350",
                  },
                  {
                    destination_name:
                      "monitoring/Deployment:prometheus-kube-state-metrics",
                    destination_port: "8080",
                    bytes_sent: "856852",
                    bytes_received: "95897021",
                  },
                  {
                    destination_name:
                      "otel-collector/Service:otel-targetallocator",
                    destination_port: "80",
                  },
                  {
                    destination_name:
                      "otel-targetallocator.otel-collector.svc.cluster.local",
                    destination_port: "80",
                    bytes_sent: "54688",
                    bytes_received: "459755",
                  },
                  {
                    destination_name:
                      "otlp-gateway-prod-us-central-0.grafana.net",
                    destination_port: "443",
                    bytes_sent: "5324",
                    bytes_received: "5311",
                  },
                  {
                    destination_name: "tempo-gateway.tempo.svc.cluster.local",
                    destination_port: "80",
                    bytes_sent: "3227",
                    bytes_received: "325",
                  },
                  {
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "2112",
                  },
                  {
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "10250",
                  },
                ],
              },
            ],
          },
        ],
      },
      {
        name: "otel-demo",
        workloads: [
          {
            name: "elasticsearch",
            kind: "Deployment",
            processes: [
              {
                name: "/usr/bin/dirname",
                arguments: "/usr/share/elasticsearch/bin/elasticsearch",
              },
              {
                name: "/usr/bin/dirname",
                arguments: "bin/elasticsearch-plugin",
              },
              {
                name: "/usr/bin/grep",
                arguments:
                  "^-\u0000/usr/share/elasticsearch/config/jvm.options",
              },
              { name: "/usr/bin/id", arguments: "-u" },
            ],
          },
          {
            name: "otel-demo-accountingservice",
            kind: "Deployment",
            processes: [
              {
                name: "/usr/bin/dash",
                arguments:
                  "./instrument.sh\u0000dotnet\u0000AccountingService.dll",
              },
              { name: "/usr/bin/dirname", arguments: "./instrument.sh" },
              {
                name: "/usr/bin/ls",
                arguments: "/app/OpenTelemetry.AutoInstrumentation.Native.so",
              },
              {
                name: "/usr/share/dotnet/dotnet",
                arguments: "AccountingService.dll",
                connections: [
                  {
                    destination_name: "10.3.6.179",
                    destination_port: "4317",
                    bytes_sent: "26403926",
                    bytes_received: "264309725",
                  },
                  {
                    destination_name:
                      "otel-demo-kafka.otel-demo.svc.cluster.local",
                    destination_port: "9092",
                    bytes_sent: "28891621",
                    bytes_received: "31865129",
                  },
                ],
              },
            ],
          },
          {
            name: "otel-demo-checkoutservice",
            kind: "Deployment",
            processes: [
              {
                name: "/bin/nc",
                arguments:
                  "-z\u0000-v\u0000-w30\u0000otel-demo-kafka\u00009092",
                connections: [
                  {
                    destination_name:
                      "otel-demo-kafka.otel-demo.svc.cluster.local",
                    destination_port: "9092",
                    bytes_sent: "2744",
                    bytes_received: "1192",
                  },
                ],
              },
              {
                name: "/bin/sh",
                arguments:
                  "-c\u0000until nc -z -v -w30 otel-demo-kafka 9092; do echo waiting for kafka; sleep 2; done;",
              },
              { name: "/bin/sleep", arguments: "2" },
              {
                name: "/usr/src/app/checkoutservice",
                connections: [
                  {
                    destination_name:
                      "ip-10-3-6-179.us-west-2.compute.internal",
                    destination_port: "4317",
                    bytes_sent: "56879050",
                    bytes_received: "1466648",
                  },
                  {
                    destination_name:
                      "otel-demo-cartservice.otel-demo.svc.cluster.local",
                    destination_port: "8080",
                    bytes_sent: "3046204",
                    bytes_received: "1931513",
                  },
                  {
                    destination_name:
                      "otel-demo-currencyservice.otel-demo.svc.cluster.local",
                    destination_port: "8080",
                    bytes_sent: "3946900",
                    bytes_received: "3090296",
                  },
                  {
                    destination_name:
                      "otel-demo-emailservice.otel-demo.svc.cluster.local",
                    destination_port: "8080",
                    bytes_sent: "5076348",
                    bytes_received: "1566784",
                  },
                  {
                    destination_name:
                      "otel-demo-flagd.otel-demo.svc.cluster.local",
                    destination_port: "8013",
                    bytes_sent: "4360725",
                    bytes_received: "3491570",
                  },
                  {
                    destination_name:
                      "otel-demo-kafka.otel-demo.svc.cluster.local",
                    destination_port: "9092",
                    bytes_sent: "2615553",
                    bytes_received: "590881",
                  },
                  {
                    destination_name:
                      "otel-demo-paymentservice.otel-demo.svc.cluster.local",
                    destination_port: "8080",
                    bytes_sent: "1910349",
                    bytes_received: "1268207",
                  },
                  {
                    destination_name:
                      "otel-demo-productcatalogservice.otel-demo.svc.cluster.local",
                    destination_port: "8080",
                    bytes_sent: "3105459",
                    bytes_received: "6433947",
                  },
                  {
                    destination_name:
                      "otel-demo-shippingservice.otel-demo.svc.cluster.local",
                    destination_port: "8080",
                    bytes_sent: "3352045",
                    bytes_received: "1806199",
                  },
                ],
              },
            ],
          },
          {
            name: "otel-demo-emailservice",
            kind: "Deployment",
            processes: [
              {
                name: "/usr/bin/env",
                arguments:
                  "ruby\u0000/usr/local/bundle/bin/bundle\u0000exec\u0000ruby\u0000email_server.rb",
              },
              {
                name: "/usr/local/bin/ruby",
                arguments:
                  "/usr/local/bundle/bin/bundle\u0000exec\u0000ruby\u0000email_server.rb",
              },
              {
                name: "/usr/local/bin/ruby",
                arguments: "email_server.rb",
                connections: [
                  {
                    destination_name:
                      "ip-10-3-6-179.us-west-2.compute.internal",
                    destination_port: "4318",
                    bytes_sent: "5422375",
                    bytes_received: "1158795",
                  },
                ],
              },
            ],
          },
          {
            name: "otel-demo-flagd",
            kind: "Deployment",
            processes: [
              {
                name: "/bin/busybox",
                arguments: "-c\u0000next start -p 4000 -H 0.0.0.0",
              },
              {
                name: "/bin/busybox",
                arguments:
                  "/usr/local/bin/docker-entrypoint.sh\u0000npm\u0000start",
              },
              {
                name: "/bin/busybox",
                arguments:
                  "node\u0000/app/node_modules/.bin/next\u0000start\u0000-p\u00004000\u0000-H\u00000.0.0.0",
              },
              {
                name: "/bin/busybox",
                arguments: "node\u0000/usr/local/bin/npm\u0000start",
              },
              { name: "/bin/cat", arguments: "/config-rw/demo.flagd.json" },
              {
                name: "/bin/cp",
                arguments:
                  "/config-ro/demo.flagd.json\u0000/config-rw/demo.flagd.json",
              },
              {
                name: "/bin/sh",
                arguments:
                  "-c\u0000cp /config-ro/demo.flagd.json /config-rw/demo.flagd.json && cat /config-rw/demo.flagd.json",
              },
              {
                name: "/flagd-build",
                arguments:
                  "start\u0000--uri\u0000file:./etc/flagd/demo.flagd.json",
                connections: [
                  {
                    destination_name:
                      "ip-10-3-8-128.us-west-2.compute.internal",
                    destination_port: "4317",
                    bytes_sent: "510334",
                    bytes_received: "15105",
                  },
                  {
                    destination_name: "ip-10-3-8-80.us-west-2.compute.internal",
                    destination_port: "4317",
                    bytes_sent: "73905",
                    bytes_received: "3949",
                  },
                  {
                    destination_name:
                      "monitoring/DaemonSet:prometheus-prometheus-node-exporter",
                    destination_port: "4317",
                    bytes_sent: "3646",
                    bytes_received: "1290",
                  },
                ],
              },
              {
                name: "/usr/local/bin/node",
                arguments:
                  "/app/node_modules/.bin/next\u0000start\u0000-p\u00004000\u0000-H\u00000.0.0.0",
              },
              {
                name: "/usr/local/bin/node",
                arguments: "/usr/local/bin/npm\u0000start",
                connections: [
                  {
                    destination_name: "registry.npmjs.org",
                    destination_port: "443",
                    bytes_sent: "2800",
                    bytes_received: "294071",
                  },
                ],
              },
            ],
          },
          {
            name: "otel-demo-imageprovider",
            kind: "Deployment",
            processes: [
              { name: "/usr/bin/cat", arguments: "/etc/nginx/nginx.conf" },
              {
                name: "/usr/bin/dash",
                arguments:
                  "-c\u0000envsubst '$OTEL_COLLECTOR_HOST $IMAGE_PROVIDER_PORT $OTEL_COLLECTOR_PORT_GRPC $OTEL_SERVICE_NAME' < /nginx.conf.template > /etc/nginx/nginx.conf && cat  /etc/nginx/nginx.conf && exec nginx -g 'daemon off;'",
              },
              {
                name: "/usr/bin/dash",
                arguments:
                  "/docker-entrypoint.sh\u0000/bin/sh\u0000-c\u0000envsubst '$OTEL_COLLECTOR_HOST $IMAGE_PROVIDER_PORT $OTEL_COLLECTOR_PORT_GRPC $OTEL_SERVICE_NAME' < /nginx.conf.template > /etc/nginx/nginx.conf && cat  /etc/nginx/nginx.conf && exec nginx -g 'daemon off;'",
              },
              {
                name: "/usr/bin/envsubst",
                arguments:
                  "$OTEL_COLLECTOR_HOST $IMAGE_PROVIDER_PORT $OTEL_COLLECTOR_PORT_GRPC $OTEL_SERVICE_NAME",
              },
              { name: "/usr/sbin/nginx", arguments: "-g\u0000daemon off;" },
            ],
          },
          {
            name: "otel-demo-kafka",
            kind: "Deployment",
            processes: [
              { name: "/bin/bash", arguments: "/etc/kafka/docker/run" },
              {
                name: "/bin/bash",
                arguments:
                  "/opt/kafka/bin/kafka-run-class.sh\u0000-name\u0000kafkaServer\u0000-loggc\u0000kafka.Kafka\u0000/opt/kafka/config/server.properties",
              },
              {
                name: "/bin/bash",
                arguments:
                  "/opt/kafka/bin/kafka-run-class.sh\u0000kafka.docker.KafkaDockerWrapper\u0000setup\u0000--default-configs-dir\u0000/etc/kafka/docker\u0000--mounted-configs-dir\u0000/mnt/shared/config\u0000--final-configs-dir\u0000/opt/kafka/config",
              },
              {
                name: "/bin/bash",
                arguments:
                  "/opt/kafka/bin/kafka-server-start.sh\u0000/opt/kafka/config/server.properties",
              },
              { name: "/bin/busybox" },
              {
                name: "/bin/busybox",
                arguments:
                  "-E\u0000(-(test|test-sources|src|scaladoc|javadoc)\\.jar|jar.asc|connect-file.*\\.jar)$",
              },
              {
                name: "/bin/busybox",
                arguments: '-E\u0000-n\u0000s/.* version "([0-9]*).*$/\\1/p',
              },
              { name: "/bin/busybox", arguments: "-a" },
              { name: "/bin/busybox", arguments: "-d \u0000-f1" },
              {
                name: "/bin/busybox",
                arguments: "-f\u00001-2\u0000-d\u0000.",
              },
              { name: "/bin/busybox", arguments: "-i" },
              {
                name: "/bin/busybox",
                arguments: "-p\u0000/opt/kafka/bin/../logs",
              },
              {
                name: "/bin/busybox",
                arguments: "/__cacert_entrypoint.sh\u0000/etc/kafka/docker/run",
              },
              {
                name: "/bin/busybox",
                arguments: "/opt/kafka/bin/kafka-run-class.sh",
              },
              {
                name: "/bin/busybox",
                arguments: "/opt/kafka/bin/kafka-server-start.sh",
              },
              {
                name: "/bin/busybox",
                arguments: "bash\u0000/etc/kafka/docker/run",
              },
              {
                name: "/bin/busybox",
                arguments:
                  "sh\u0000/__cacert_entrypoint.sh\u0000/etc/kafka/docker/run",
              },
              {
                name: "/opt/java/openjdk/bin/java",
                connections: [
                  {
                    destination_name: "10.3.6.179",
                    destination_port: "4318",
                    bytes_sent: "40530647",
                    bytes_received: "2784148",
                  },
                  {
                    destination_name: "127.0.0.1",
                    destination_port: "9093",
                    bytes_sent: "5328503",
                    bytes_received: "2651730",
                  },
                ],
              },
              { name: "/opt/java/openjdk/bin/java", arguments: "-version" },
            ],
          },
          {
            name: "otel-demo-loadgenerator",
            kind: "Deployment",
            processes: [
              {
                name: "/opt/pw-browsers/chromium-1091/chrome-linux/chrome",
                connections: [
                  {
                    destination_name: "127.0.0.1",
                    destination_port: "8080",
                    bytes_sent: "720",
                    bytes_received: "480",
                  },
                  {
                    destination_name: "::1",
                    destination_port: "8080",
                    bytes_sent: "960",
                  },
                  {
                    destination_name: "fonts.gstatic.com",
                    destination_port: "443",
                    bytes_sent: "28724",
                    bytes_received: "611561",
                  },
                  {
                    destination_name:
                      "ip-10-3-6-179.us-west-2.compute.internal",
                    destination_port: "4318",
                    bytes_sent: "531042",
                    bytes_received: "8347",
                  },
                  {
                    destination_name:
                      "otel-demo-frontendproxy.otel-demo.svc.cluster.local",
                    destination_port: "8080",
                    bytes_sent: "262756",
                    bytes_received: "12821893",
                  },
                ],
              },
              {
                name: "/opt/pw-browsers/chromium-1091/chrome-linux/chrome",
                arguments:
                  "--type=gpu-process\u0000--no-sandbox\u0000--disable-dev-shm-usage\u0000--disable-breakpad\u0000--disable-logging\u0000--headless",
              },
              {
                name: "/opt/pw-browsers/chromium-1091/chrome-linux/chrome",
                arguments:
                  "--type=gpu-process\u0000--no-sandbox\u0000--disable-dev-shm-usage\u0000--disable-breakpad\u0000--disable-logging\u0000--headless\u0000-",
              },
              {
                name: "/usr/bin/bash",
                arguments:
                  "/usr/bin/ldd\u0000/opt/pw-browsers/chromium-1091/chrome-linux/chrome",
              },
              {
                name: "/usr/bin/bash",
                arguments:
                  "/usr/bin/ldd\u0000/opt/pw-browsers/chromium-1091/chrome-linux/chrome-wrapper",
              },
              {
                name: "/usr/bin/bash",
                arguments:
                  "/usr/bin/ldd\u0000/opt/pw-browsers/chromium-1091/chrome-linux/chrome_crashpad_handler",
              },
              {
                name: "/usr/bin/bash",
                arguments:
                  "/usr/bin/ldd\u0000/opt/pw-browsers/chromium-1091/chrome-linux/chrome_sandbox",
              },
              {
                name: "/usr/bin/bash",
                arguments:
                  "/usr/bin/ldd\u0000/opt/pw-browsers/chromium-1091/chrome-linux/libEGL.so",
              },
              {
                name: "/usr/bin/bash",
                arguments:
                  "/usr/bin/ldd\u0000/opt/pw-browsers/chromium-1091/chrome-linux/libGLESv2.so",
              },
              {
                name: "/usr/bin/bash",
                arguments:
                  "/usr/bin/ldd\u0000/opt/pw-browsers/chromium-1091/chrome-linux/libvk_swiftshader.so",
              },
              {
                name: "/usr/bin/bash",
                arguments:
                  "/usr/bin/ldd\u0000/opt/pw-browsers/chromium-1091/chrome-linux/libvulkan.so.1",
              },
              {
                name: "/usr/bin/bash",
                arguments:
                  "/usr/bin/ldd\u0000/opt/pw-browsers/chromium-1091/chrome-linux/xdg-mime",
              },
              {
                name: "/usr/bin/bash",
                arguments:
                  "/usr/bin/ldd\u0000/opt/pw-browsers/chromium-1091/chrome-linux/xdg-settings",
              },
              {
                name: "/usr/bin/dash",
                arguments:
                  "/usr/local/lib/python3.12/site-packages/playwright/driver/playwright.sh\u0000run-driver",
              },
              {
                name: "/usr/bin/dirname",
                arguments:
                  "/usr/local/lib/python3.12/site-packages/playwright/driver/playwright.sh",
              },
              {
                name: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                arguments:
                  "--verify\u0000/opt/pw-browsers/chromium-1091/chrome-linux/chrome",
              },
              {
                name: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                arguments:
                  "--verify\u0000/opt/pw-browsers/chromium-1091/chrome-linux/chrome-wrapper",
              },
              {
                name: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                arguments:
                  "--verify\u0000/opt/pw-browsers/chromium-1091/chrome-linux/chrome_crashpad_handler",
              },
              {
                name: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                arguments:
                  "--verify\u0000/opt/pw-browsers/chromium-1091/chrome-linux/chrome_sandbox",
              },
              {
                name: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                arguments:
                  "--verify\u0000/opt/pw-browsers/chromium-1091/chrome-linux/libEGL.so",
              },
              {
                name: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                arguments:
                  "--verify\u0000/opt/pw-browsers/chromium-1091/chrome-linux/libGLESv2.so",
              },
              {
                name: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                arguments:
                  "--verify\u0000/opt/pw-browsers/chromium-1091/chrome-linux/libvk_swiftshader.so",
              },
              {
                name: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                arguments:
                  "--verify\u0000/opt/pw-browsers/chromium-1091/chrome-linux/libvulkan.so.1",
              },
              {
                name: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                arguments:
                  "--verify\u0000/opt/pw-browsers/chromium-1091/chrome-linux/xdg-mime",
              },
              {
                name: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                arguments:
                  "--verify\u0000/opt/pw-browsers/chromium-1091/chrome-linux/xdg-settings",
              },
              {
                name: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                arguments: "--version",
              },
              {
                name: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                arguments: "/opt/pw-browsers/chromium-1091/chrome-linux/chrome",
              },
              {
                name: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                arguments:
                  "/opt/pw-browsers/chromium-1091/chrome-linux/chrome_crashpad_handler",
              },
              {
                name: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                arguments:
                  "/opt/pw-browsers/chromium-1091/chrome-linux/chrome_sandbox",
              },
              {
                name: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                arguments:
                  "/opt/pw-browsers/chromium-1091/chrome-linux/libEGL.so",
              },
              {
                name: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                arguments:
                  "/opt/pw-browsers/chromium-1091/chrome-linux/libGLESv2.so",
              },
              {
                name: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                arguments:
                  "/opt/pw-browsers/chromium-1091/chrome-linux/libvk_swiftshader.so",
              },
              {
                name: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                arguments:
                  "/opt/pw-browsers/chromium-1091/chrome-linux/libvulkan.so.1",
              },
              {
                name: "/usr/local/bin/python3.12",
                arguments: "/usr/local/bin/locust\u0000--skip-log-setup",
                connections: [
                  {
                    destination_name: "10.3.6.179",
                    destination_port: "4317",
                    bytes_sent: "54376481",
                    bytes_received: "6735801",
                  },
                  {
                    destination_name: "172.20.124.159",
                    destination_port: "8013",
                    bytes_sent: "4397570",
                    bytes_received: "3386598",
                  },
                  {
                    destination_name:
                      "otel-demo-frontendproxy.otel-demo.svc.cluster.local",
                    destination_port: "8080",
                    bytes_sent: "42453967",
                    bytes_received: "77618775",
                  },
                ],
              },
              {
                name: "/usr/local/lib/python3.12/site-packages/playwright/driver/node",
                arguments:
                  "/usr/local/lib/python3.12/site-packages/playwright/driver/package/lib/cli/cli.js\u0000run-driver",
              },
            ],
          },
          {
            name: "otel-demo-recommendationservice",
            kind: "Deployment",
            processes: [
              {
                name: "/usr/local/bin/python3.12",
                arguments:
                  "/usr/local/bin/opentelemetry-instrument\u0000python\u0000recommendation_server.py",
              },
              {
                name: "/usr/local/bin/python3.12",
                arguments: "recommendation_server.py",
                connections: [
                  {
                    destination_name: "10.3.6.179",
                    destination_port: "4317",
                    bytes_sent: "212894099",
                    bytes_received: "7246688",
                  },
                  {
                    destination_name: "172.20.124.159",
                    destination_port: "8013",
                    bytes_sent: "46962291",
                    bytes_received: "25819143",
                  },
                  {
                    destination_name: "172.20.237.99",
                    destination_port: "8080",
                    bytes_sent: "40751069",
                    bytes_received: "555895288",
                  },
                ],
              },
            ],
          },
          {
            name: "otel-demo-valkey",
            kind: "Deployment",
            processes: [
              { name: "/bin/busybox", arguments: "-u" },
              {
                name: "/bin/busybox",
                arguments:
                  "/usr/local/bin/docker-entrypoint.sh\u0000valkey-server",
              },
              { name: "/usr/local/bin/valkey-server" },
            ],
          },
          {
            name: "tomcat",
            kind: "Job",
            processes: [
              { name: "/usr/bin/bash" },
              {
                name: "/usr/bin/bash",
                arguments: "/usr/local/tomcat/bin/catalina.sh\u0000run",
              },
              {
                name: "/usr/bin/curl",
                arguments: "ebpf.io",
                connections: [
                  {
                    destination_name: "ebpf.io",
                    destination_port: "80",
                    bytes_sent: "391",
                    bytes_received: "1095",
                  },
                ],
              },
              {
                name: "/usr/bin/curl",
                arguments: "isovalent.com",
                connections: [
                  {
                    destination_name: "isovalent.com",
                    destination_port: "80",
                    bytes_sent: "397",
                    bytes_received: "481",
                  },
                ],
              },
              {
                name: "/usr/bin/dirname",
                arguments: "/usr/local/tomcat/bin/catalina.sh",
              },
              {
                name: "/usr/bin/env",
                arguments:
                  "bash\u0000/usr/local/tomcat/bin/catalina.sh\u0000run",
              },
              { name: "/usr/bin/uname" },
              {
                name: "/usr/lib/jvm/java-1.8.0-amazon-corretto/bin/java",
                arguments: "-Djava.util.logging.config.file=/usr/local/t",
                connections: [
                  {
                    destination_name: "::1",
                    destination_port: "8080",
                    bytes_sent: "224",
                  },
                ],
              },
            ],
          },
          {
            name: "kafka",
            kind: "StatefulSet",
            processes: [
              {
                name: "/bin/busybox",
                arguments: "(-(test|src|scaladoc|javadoc)\\.jar|jar.asc)$",
              },
              {
                name: "/bin/busybox",
                arguments: '-E\u0000-n\u0000s/.* version "([^.-]*).*"/\\1/p',
              },
              {
                name: "/usr/lib/jvm/java-1.8-openjdk/jre/bin/java",
                connections: [
                  {
                    destination_name: "10.3.5.175",
                    destination_port: "2181",
                    bytes_sent: "6818777",
                    bytes_received: "157660702",
                  },
                  {
                    destination_name: "10.3.6.140",
                    destination_port: "9092",
                    bytes_sent: "3108",
                    bytes_received: "970",
                  },
                ],
              },
              {
                name: "/usr/lib/jvm/java-1.8-openjdk/jre/bin/java",
                arguments: "-version",
              },
            ],
          },
          {
            name: "otel-demo-opensearch",
            kind: "StatefulSet",
            processes: [
              {
                name: "/usr/bin/bash",
                arguments:
                  "-c\u0000#!/usr/bin/env bash\ncp -r /tmp/configfolder/*  /tmp/config/\n",
              },
              {
                name: "/usr/bin/bash",
                arguments: "./opensearch-docker-entrypoint.sh\u0000opensearch",
              },
              {
                name: "/usr/bin/bash",
                arguments:
                  "/usr/share/opensearch/bin/opensearch\u0000-Ediscovery.seed_hosts=opensearch-",
              },
              {
                name: "/usr/bin/bash",
                arguments: "/usr/share/opensearch/bin/opensearch-cli",
              },
              {
                name: "/usr/bin/bash",
                arguments:
                  "/usr/share/opensearch/bin/opensearch-performance-analyzer/performance-analyzer-agent-cli",
              },
              {
                name: "/usr/bin/bash",
                arguments: "bin/opensearch-cli\u0000has-passwd\u0000--silent",
              },
              {
                name: "/usr/bin/bash",
                arguments:
                  "bin/opensearch-keystore\u0000has-passwd\u0000--silent",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=cp\u0000/usr/bin/cp\u0000-r\u0000/tmp/configfolder/opensearch.yml\u0000/tmp/config/",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=dirname\u0000/usr/bin/dirname\u0000/usr/share/opensearch/bin/opensearch",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=dirname\u0000/usr/bin/dirname\u0000/usr/share/opensearch/bin/opensearch-cli",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=dirname\u0000/usr/bin/dirname\u0000bin/opensearch-cli",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=dirname\u0000/usr/bin/dirname\u0000bin/opensearch-keystore",
              },
              {
                name: "/usr/bin/coreutils",
                arguments: "--coreutils-prog-shebang=env\u0000/usr/bin/env",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=env\u0000/usr/bin/env\u0000bash\u0000/usr/share/opensearch/bin/opensearch\u0000-Ediscovery.seed_hosts=opensearch-",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=env\u0000/usr/bin/env\u0000bash\u0000/usr/share/opensearch/bin/opensearch-cli",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=env\u0000/usr/bin/env\u0000bash\u0000bin/opensearch-cli\u0000has-passwd\u0000--silent",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=env\u0000/usr/bin/env\u0000bash\u0000bin/opensearch-keystore\u0000has-passwd\u0000--silent",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=id\u0000/usr/bin/id\u0000-u",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=uname\u0000/usr/bin/uname\u0000-s",
              },
              { name: "/usr/sbin/ldconfig", arguments: "-p" },
              { name: "/usr/share/opensearch/jdk/bin/java" },
              {
                name: "/usr/share/opensearch/jdk/bin/java",
                arguments:
                  "-Xms1g\u0000-Xmx1g\u0000-XX:+UseG1GC\u0000-XX:G1ReservePercent=25\u0000-",
              },
              {
                name: "/usr/share/opensearch/jdk/bin/java",
                arguments:
                  "-Xms1g\u0000-Xmx1g\u0000-XX:+UseG1GC\u0000-XX:G1ReservePercent=25\u0000-X",
              },
              {
                name: "/usr/share/opensearch/jdk/bin/java",
                arguments: "-Xshare:auto\u0000-Xms4m\u0000-Xmx64m\u0000-X",
              },
              {
                name: "/usr/share/opensearch/jdk/bin/java",
                arguments:
                  "-Xshare:auto\u0000-Xms4m\u0000-Xmx64m\u0000-XX:+UseSerialGC\u0000-Dopensearch.cgroups.hierarchy.override=/\u0000-Xms300m\u0000-Xmx300m\u0000-Dopensearch.path.",
              },
              {
                name: "/usr/share/opensearch/jdk/bin/java",
                arguments:
                  "-Xshare:auto\u0000-cp\u0000/usr/share/opensearch/lib/*\u0000org.opensearch.tools.java_version_checker.JavaVersionChecker",
              },
              {
                name: "/usr/share/opensearch/jdk/bin/java",
                arguments:
                  "-Xshare:auto\u0000-cp\u0000/usr/share/opensearch/lib/*\u0000org.opensearch.tools.launchers.JvmOptionsParser\u0000/usr/share/opensearch/config",
              },
              {
                name: "/usr/share/opensearch/jdk/bin/java",
                arguments:
                  "-Xshare:auto\u0000-cp\u0000/usr/share/opensearch/lib/*\u0000org.opensearch.tools.launchers.TempDirectory",
              },
              {
                name: "/usr/share/opensearch/jdk/bin/java",
                arguments: "-version",
              },
              {
                name: "/usr/share/opensearch/jdk/lib/jspawnhelper",
                arguments: "21.0.5+11-LTS\u000047:48:50",
              },
              {
                name: "/usr/share/opensearch/jdk/lib/jspawnhelper",
                arguments: "21.0.5+11-LTS\u000048:49:51",
              },
              {
                name: "/usr/share/opensearch/jdk/lib/jspawnhelper",
                arguments: "21.0.5+11-LTS\u000062:63:65",
              },
            ],
          },
        ],
      },
      {
        name: "tempo",
        workloads: [
          {
            name: "tempo-compactor",
            kind: "Deployment",
            processes: [
              {
                name: "/tempo",
                arguments:
                  "-target=compactor\u0000-config.file=/conf/tempo.yaml\u0000-mem-ballast-size-mbs=1024",
                connections: [
                  {
                    destination_name: "127.0.0.1",
                    destination_port: "5778",
                    bytes_sent: "60",
                    bytes_received: "40",
                  },
                  {
                    destination_name:
                      "df-tetragon-dev-ce-01-grafana-tempo.s3.dualstack.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "92859",
                    bytes_received: "33840044",
                  },
                  {
                    destination_name:
                      "df-tetragon-dev-ce-01-logs.s3.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "9575",
                    bytes_received: "28401",
                  },
                  {
                    destination_name:
                      "prod-registry-k8s-io-us-west-2.s3.dualstack.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "2654704",
                    bytes_received: "62076083",
                  },
                  {
                    destination_name: "stats.grafana.org",
                    destination_port: "443",
                    bytes_sent: "2621",
                    bytes_received: "4410",
                  },
                  {
                    destination_name: "sts.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "7769",
                    bytes_received: "16552",
                  },
                  {
                    destination_name:
                      "tempo-gossip-ring.tempo.svc.cluster.local",
                    destination_port: "7946",
                    bytes_sent: "11792",
                    bytes_received: "4761",
                  },
                  {
                    destination_name: "tempo-memcached.tempo.svc.cluster.local",
                    destination_port: "11211",
                    bytes_sent: "102977",
                    bytes_received: "432",
                  },
                ],
              },
            ],
          },
          {
            name: "tempo-distributor",
            kind: "Deployment",
            processes: [
              {
                name: "/tempo",
                arguments:
                  "-target=distributor\u0000-config.file=/conf/tempo.yaml\u0000-mem-ballast-size-mbs=1024",
                connections: [
                  {
                    destination_name: "127.0.0.1",
                    destination_port: "5778",
                    bytes_sent: "75000",
                    bytes_received: "50000",
                  },
                  {
                    destination_name:
                      "df-tetragon-dev-ce-01-logs.s3.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "150030300",
                    bytes_received: "573919543",
                  },
                  {
                    destination_name: "stats.grafana.org",
                    destination_port: "443",
                    bytes_sent: "17226",
                    bytes_received: "27760",
                  },
                  {
                    destination_name: "sts.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "4689",
                    bytes_received: "11648",
                  },
                  {
                    destination_name:
                      "tempo-gossip-ring.tempo.svc.cluster.local",
                    destination_port: "7946",
                    bytes_sent: "109209763",
                    bytes_received: "1037218066",
                  },
                  {
                    destination_name:
                      "tempo-gossip-ring.tempo.svc.cluster.local",
                    destination_port: "9095",
                    bytes_sent: "2166331574",
                    bytes_received: "105047355",
                  },
                ],
              },
            ],
          },
          {
            name: "tempo-query-frontend",
            kind: "Deployment",
            processes: [
              {
                name: "/tempo",
                arguments:
                  "-target=query-frontend\u0000-config.file=/conf/tempo.yaml\u0000-mem-ballast-size-mbs=1024",
                connections: [
                  {
                    destination_name: "127.0.0.1",
                    destination_port: "5778",
                    bytes_sent: "60",
                    bytes_received: "40",
                  },
                  {
                    destination_name:
                      "df-tetragon-dev-ce-01-grafana-tempo.s3.dualstack.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "17102",
                    bytes_received: "40358",
                  },
                  {
                    destination_name:
                      "df-tetragon-dev-ce-01-logs.s3.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "2823",
                    bytes_received: "12080",
                  },
                  {
                    destination_name: "stats.grafana.org",
                    destination_port: "443",
                    bytes_sent: "2576",
                    bytes_received: "4358",
                  },
                  {
                    destination_name: "sts.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "7921",
                    bytes_received: "16730",
                  },
                ],
              },
            ],
          },
          {
            name: "tempo-ingester",
            kind: "StatefulSet",
            processes: [
              {
                name: "/tempo",
                arguments:
                  "-target=ingester\u0000-config.file=/conf/tempo.yaml\u0000-mem-ballast-size-mbs=1024",
                connections: [
                  {
                    destination_name: "127.0.0.1",
                    destination_port: "5778",
                    bytes_sent: "60",
                    bytes_received: "40",
                  },
                  {
                    destination_name: "3.5.82.161",
                    destination_port: "443",
                  },
                  {
                    destination_name: "52.92.149.66",
                    destination_port: "443",
                  },
                  {
                    destination_name: "52.92.227.234",
                    destination_port: "443",
                    bytes_sent: "17832504",
                    bytes_received: "56490",
                  },
                  {
                    destination_name: "52.94.181.132",
                    destination_port: "443",
                  },
                  {
                    destination_name:
                      "al2023-repos-us-west-2-de612dc2.s3.dualstack.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "1465456419",
                    bytes_received: "7127830",
                  },
                  {
                    destination_name:
                      "df-tetragon-dev-ce-01-grafana-tempo.s3.dualstack.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "3395477",
                    bytes_received: "26288",
                  },
                  {
                    destination_name:
                      "df-tetragon-dev-ce-01-logs.s3.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "2819",
                    bytes_received: "7514",
                  },
                  {
                    destination_name: "stats.grafana.org",
                    destination_port: "443",
                    bytes_sent: "2621",
                    bytes_received: "4410",
                  },
                  {
                    destination_name: "sts.us-west-2.amazonaws.com",
                    destination_port: "443",
                  },
                  {
                    destination_name:
                      "tempo-gossip-ring.tempo.svc.cluster.local",
                    destination_port: "7946",
                    bytes_sent: "11495",
                    bytes_received: "4299",
                  },
                  {
                    destination_name: "tempo-memcached.tempo.svc.cluster.local",
                    destination_port: "11211",
                    bytes_sent: "205894",
                    bytes_received: "856",
                  },
                  {
                    destination_name: "tempo/Deployment:tempo-compactor",
                    destination_port: "7946",
                    bytes_sent: "1152",
                    bytes_received: "268",
                  },
                  {
                    destination_name: "tempo/Deployment:tempo-distributor",
                    destination_port: "7946",
                    bytes_sent: "5958",
                    bytes_received: "1072",
                  },
                  {
                    destination_name: "tempo/Deployment:tempo-querier",
                    destination_port: "7946",
                    bytes_sent: "10981",
                    bytes_received: "1340",
                  },
                  {
                    destination_name: "tempo/Service:tempo-memcached",
                    destination_port: "11211",
                    bytes_sent: "205738",
                    bytes_received: "700",
                  },
                ],
              },
            ],
          },
          {
            name: "tempo-memcached",
            kind: "StatefulSet",
            processes: [
              {
                name: "/bin/busybox",
                arguments: "/usr/local/bin/docker-entrypoint.sh\u0000memcached",
              },
              { name: "/usr/local/bin/memcached" },
            ],
          },
        ],
      },
      {
        name: "tenant-jobs",
        workloads: [
          {
            name: "crawler",
            kind: "Deployment",
            processes: [
              {
                name: "/bin/busybox",
                arguments:
                  "/usr/local/bin/docker-entrypoint.sh\u0000node\u0000crawler.js",
              },
              {
                name: "/usr/local/bin/node",
                arguments: "crawler.js",
                connections: [
                  {
                    destination_name: "api.github.com",
                    destination_port: "80",
                    bytes_sent: "1428",
                    bytes_received: "1292",
                  },
                  {
                    destination_name: "loader.tenant-jobs.svc.cluster.local",
                    destination_port: "50051",
                    bytes_sent: "1520",
                    bytes_received: "1272",
                  },
                ],
              },
            ],
          },
          {
            name: "jobs-app-entity-operator",
            kind: "Deployment",
            processes: [
              {
                name: "/usr/bin/bash",
                arguments: "/opt/strimzi/bin/launch_java.sh",
              },
              {
                name: "/usr/bin/bash",
                arguments: "/opt/strimzi/bin/tls_prepare_certificates.sh",
              },
              {
                name: "/usr/bin/bash",
                arguments: "/opt/strimzi/bin/topic_operator_run.sh",
              },
              {
                name: "/usr/bin/bash",
                arguments: "/opt/strimzi/bin/user_operator_run.sh",
              },
              {
                name: "/usr/bin/bash",
                arguments: "/opt/stunnel/stunnel_healthcheck.sh\u00002181",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=basename\u0000/usr/bin/basename\u0000/etc/tls-sidecar/cluster-ca-certs/ca.crt\u0000.crt",
              },
              {
                name: "/usr/bin/coreutils",
                arguments: "--coreutils-prog-shebang=cat\u0000/usr/bin/cat",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=env\u0000/usr/bin/env\u0000bash\u0000/opt/strimzi/bin/launch_java.sh",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=env\u0000/usr/bin/env\u0000bash\u0000/opt/strimzi/bin/tls_prepare_certificates.sh",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=env\u0000/usr/bin/env\u0000bash\u0000/opt/strimzi/bin/user_operator_run.sh",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=env\u0000/usr/bin/env\u0000bash\u0000/opt/stunnel/stunnel_healthcheck.sh\u00002181",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=head\u0000/usr/bin/head\u0000-c32",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=mkdir\u0000/usr/bin/mkdir\u0000-p\u0000/tmp/topic-operator",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=rm\u0000/usr/bin/rm\u0000-f\u0000/tmp/topic-operator/replication.keystore.p12",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=rm\u0000/usr/bin/rm\u0000-f\u0000/tmp/topic-operator/replication.truststore.p12",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=rm\u0000/usr/bin/rm\u0000-rfv\u0000/tmp/hsperfdata_strimzi",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=rm\u0000/usr/bin/rm\u0000-rfv\u0000/tmp/hsperfdata_strimzi\u0000/tmp/topic-operator",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=tr\u0000/usr/bin/tr\u0000-dc\u0000_A-Z-a-z-0-9",
              },
              { name: "/usr/bin/grep", arguments: "-q\u0000:2181" },
              { name: "/usr/bin/netstat", arguments: "-ntl" },
              {
                name: "/usr/bin/openssl",
                arguments:
                  "pkcs12\u0000-export\u0000-in\u0000/etc/eto-certs/entity-",
              },
              { name: "/usr/bin/tini" },
            ],
          },
          {
            name: "loader",
            kind: "Deployment",
            processes: [
              {
                name: "/bin/busybox",
                arguments:
                  "/usr/local/bin/docker-entrypoint.sh\u0000node\u0000server.js",
              },
              {
                name: "/usr/local/bin/node",
                arguments: "server.js",
                connections: [
                  {
                    destination_name:
                      "jobs-app-kafka-0.jobs-app-kafka-brokers.tenant-jobs.svc.cluster.local",
                    destination_port: "9092",
                    bytes_sent: "8053",
                    bytes_received: "5528",
                  },
                  {
                    destination_name:
                      "jobs-app-kafka-brokers.tenant-jobs.svc.cluster.local",
                    destination_port: "9092",
                    bytes_sent: "246",
                    bytes_received: "542",
                  },
                ],
              },
            ],
          },
          {
            name: "resumes",
            kind: "Deployment",
            processes: [
              {
                name: "/bin/busybox",
                arguments:
                  "/usr/local/bin/docker-entrypoint.sh\u0000node\u0000worker.js",
              },
              {
                name: "/usr/local/bin/node",
                arguments: "worker.js",
                connections: [
                  {
                    destination_name: "coreapi.tenant-jobs.svc.cluster.local",
                    destination_port: "9080",
                    bytes_sent: "8414",
                    bytes_received: "7056",
                  },
                  {
                    destination_name:
                      "jobs-app-kafka-0.jobs-app-kafka-brokers.tenant-jobs.svc.cluster.local",
                    destination_port: "9092",
                    bytes_sent: "686",
                    bytes_received: "937",
                  },
                  {
                    destination_name:
                      "jobs-app-kafka-brokers.tenant-jobs.svc.cluster.local",
                    destination_port: "9092",
                    bytes_sent: "2287",
                    bytes_received: "2293",
                  },
                ],
              },
            ],
          },
          {
            name: "jobs-app-kafka-0",
            kind: "Pod",
            processes: [
              {
                name: "/usr/bin/bash",
                arguments: "./kafka_config_generator.sh",
              },
              {
                name: "/usr/bin/bash",
                arguments: "./kafka_tls_prepare_certificates.sh",
              },
              {
                name: "/usr/bin/bash",
                arguments:
                  "/opt/kafka/bin/kafka-run-class.sh\u0000-name\u0000kafkaServer\u0000-loggc\u0000kafka.Kafka\u0000/tmp/strimzi.properties",
              },
              {
                name: "/usr/bin/bash",
                arguments:
                  "/opt/kafka/bin/kafka-server-start.sh\u0000/tmp/strimzi.properties",
              },
              {
                name: "/usr/bin/bash",
                arguments: "/opt/kafka/kafka_liveness.sh",
              },
              {
                name: "/usr/bin/bash",
                arguments: "/opt/kafka/kafka_readiness.sh",
              },
              {
                name: "/usr/bin/bash",
                arguments: "/opt/kafka/kafka_run.sh",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=basename\u0000/usr/bin/basename\u0000/opt/kafka/client-ca-certs/ca.crt\u0000.crt",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=basename\u0000/usr/bin/basename\u0000/opt/kafka/cluster-ca-certs/ca.crt\u0000.crt",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=cat\u0000/usr/bin/cat\u0000/opt/kafka/custom-config/listeners.config",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=cut\u0000/usr/bin/cut\u0000-f\u00001-2\u0000-d\u0000.",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=dirname\u0000/usr/bin/dirname\u0000/opt/kafka/bin/kafka-run-class.sh",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=dirname\u0000/usr/bin/dirname\u0000/opt/kafka/bin/kafka-server-start.sh",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=env\u0000/usr/bin/env\u0000bash\u0000./kafka_config_generator.sh",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=env\u0000/usr/bin/env\u0000bash\u0000./kafka_tls_prepare_certificates.sh",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=env\u0000/usr/bin/env\u0000bash\u0000/opt/kafka/kafka_liveness.sh",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=env\u0000/usr/bin/env\u0000bash\u0000/opt/kafka/kafka_readiness.sh",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=env\u0000/usr/bin/env\u0000bash\u0000/opt/kafka/kafka_run.sh",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=head\u0000/usr/bin/head\u0000-c32",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=ls\u0000/usr/bin/ls\u0000/opt/kafka/libs/kafka-agent-0.38.0.jar",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=mkdir\u0000/usr/bin/mkdir\u0000-p\u0000/tmp/kafka",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=rm\u0000/usr/bin/rm\u0000-f\u0000/tmp/kafka/authz-keycloak.truststore.p12",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=rm\u0000/usr/bin/rm\u0000-f\u0000/tmp/kafka/authz-opa.truststore.p12",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=rm\u0000/usr/bin/rm\u0000-f\u0000/tmp/kafka/clients.truststore.p12",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=rm\u0000/usr/bin/rm\u0000-f\u0000/tmp/kafka/cluster.keystore.p12",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=rm\u0000/usr/bin/rm\u0000-f\u0000/tmp/kafka/cluster.truststore.p12",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=rm\u0000/usr/bin/rm\u0000-f\u0000/var/opt/kafka/kafka-ready\u0000/var/opt/kafka/zk-connected",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=rm\u0000/usr/bin/rm\u0000-f\u0000/var/opt/kafka/zk-connected\u00002",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=rm\u0000/usr/bin/rm\u0000-rfv\u0000/tmp/*",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=tee\u0000/usr/bin/tee\u0000/tmp/strimzi.properties",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=tr\u0000/usr/bin/tr\u0000-dc\u0000_A-Z-a-z-0-9",
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=uname\u0000/usr/bin/uname\u0000-a",
              },
              {
                name: "/usr/bin/envsubst",
                arguments: "${STRIMZI_RACK_ID}",
              },
              { name: "/usr/bin/gawk", arguments: "-F-\u0000{print $NF}" },
              {
                name: "/usr/bin/grep",
                arguments:
                  "-E\u0000(-(test|test-sources|src|scaladoc|javadoc)\\.jar|jar.asc|connect-file.*\\.jar)$",
              },
              {
                name: "/usr/bin/grep",
                arguments:
                  "-Eq\u0000tcp6?[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+[^ ]+:9091.*LISTEN[[:space:]]*",
              },
              { name: "/usr/bin/hostname" },
              { name: "/usr/bin/netstat", arguments: "-lnt" },
              {
                name: "/usr/bin/openssl",
                arguments:
                  "pkcs12\u0000-export\u0000-in\u0000/opt/kafka/broker-certs/jobs-app-kafka-0.crt\u0000-inkey\u0000/op",
              },
              {
                name: "/usr/bin/openssl",
                arguments:
                  "verify\u0000-CAfile\u0000/opt/kafka/cluster-ca-certs/ca.crt\u0000/opt/kafka/broker-certs/jobs-app-kafka-0.crt",
              },
              {
                name: "/usr/bin/openssl",
                arguments:
                  "verify\u0000-CAfile\u0000/opt/kafka/cluster-ca-certs/ca.p12\u0000/opt/kafka/broker-certs/jobs-app-kafka-0.crt",
              },
              {
                name: "/usr/bin/openssl",
                arguments:
                  "verify\u0000-CAfile\u0000/opt/kafka/cluster-ca-certs/ca.password\u0000/opt/kafka/broker-certs/jobs-app-kafka-0.crt",
              },
              {
                name: "/usr/bin/sed",
                arguments:
                  "-e\u0000s/sasl.jaas.config=.*/sasl.jaas.config=[hidden]/g\u0000-e\u0000s/password=.*/password=[hidden]/g",
              },
              {
                name: "/usr/bin/tini",
                arguments:
                  "-w\u0000-e\u0000143\u0000--\u0000/opt/kafka/bin/kafka-server-start.sh\u0000/tmp/strimzi.properties",
              },
              {
                name: "/usr/lib/jvm/java-17-openjdk-17.0.9.0.9-2.el8.x86_64/bin/java",
                connections: [
                  {
                    destination_name: "10.3.8.169",
                    destination_port: "9090",
                    bytes_sent: "9240",
                    bytes_received: "10750",
                  },
                  {
                    destination_name: "10.3.8.169",
                    destination_port: "9091",
                    bytes_sent: "4346",
                    bytes_received: "10179",
                  },
                  {
                    destination_name: "10.3.8.44",
                    destination_port: "9090",
                    bytes_sent: "19749",
                    bytes_received: "19729",
                  },
                  {
                    destination_name: "172.20.114.244",
                    destination_port: "2181",
                    bytes_sent: "6565",
                    bytes_received: "11694",
                  },
                ],
              },
              {
                name: "/usr/lib/jvm/java-17-openjdk-17.0.9.0.9-2.el8.x86_64/bin/keytool",
                arguments:
                  "-keystore\u0000/tmp/kafka/clients.truststore.p12\u0000-storepass\u0000MwlBf_2vOrEjafpQNTIYGclilHrtgJv8\u0000-noprompt\u0000-alias\u0000ca\u0000-import\u0000-file\u0000/opt/kafka/client-ca-certs/ca.crt\u0000-storetype\u0000PKCS12",
              },
              {
                name: "/usr/lib/jvm/java-17-openjdk-17.0.9.0.9-2.el8.x86_64/bin/keytool",
                arguments:
                  "-keystore\u0000/tmp/kafka/clients.truststore.p12\u0000-storepass\u0000_Urd8cr8udBXd7sTpXQNzqZBVpHNIQWl\u0000-noprompt\u0000-alias\u0000ca\u0000-import\u0000-file\u0000/opt/kafka/client-ca-certs/ca.crt\u0000-storetype\u0000PKCS12",
              },
              {
                name: "/usr/lib/jvm/java-17-openjdk-17.0.9.0.9-2.el8.x86_64/bin/keytool",
                arguments:
                  "-keystore\u0000/tmp/kafka/cluster.truststore.p12\u0000-storepass\u0000MwlBf_2vOrEjafpQNTIYGclilHrtgJv8\u0000-noprompt\u0000-alias\u0000ca\u0000-import\u0000-file\u0000/opt/kafka/cluster-ca-certs/ca.crt\u0000-storetype\u0000PKCS12",
              },
              {
                name: "/usr/lib/jvm/java-17-openjdk-17.0.9.0.9-2.el8.x86_64/bin/keytool",
                arguments:
                  "-keystore\u0000/tmp/kafka/cluster.truststore.p12\u0000-storepass\u0000_Urd8cr8udBXd7sTpXQNzqZBVpHNIQWl\u0000-noprompt\u0000-alias\u0000ca\u0000-import\u0000-file\u0000/opt/kafka/cluster-ca-certs/ca.crt\u0000-storetype\u0000PKCS12",
              },
            ],
          },
        ],
      },
      {
        name: "tetragon",
        workloads: [
          {
            name: "tetragon",
            kind: "DaemonSet",
            processes: [
              { name: "/bin/busybox" },
              {
                name: "/usr/bin/tetragon",
                connections: [
                  {
                    destination_name: "172.20.0.1",
                    destination_port: "443",
                    bytes_sent: "36558",
                    bytes_received: "667620",
                  },
                  {
                    destination_name: "44.240.52.83",
                    destination_port: "443",
                    bytes_sent: "7436745",
                    bytes_received: "91152",
                  },
                  {
                    destination_name: "52.11.0.27",
                    destination_port: "443",
                    bytes_sent: "2264399",
                    bytes_received: "37235",
                  },
                  {
                    destination_name: "52.26.129.24",
                    destination_port: "443",
                    bytes_sent: "68996",
                    bytes_received: "1867",
                  },
                  {
                    destination_name: "52.35.164.34",
                    destination_port: "443",
                  },
                  {
                    destination_name: "52.94.181.132",
                    destination_port: "443",
                    bytes_sent: "144",
                    bytes_received: "224",
                  },
                  {
                    destination_name: "52.94.185.153",
                    destination_port: "443",
                    bytes_sent: "4541",
                    bytes_received: "10128",
                  },
                  {
                    destination_name: "52.94.185.55",
                    destination_port: "443",
                    bytes_sent: "196",
                    bytes_received: "224",
                  },
                  {
                    destination_name: "54.149.245.243",
                    destination_port: "443",
                    bytes_sent: "67742",
                    bytes_received: "1613",
                  },
                  {
                    destination_name: "54.191.237.16",
                    destination_port: "443",
                  },
                  {
                    destination_name: "54.240.250.235",
                    destination_port: "443",
                    bytes_sent: "40",
                    bytes_received: "40",
                  },
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                  },
                  {
                    destination_name:
                      "ingestion.us-west-2.dataplane.sonar.networking.aws.dev",
                    destination_port: "443",
                  },
                  {
                    destination_name: "sts.us-west-2.amazonaws.com",
                    destination_port: "443",
                    bytes_sent: "4345",
                    bytes_received: "9114",
                  },
                ],
              },
              {
                name: "/var/lib/tetragon/tetragon-fs-scanner",
                arguments:
                  "-hostMntNs\u00004026531841\u0000-scannerFifoPath\u0000/var/run/cilium/hubble/fs_scanner.sock\u0000-logLevel\u0000info\u0000-logFormat\u0000text",
              },
              {
                name: "/var/lib/tetragon/tetragon-runner",
                arguments:
                  "/procRoot/1/ns/mnt\u0000/var/lib/tetragon/tetragon-fs-scanner\u0000-hostMntNs\u00004026531841\u0000-scannerFifoPath\u0000/var/run/cilium/hubble/fs_scanner.sock\u0000-logLevel\u0000info\u0000-logFormat\u0000text",
              },
            ],
          },
          {
            name: "tetragon-grafana",
            kind: "Deployment",
            processes: [
              { name: "/bin/bash", arguments: "-e\u0000/run.sh" },
              { name: "/bin/busybox" },
              {
                name: "/bin/busybox",
                arguments: "-r\u0000s/([^=]*)__FILE=.*/\\1/g",
              },
              {
                name: "/bin/busybox",
                arguments: "/var/lib/grafana/plugins",
              },
              { name: "/bin/busybox", arguments: "^GF_[^=]\\+__FILE=.\\+" },
              {
                name: "/usr/share/grafana/bin/grafana",
                arguments:
                  "server\u0000--homepath=/usr/share/grafana\u0000--config=/etc/g",
                connections: [
                  {
                    destination_name: "grafana.com",
                    destination_port: "443",
                    bytes_sent: "13379",
                    bytes_received: "34713",
                  },
                  {
                    destination_name: "secure.gravatar.com",
                    destination_port: "443",
                    bytes_sent: "2610",
                    bytes_received: "5431",
                  },
                  {
                    destination_name: "stats.grafana.org",
                    destination_port: "443",
                    bytes_sent: "10002",
                    bytes_received: "4937",
                  },
                  {
                    destination_name: "storage.googleapis.com",
                    destination_port: "443",
                    bytes_sent: "19225",
                    bytes_received: "8449924",
                  },
                  {
                    destination_name:
                      "tetragon-prometheus.tetragon.svc.cluster.local",
                    destination_port: "9090",
                    bytes_sent: "340",
                    bytes_received: "480",
                  },
                ],
              },
            ],
          },
          {
            name: "tetragon-prometheus",
            kind: "StatefulSet",
            processes: [
              {
                name: "/bin/prometheus",
                arguments:
                  "--config.file=/etc/prometheus/prometheus.yaml\u0000--web.console.templates=/etc/prometheus/consoles\u0000--web.console.libraries=/etc/",
                connections: [
                  {
                    destination_name: "default/Service:kubernetes",
                    destination_port: "443",
                    bytes_sent: "91312",
                    bytes_received: "3039040",
                  },
                  {
                    destination_name:
                      "ip-10-3-5-195.us-west-2.compute.internal",
                    destination_port: "2112",
                    bytes_sent: "923",
                    bytes_received: "35040",
                  },
                  {
                    destination_name:
                      "ip-10-3-5-195.us-west-2.compute.internal",
                    destination_port: "10250",
                    bytes_sent: "4691",
                    bytes_received: "90949",
                  },
                  {
                    destination_name:
                      "ip-10-3-5-231.us-west-2.compute.internal",
                    destination_port: "2112",
                    bytes_sent: "54458",
                    bytes_received: "2267950",
                  },
                  {
                    destination_name:
                      "ip-10-3-5-231.us-west-2.compute.internal",
                    destination_port: "10250",
                    bytes_sent: "137556",
                    bytes_received: "4341895",
                  },
                  {
                    destination_name: "kube-system/DaemonSet:cilium",
                    destination_port: "2112",
                    bytes_sent: "23327",
                    bytes_received: "852483",
                  },
                  {
                    destination_name: "kube-system/DaemonSet:cilium",
                    destination_port: "10250",
                    bytes_sent: "53389",
                    bytes_received: "1666312",
                  },
                  {
                    destination_name: "kube-system/DaemonSet:cilium-node-init",
                    destination_port: "2112",
                    bytes_sent: "46589",
                    bytes_received: "2016113",
                  },
                  {
                    destination_name: "kube-system/DaemonSet:cilium-node-init",
                    destination_port: "10250",
                    bytes_sent: "205030",
                    bytes_received: "6895057",
                  },
                  {
                    destination_name: "kube-system/DaemonSet:kube-proxy",
                    destination_port: "2112",
                    bytes_sent: "60",
                    bytes_received: "40",
                  },
                  {
                    destination_name: "kube-system/DaemonSet:kube-proxy",
                    destination_port: "10250",
                    bytes_sent: "519",
                    bytes_received: "275",
                  },
                  {
                    destination_name:
                      "kubeshark/DaemonSet:kubeshark-worker-daemon-set",
                    destination_port: "2112",
                    bytes_sent: "60",
                    bytes_received: "40",
                  },
                  {
                    destination_name:
                      "kubeshark/DaemonSet:kubeshark-worker-daemon-set",
                    destination_port: "10250",
                    bytes_sent: "571",
                    bytes_received: "275",
                  },
                  {
                    destination_name:
                      "monitoring/DaemonSet:prometheus-prometheus-node-exporter",
                    destination_port: "2112",
                    bytes_sent: "818",
                    bytes_received: "28159",
                  },
                  {
                    destination_name:
                      "monitoring/DaemonSet:prometheus-prometheus-node-exporter",
                    destination_port: "10250",
                    bytes_sent: "3990",
                    bytes_received: "61146",
                  },
                  {
                    destination_name: "otel-collector/DaemonSet:otel-collector",
                    destination_port: "2112",
                    bytes_sent: "21095",
                    bytes_received: "896147",
                  },
                  {
                    destination_name: "otel-collector/DaemonSet:otel-collector",
                    destination_port: "10250",
                    bytes_sent: "57666",
                    bytes_received: "1870183",
                  },
                  {
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "2112",
                    bytes_sent: "180912",
                    bytes_received: "10794238",
                  },
                  {
                    destination_name: "tetragon/DaemonSet:tetragon",
                    destination_port: "10250",
                    bytes_sent: "932030",
                    bytes_received: "31558959",
                  },
                  {
                    destination_name:
                      "tetragon/Deployment:tetragon-kube-state-metrics",
                    destination_port: "8080",
                    bytes_sent: "636441",
                    bytes_received: "68159003",
                  },
                ],
              },
            ],
          },
        ],
      },
      {
        name: "tetragon-tracing-demo",
        workloads: [
          {
            name: "tls-weak-version",
            kind: "Pod",
            processes: [
              {
                name: "/usr/bin/dash",
                arguments: "-c\u0000sleep infinity",
              },
              { name: "/usr/bin/sleep", arguments: "infinity" },
            ],
          },
        ],
      },
      {
        name: "vector",
        workloads: [
          {
            name: "vector",
            kind: "DaemonSet",
            processes: [
              {
                name: "/usr/bin/vector",
                connections: [
                  {
                    destination_name: "172.20.1.197",
                    destination_port: "8080",
                    bytes_sent: "6353197",
                    bytes_received: "5586",
                  },
                  {
                    destination_name: "52.13.169.55",
                    destination_port: "443",
                  },
                  {
                    destination_name:
                      "http-inputs.cisco-ngfwbu-valent.splunkcloud.com",
                    destination_port: "443",
                  },
                  {
                    destination_name: "squash.tetragon.svc.cluster.local",
                    destination_port: "8080",
                    bytes_sent: "508769",
                    bytes_received: "1400",
                  },
                  {
                    destination_name: "tetragon/Service:squash",
                    destination_port: "8080",
                  },
                ],
              },
              {
                name: "/usr/bin/vector",
                arguments: "--config-dir\u0000/etc/vector/",
                connections: [
                  {
                    destination_name:
                      "http-inputs.cisco-ngfwbu-valent.splunkcloud.com",
                    destination_port: "443",
                    bytes_sent: "4529830",
                    bytes_received: "91176",
                  },
                  {
                    destination_name: "squash.tetragon.svc.cluster.local",
                    destination_port: "8080",
                    bytes_sent: "64033009",
                    bytes_received: "139252",
                  },
                ],
              },
            ],
          },
        ],
      },
    ],
    host: {
      processes: [
        { name: "/bin/busybox", arguments: "-u" },
        {
          name: "/bin/busybox",
          arguments: "/usr/local/bin/docker-entrypoint.sh\u0000valkey-server",
        },
        {
          name: "/bin/node_exporter",
          arguments:
            "--path.procfs=/host/proc\u0000--path.sysfs=/host/sys\u0000--path.rootfs=/host/root\u0000--path.udev.data=/host/root/run/udev/data\u0000--web.listen-address=[0.0.0.0]:9100\u0000--collector.filesystem.mount-points-exclude=^/(dev|proc|sys|var/lib/docker/.",
        },
        {
          name: "/bin/prometheus-config-reloader",
          arguments:
            "--watch-interval=0\u0000--listen-address=:8081\u0000--config-file=/etc/alertmanager/config/alertmanager.yaml.gz\u0000--config-envsubst-file=/etc/alertmanager/config_out/alertmanager.env.yaml\u0000--watched-dir=/etc/alertmanager/config",
        },
        {
          name: "/csi-node-driver-registrar",
          arguments:
            "--csi-address=/csi/csi.sock\u0000--kubelet-registration-path=/var/lib/kubelet/plugins/ebs.csi.aws.com/csi.sock\u0000--v=2",
        },
        {
          name: "/etc/eks/image-credential-provider/ecr-credential-provider",
          connections: [
            {
              destination_name: "169.254.169.254",
              destination_port: "80",
              bytes_sent: "1767",
              bytes_received: "3151",
            },
            {
              destination_name: "api.ecr.us-west-2.amazonaws.com",
              destination_port: "443",
              bytes_sent: "3708",
              bytes_received: "11184",
            },
          ],
        },
        {
          name: "/livenessprobe",
          arguments: "--csi-address=/csi/csi.sock",
        },
        {
          name: "/opt/bitnami/kubernetes-event-exporter/bin/kubernetes-event-exporter",
          arguments: "-conf=/data/config.yaml",
          connections: [
            {
              destination_name: "default/Service:kubernetes",
              destination_port: "443",
              bytes_sent: "160316",
              bytes_received: "5043053",
            },
          ],
        },
        { name: "/opt/cni/bin/cilium-cni" },
        {
          name: "/opt/cni/bin/cilium-mount",
          arguments: "/run/cilium/cgroupv2",
        },
        { name: "/opt/cni/bin/cilium-sysctlfix" },
        { name: "/opt/cni/bin/loopback" },
        {
          name: "/opt/tetragon/tetragon-oci-hook",
          arguments:
            "createRuntime\u0000--log-fname\u0000/opt/tetragon/tetragon-oci-hook.log\u0000--grpc-address=localhost:54321\u0000--fail-allow-namespaces\u0000tetragon",
          connections: [
            {
              destination_name: "127.0.0.1",
              destination_port: "54321",
              bytes_sent: "16542",
              bytes_received: "5464",
            },
          ],
        },
        { name: "/pause" },
        {
          name: "/usr/bin/aws-ebs-csi-driver",
          arguments:
            "node\u0000--endpoint=unix:/csi/csi.sock\u0000--logging-format=text\u0000--v=2",
          connections: [
            {
              destination_name: "169.254.169.254",
              destination_port: "80",
              bytes_sent: "3014",
              bytes_received: "3903",
            },
            {
              destination_name: "default/Service:kubernetes",
              destination_port: "443",
              bytes_sent: "2839",
              bytes_received: "12568",
            },
          ],
        },
        { name: "/usr/bin/basename", arguments: "/cni/loopback" },
        { name: "/usr/bin/basename", arguments: "/opt/cni/bin/cilium-cni" },
        {
          name: "/usr/bin/bash",
          arguments:
            "-c\u0000\n        /usr/bin/chronyc cyclelogs > /dev/null 2>&1 || true\n\u0000logrotate_script\u0000/var/log/chrony/*.log ",
        },
        {
          name: "/usr/bin/bash",
          arguments:
            '-c\u0000--\u0000mount | grep "/sys/fs/bpf type bpf" || mount -t bpf bpf /sys/fs/bpf',
        },
        {
          name: "/usr/bin/bash",
          arguments:
            "-c\u0000set -o errexit\nset -o pipefail\nset -o nounset\n\n# When running",
        },
        {
          name: "/usr/bin/bash",
          arguments: "/etc/update-motd.d/10-nvidia-eula",
        },
        {
          name: "/usr/bin/bash",
          arguments: "/etc/update-motd.d/70-available-updates",
        },
        { name: "/usr/bin/bash", arguments: "/install-plugin.sh" },
        { name: "/usr/bin/bash", arguments: "/usr/sbin/raid-check" },
        { name: "/usr/bin/bash", arguments: "/usr/sbin/update-motd" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.part1Xw5b" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.part4m1JX" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.part6PdPy" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.part6VV3a" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partBbtvc" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partBepMz" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partK3o18" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partK6TuU" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partL3GyD" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partNvRMg" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partPqG3S" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partPwKwt" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partSnk8m" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partSuwv0" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partTSQMr" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partUd1cU" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partX0Tld" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partXKR6a" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partYwc8V" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partZVCfT" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partZarqx" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partZeugm" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partaZQ9e" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partc5GFA" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.parteoUki" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partf4axd" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partjQ6m1" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partk5jtm" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partoLAaM" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partob2Uz" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partp2NXR" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partpiKKo" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partunACI" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partwwNGb" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partyYDK1" },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.0gsNSiuWU1",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.5LkxYPhWpk",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.A7UdddUeNj",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.B3hQQlvKmi",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.BGVbzMPUL1",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.CmpENTL0NF",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.FUAfFzKRir",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.HtdLVciCJK",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.PlGe1AUWpH",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.QXNSiA1RsF",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.RnwxYv63sr",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.U4VtxayePA",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.W4PSEBHfaB",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.WFbB9sgpfA",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.dFX7CB5YVC",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.dPTFnAL7oR",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.gQ69mWXyiR",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.l6igLL0Dr3",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.lttTh0XpMg",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.qmcRMQdmqP",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.uHoULVeGhb",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.v58apTE1LS",
        },
        {
          name: "/usr/bin/chmod",
          arguments: "go+r\u0000/var/lib/update-motd/tmp.vFkxXkUBQ7",
        },
        { name: "/usr/bin/chronyc", arguments: "cyclelogs" },
        {
          name: "/usr/bin/cilium-agent",
          arguments: "--config-dir=/tmp/cilium/config-map",
        },
        { name: "/usr/bin/cilium-dbg", arguments: "build-config" },
        {
          name: "/usr/bin/containerd",
          connections: [
            {
              destination_name: "104.18.37.147",
              destination_port: "443",
              bytes_sent: "180",
              bytes_received: "104",
            },
            { destination_name: "172.64.150.109", destination_port: "443" },
            {
              destination_name: "3.219.175.113",
              destination_port: "443",
              bytes_sent: "180",
              bytes_received: "156",
            },
            {
              destination_name: "52.54.136.228",
              destination_port: "443",
              bytes_sent: "1141",
              bytes_received: "5344",
            },
            {
              destination_name: "54.210.103.166",
              destination_port: "443",
              bytes_sent: "614",
              bytes_received: "6758",
            },
            {
              destination_name: "602401143452.dkr.ecr.us-west-2.amazonaws.com",
              destination_port: "443",
              bytes_sent: "98817",
              bytes_received: "111230",
            },
            {
              destination_name: "auth.docker.io",
              destination_port: "443",
              bytes_sent: "4703",
              bytes_received: "6325",
            },
            {
              destination_name: "cdn03.quay.io",
              destination_port: "443",
              bytes_sent: "72984",
              bytes_received: "10912855",
            },
            {
              destination_name:
                "df-tetragon-dev-ce-01-grafana-tempo.s3.dualstack.us-west-2.amazonaws.com",
              destination_port: "443",
              bytes_sent: "21020",
              bytes_received: "19772782",
            },
            {
              destination_name:
                "df-tetragon-dev-ce-01-logs.s3.us-west-2.amazonaws.com",
              destination_port: "443",
              bytes_sent: "34961",
              bytes_received: "4990870",
            },
            {
              destination_name:
                "docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com",
              destination_port: "443",
              bytes_sent: "6741",
              bytes_received: "774531",
            },
            {
              destination_name: "ghcr.io",
              destination_port: "443",
              bytes_sent: "11815",
              bytes_received: "45835",
            },
            {
              destination_name: "pkg-containers.githubusercontent.com",
              destination_port: "443",
              bytes_sent: "36208",
              bytes_received: "17241262",
            },
            {
              destination_name:
                "prod-registry-k8s-io-us-west-2.s3.dualstack.us-west-2.amazonaws.com",
              destination_port: "443",
              bytes_sent: "21242",
              bytes_received: "14512117",
            },
            {
              destination_name:
                "prod-us-west-2-starport-layer-bucket.s3.us-west-2.amazonaws.com",
              destination_port: "443",
              bytes_sent: "26748",
              bytes_received: "17009794",
            },
            {
              destination_name: "production.cloudflare.docker.com",
              destination_port: "443",
              bytes_sent: "26121",
              bytes_received: "31609764",
            },
            {
              destination_name: "quay.io",
              destination_port: "443",
              bytes_sent: "18529",
              bytes_received: "118711",
            },
            {
              destination_name: "registry.k8s.io",
              destination_port: "443",
              bytes_sent: "9697",
              bytes_received: "31889",
            },
            {
              destination_name: "us-west1-docker.pkg.dev",
              destination_port: "443",
              bytes_sent: "3532",
              bytes_received: "15806",
            },
          ],
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments: "-namespace\u0000k8s.io\u0000-address\u0000/run/container",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000008ffc267c37f8f392d1e170ec841f6c3a1181d71621b7f30fad20c9300aefab\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000123fd58dfeeea8ff94084dec24ef4a7bfb79f42ad9db7b0480171ca8a20f972\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000019c6314888aa63abd2ed093cce485cbf86f57101df856152b49fb87c132c0cc\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000001bd73396f11aa0d218f12b99b0a1e9691eb76ce276dca473093e7d5f5a5df76\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000001e6efff04103fc38309847a87afa4f1df1ae11c220aead11f024a1f52836c9c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000020f63522f815076499925295d73c65af0cbb5372fbdd1e31856a58e5cb9f072\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000210040f7c63035756d5af0d6ca74e41d2284ae065e9421d0f12ce1c2ed9917c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000022c96f7bdb76129554efa0279594df41ecbd8b96a4fa22855a25299f1816c7e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000028a9d0342b2b76a568912a56a4d4af494cd4ac8bec2d1fca1ce6f7c711c0a24\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000003048f0130d2e94f7cd8008ec29830bc558e3b24f4687235d844b83228551a0a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000003f263e8734cbaa426eca21e72256aa1f8cd218746ca1ac497879140a7bc626a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000424b85e1f3b0a6c71709dd1ff10f3589f76d672e7bb272f680aa6bdd163120b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000004522da752b70c534fe00606f09010eba043d139fe5489f8d003630fc11b5712\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000004c8eaa496dace3f510458c9573621bd27f39e9c3f12028f4779b314c1e36302\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000004d8f15e787d2109dcb83b8e066cf217fb22dc2cb5ffeb8eda51ce5854ab7cb9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000004fb7f134ffe8a6e6204dbf627c9c2cc88dd0427b4476021ab40ddcdc672e617\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000586b29dff682cc77a99566cc63d654cb35bd9deced98562f31877665c151eb9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000006051576641af62298cb8987ad0dd3b42b7148dd12f23ae9afc474e85a652940\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000659cdb586b47fdc0e91a99749278fa49a36da0dcb06b7cb1a8e2491be442737\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000008165cc54cbaa7a8f99e37032248a9e20021b7e36991f39ce595805b53eefb4e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000852945d246111075a6bb862ac68317c640258eaeb3382e539a3f8806a861c76\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000088e25485d96cbf76af8d252c4e70c429ef70d68538923bf945210db6a9e3569\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000009182d414cee756ceabb2ac9ac91f74a7d90ef38ba8d597f74bf279938fcf484\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000098e3d505e0266bab4c19bc1a824f5f2b359b745380cbeca4620f6ba8d5de92e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000099dc293fa70909e774728f4a2c1266d7a3ac43347df45a5d4f695f720684683\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000099e2b51a59b83e37b85e35cbf0eb084ad9b67c184f1bcde07bf772ea2e1cc42\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000009fa71f56a8de021e95914ee6dbe11a25392cb67f601f8eca0016b429367aa11\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000a165a34f2cebe1244db1412b423a40bdcdad1477c893a8ba75b221dc01c39bb\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000a84e9945c7f40823899909ce8bcf10dfb0a623e918195c4012f5394cbb2422b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000b9cbbbf4cfa0682d07754bc029d98615fb1bdc418df9c32da3e6f2e281ac787\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000bf25724d5ecb4701e27e22251c1c2c46c39bc386da4ebd03fead56bf526400e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000c0960c26a93a6e770b146f3524a9f5ebc40803670293d77937988761184519d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000c0c727c874391788c77e07866014c16b19ddf4b1b7b7a06202644cadb43563d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000c2114ab789b6a934d85eb190c2ce71b1ec652ad659e22d0c1b2e308c6c08d87\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000c69138904b28ec0f83b349587f48d14fe80c4cab80cc6a8799a6bb99ef21631\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000cc1cac12a90087ae549e1bacc4278f638398e1cedc6218cdc1e72ed2097e634\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000cdf021b67e6facfac23f1018e67008804b6c7f6d2f5abc0c8ddfeb4e96f62de\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000d1139f1cffd4d795b680bceda648f02f7299d83b36775c71845104e815d3525\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000d503762dae63709ce78a8389bdbfe0970142740b6c1fc3723f824fc8eeec3ac\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000d54287f4a4ada7a0f14ecad4decedc0a4e096c4cb1d583527eb5fc4248c4540\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000d57375e0cb1631e7b937a1628b6b0f82604f67ee4434ac7da62cd48eab3bbcc\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000e0369ee760e553e96bd2a9469acec127e57a99c5dc9120364e23d55989daed8\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000e7089afcfa82657621a06dd98ebe07028dc36e269779c5ef95fd9302c042fff\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000e9d515e4fdda46dd684d23b8574749552abf0af78c762d20d958d6c295f88a7\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00000f5874116ff81080902f122216c1ac8fb3ae1de581988f5cc3d31319e6bec382\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000010019a27e89c0e53d77413c1101a43764df82b10ef4126233a5caba2862e5f40\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001081eb70ebd183e5a8af4c2d2902e7ac5cd5b224feec866ed7b40cd52ab437aa\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000010908bcfb2e21e10a48e260c37e85effa26f0107f5b9ac974ea4e54cc8899cc1\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000011c078fb4832e9e30f6121705a2fcf17a5548ea8338e3bbe54f9fbafe4958964\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000011eafdf633b5d22272f21fe291a69bb2fb52380d4502d48a58df9df4822ba859\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001235dd6cbca6efa524c77e4910f6bbb62bf14f8586a6ffb8b1db2bbf28cf71d2\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000123e20d21d076648bbc4e93b1c11c9a47e6fbb953c83f494addcb59183958eca\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000013436b9c0f01ebe152cb46f11ec52ec37468b6bb4684550a52c63aa79a87ab25\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000137815f34d667f7098d67a1c7087c398d5d996a444d298db9f2715dbadedec31\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000139a6746ed9f9cc9befa094303480d2363db41ce3a4c77b7091fdcc9630033e7\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000013a11667a2231105d3f04a62bc5fecfd4eb2dafa6bfc3760f279873a21207f2d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000013a5309adc54b31594a44ea1afca6ba043d8b8498e7ebcb91234fb8ea35301c9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000013e955a2a26fed9fbc28a89ace7d26999897c5f9060e72a57a9211c17de15375\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000014225a18df6b42f765e6d6392edfae3b72fbd4d1580540307a2532313ff47763\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000148dfe8d7522117e0a4f54064464c3f5e0e079ff5b35fdb292954ac5b1af2f52\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000014ecd37eabf456c27778c10be7d113519d3208b539f8baa7d1d8704420d82ec2\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000150b9044d50e85c5b88ba6071683ee1a35bf609d3c83eb0eae5419633db2c4fe\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001545a516773ab32c8e9c2be47409ca1937ed7243ea82fc0494dee3fbd9f3db33\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000015772c6db66ad5288ccbcbda1d2d9294019f835721e0cb1fddaaf194e4b52812\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000161e90a9dc42dc9d3dc4d9b80e3fe24f7b02ff3a42a61bd5e8aeeee558c40676\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000166868e1f381af83d21e832432d2d198951ca56213ab942d539e9ae6d4fefa57\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000016e7a50254f97f9f3987fa013fe60a644e9e9d6a6b3c9c5a06d19068d57d7413\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000016f44f928f65b178ed2f955f4a1cf7d475814cc05f5bcdf9be97dce97cf2fd53\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001757f355619c9b1e4bab940e7f763dda5947b476448207bea7f802565da09cca\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000177fc194876335c2ad719e4251800ec655d110a6c6d637f9df4f330e72eb933b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000187f2f74f0ae90ae4d38995de7de3615076599168ae088171d9bee0f865f2baa\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001899adbedf2b9197d5ff9729b561cf13d24192a5fd2005858b27f3163efe493a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000018e793fc53e39ca24eb02d176109a4ff825d22d8559bc3c46603dbb7803a5bff\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000019a6d9b8a7e82ae76b79cdab9a4e2c1935abc919b9595bd31303a3790af87b63\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000019aa8f8a156510c7821a038cd9083e1bf04c0f7e4009a785c3b946373519afc3\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000019b939c42ce49a1339b6d12e2ebdb83356a140a8be4fcbb24eef3b4645bd9e99\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000019d699ed586295e80395b4fb2d8b4a45e9bae91256cb9cb807ab631815e1e85f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001a20cdd226470380f4c1047907038ebbad46c89daee59bb2a565ede8d17c054c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001a3f7e3469bcdcce3c341fb698a4b61c6038ab6c727edad2ccd811b392ca60ce\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001ab4844bce837b448c0043d4ad7c823f66e31ef0c93f39afa1b55ee319898c2c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001aecc28aca6b6267035421df5dcebebe51ca6b7a4016c5f163581aa298b49809\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001b0795f186425de550d259f5c4ce209a2bc0e0f960edd9cd8d0097e09d0cf245\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001b0f628e7061b10ef2eb1c07142fe3e70c9425846d78cfac55a0fe3ff15c06eb\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001b8496a591b68476fb1507f290ddcefb1249369965023cec23d7b6656cfa3fc6\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001bb6293f309a9b200627aaf064e39786d6d5ec687cb69cb6394830ff50aca9ff\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001bef5d1750ac91587cff169736e937b1ae28115fb35e4f97361d0b4bbd562bdd\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001c15b1f83ff52bbe306cf6d39ed4902315d9c4af6c557390da1cbf549e367daf\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001c962301943a199401072922199e22ba68c7f2fbe58c108d6fa557c4cb1f4e00\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001ca1ef1869643242485123049b3737ae5dd02afa95207d8ba0e3c5d74803b821\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001d1c1b0e1c27c5402a1dae3ec973111796b1c7ecbf25b443c71faa474c20de22\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001d1f32d54700b8284fa876cba5db2599674c247c591f787a861aeafd060537e7\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001d8d89dffaac59729e701cbb07cd23eb552f84c66883c4d77859111b3e544d7c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001dba5588172d1862baaf4c40e1af3ef706b1f0464947b7c32f29763d5be2666b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001dfe7e413fb0a380bf841e9ba2713812dc49348062b3c479bba80968eb062676\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001e4a0a2fc205ac8254826f7a4f0e3db88fa4efb6221b2a261b8f21af68f4a827\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001e6db9e3b4d6e78a059312ee7832228f21205160ead43c3f4d3cefd1eab23778\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001e6df016382f84c2fdb623e96b6230d5ce26d3fdf4f9b3bc5b8d4d035bf863e8\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001f2f078a773cf238de16ccfe324103387862bed51be2a231723ffcef8b667369\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001f96866acc41a39ae2aa56096c6d1b8bfa25b36b291d0a715c1eec52eca54e18\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00001ff2992ae6e0ca0e10e9c0b2f1de4a10ee77b42dd3746bbe3eb6c8c71682b42d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000020bb45a57005c5e806c6d4c2c53e685185b991e6f13cdd0395da476dfba37bfb\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000217308713c2d4d3e0cf1b46d551c018ec55813fd2d26bee1c29a82f5542c63c8\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000021b5e864386890a13ad4e307d42a1e334ddc2d200362d4a00c4c12d9368826aa\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000021b8e66101ec8885c3a8307e2e7b5fab3868ccc05f4e76e7f8761bf03b11f5b5\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000021e56b861db2eb250d7fccafe462da9aeb40c0a175fc0e3a9f651efa44192a0d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000021e8f75d39f5bd5c51d64a74382e619e301a0c1b02dc9a5189beb119d7f91b6b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000021e921c847043b332ca00e04daafd3dfb4aba8e03b79ba8aac84dc17938cbe10\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000023eaf2f9597b4932a50f92c5a34542d63e49e652e3b07307692a6500c9457691\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002423a3064daaa56afb8f4cff1384c69d2bda7d225aa8837106ce881496096262\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000024652e7f422c05f34710d627e48bab4ed1557da197fdf72400a0836611edba47\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000248d5e5bc82a61608f7b53d46b18c9b73a16fc5e0543d068dac8eaaf50f84834\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000025dd76ff549c177a07e4d3ec6e61a399e785e72ad6f724037f260150c2a39f85\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002606fdb4e1c9775dfb55d595bbbd93a0f630d4b2befb81b3a0eaec90c238936a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002611f5b6a4b1341d6fd3335fc6479d240113cde7b45705fbfb7c1bc62fd61cae\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000026471a918c269d318e67f57158b1f432012e01aae46be2df1d10197cf04b11a6\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000267644c26c28f848986447549292575c018ad8f75f25bbd0e94049927e144d48\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000026842306c474c640420d15ad55fe91600b61a4cbac51ac2b559de72dfb4b9114\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000026bad06aa9087e3b48b696534ba3b47091cfa60f8ca3965e072067a43cca0da6\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000026c9cf4bdfb61ae0647b4aaedfb25dafc8d416c9cc3d63a76dd65e6fbfebbd65\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000027261c8e59efe2bd9f74c574eb4ec7eeba2eb16efc90d9ac9ccec5016e3c089f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000027e203083acdff2849c62a87325e2adceb17648aeaf3b069759b3b2f5482fd01\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000027f08cf88cc321a20a213034d087c144953bf2397781513ca77c823563ee8726\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000280a068743e37fc59b4e7a451592fb570a4826014da64446cc2a2038cc3ab621\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000028465180c1440aa15fb84e2fb4ce2adc4a8c625e806c7c83b856d9a077cf0fff\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002851c84376d9e349924156856f4b0dc38904a4b4927570a165418d1910dda0d7\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000285b80554aab66accd0641f91b9f3f1b5bd44ff4e6a500f34196c34207578f12\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000028b1cb5ee898c4acef05ed4ca96d63511f6e112ae96cd417a11c73fb39aaf9f8\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000028eb5a143033b9df13ab0b0fe9f11b44cdfb14c55002c636a1e84f57d17b81c0\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000028f9be4267d1682ae6d833d3d6fc00ce7cfb74b03f20bdc872d58e7561bc4606\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000029a50a68cd383ea89ad38774501c56f0b92e8168b9e435c5009cd0ccf315469c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000029b92298773f00ace8fcabadda8343f03a1c213626685b432803180e1b05198a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000029d3023a4baf9f19dcd27dd1c4a9f87bbbab02444cac81415c5f4e44e4bee3f9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000029e3d2253ada9c50d6bb2819617a591769a098e913b024b9e07122ec3dc863a0\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002a874ced6370fd94be8d4f5ff0cbe8deab7111d4e5ca2f8c1554880b89fad4f2\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002bc361edf01101cb1414894068c28abc46f88268aecbefed8d3271953d7bbf24\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002bd650960e041d79367a6220e74830cb77dc0b2e93cfafd9186473d20896def4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002c16a30d47cd89860191fbf0202cad23dfe0045748e0c4ce8983db7887ca2790\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002c2baff1f8a324db622a10b71a683c59d29cb143db9e604c4c9d1969fa12198e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002c74916b8ab101bd6170eb65e4a41378886c5c41377d29d06d242d1504f1b66d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002c8d71c8ce8d123e077936022af97056e0660d257817f326a7fb1a2563fa5657\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002cdc1b241b0ce926fc8ea690cc14f45f59bfd1ed289d8d241f2793c563b97871\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002cea86434f8f5f63c9c12c3f77ce7fb6b65407692d21f2e7ba374c3fd01e847f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002d26d25b46cfb1b8fc23075bf80b400fd07dbc2d66e6220a79702c2d8778a3a7\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002dcaa499b6e71043791467902766f1d00b5f4289cc053f40255150132d9ffe1c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002e7431d94e324efce4a40af7f495c66491c06155762e217a89ecfd6f93145405\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002e7447f7531853a0060c84ea0f7324e8f6ae84b95ebe23c159fd3dc4d5c1e693\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002eda902654d50130173759dd5a26a7dc0ad6d0b97aaa4e4209f61496cb067427\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002f05178879415114bde481f1d618533abe48531ec4030f3513aae334420dd7e2\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002f0c34ec0198c18a1251be10a4fc04951d2b212b8191c3a0adea06e80c3ded90\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00002f2a5c00d4e33e93f5fdec022a9e25bd53cec409290e35304b92cf22c0492fb8\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000030183e14e34391c2bc173b051bbe7f4b5cca3361c2368ad4c314432a32c68e77\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000302d90a207d6b886e5a452b0b41af4b7dd91cda73379e1f67996692c20055f79\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000305dcd1a72c01fb9eccc3fd22c1b0f326c23bf45a04c1d0d40651a79b69c225b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000030be9aadb5be5d39f287144a351335306b4d802650221b7340ad4f5ec3dbe90b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000030e212c6cdd85c806c6d27a304ac3edc4969ce69281892af12a63de208338bde\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003173fb7d1b7cc56e1a0ab1309b94bb167261a8a074f2829ae58560c5c57e790a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000031e9d8748d5ed3c95c0739691aeb375d374aeaa9a5cef62b06ddb679fb805cd4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000320440a7197d3037004514d778299cc1bb4491bb91361c5427ad23a87a80e741\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000321b346f32ae24cb2794b02c14614e6ad3ebef38f43fa96e61ffa8e757cea756\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000323d650260c21ca45a7cfde6a494bf99959c4f3f41b0b565dbda3cdb93a7b050\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003264fc9ce6152a3275bc4745070d5445bfc0faea7dd7c5c47e238146e711d867\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000032a864662c62fc02b3a18c4471cde3228f5d7af7b5507d0c1540aa87a2df27be\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000331ce62ecebeb23a1814b20cbaeda11627d4c38b2d1cb89228c0e5c2f94e56e4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000332af505d44271644c921d787e1c0b6643f375e6814673b5d63f00cecee48b5e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000033caa10f2616698b3f266df52f47388fa5a936970cd5ea592fef5975efb26fb4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000033ebd3bb96557380365ac95b238418d86280eb6e4ea213aa70feb11992c145db\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003442a04150f219aaf6199700a167154dee4b9b2bbdb3dc167f38e0f5f71d1079\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003446272e40df7db62df79875b9d32e744181590adf29cac8d5a64983f790fe68\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000034615924cfce24537d44026302ddf6c997970be5843acbe04c0b52a402dafe9c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000352a6fcc995760a5c637efb776584e2417acb929b87ceb54805e150a6e20cc4c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003533dca8260e50516e5c119ec47048ee17b8b2d255501432219330ec3b9c090e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000355725f55f886237886ca51c129f8f4cfacaa4cb3c5d12b8eca43e815e942cc1\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000035ab87b1e3a57833e3bde6fbb61baf8aa8f311a71e1fb76c5ad37654a7230afc\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000035e70d1469065b0efa13ef6e46974fb8429d9a853c4e3a0ecef475fe67a479da\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003681175d2e32dfeefd338d0cdfdd5002bfca80dd0c80e47c83a4aa70955206b6\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000036a8d2ff1d8fa4af09c9931f410c5152a442f16590b7b746ebb69e4fe4773d8d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000036c56d1d8a71fd7fce54889377baa3f3d9f60caafc168d2e826f07e4a39b1f81\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000036e71cc2a5cab9c028a8945ed2be4ec976ebc9e7570b12b5286e0820c2d2c177\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003718de74e637d1c2815e4559699a58f67436f7d942be13eb803a2b7dbbf5c29b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003748ba740f7fc64c7d9e9c769dd790cac043874f34d0e5a1a8fa7734a3b76803\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000037bd6521f36dac8475007279f8018a1145754e2d5d5a35ad6cf1bca08beba351\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000038fea03074051f7cd02831c6a29a67a39529d682f2b2c4c651d896f2ddeffeae\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000039245b7e1f5699c8df24848dd7e2f656feeeec6a469c619feef1a7d834b06ccc\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003931cbb6f97406df6966662b36169af13e59a5c9358f13e289e9f1ad5180e4da\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000039d4e70eaea0e38e1100e0331186103d9952d7127695b62a2027a2a07eb62043\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003a452d927c1cbca2d4962173ea01b6460acf1a5233b6bc757d916b188fa7b1a4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003a635d161b35cfc180711ad5a9481fc8b863395a97144ad43a125353531fece8\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003b405692323f4d094822c35621d7c1b44d0d592211012a8f37b59d5e8e48e503\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003b4ed6dae886d73e9267f210855851deb4b40a7f3deed6d2fdc5fb7282fb8402\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003b6c96143a853e8f5ebb4619d5994d1e94041adb1eecc9c7fdda54b569c4dff2\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003b884654adf326afba42b3a6f955e81df318baa742272cf278ed68ca2380ad70\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003b89298ee693ef1e210765e8701dfdcc8905a5c30fe4cdcc4825b6eb351d46ab\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003ba2311d89988ce1ebf1bc18d6fe36e17a692bb0c5407be1390a9174113b7e21\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003bd075da236be3b11e328cc4223f42aa95f18e13493f0e035ccae7c9ef7ee308\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003bdd0c903b2dff2ebc04b92325b419ccab8940c7480951399eda77daf8a516a5\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003c5541cb9d2b6cb9cce71364d80d36a953bd7e43a95992404c0135982ef81dfe\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003c81771cf005061a6d577f58246b36dc9d7d84db592f2991f798acfa2315e027\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003d5b0d088d8abb47398f0bf8163e80158a8c25a7296deecb9069af8736891da4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003da6259d0c0d8677eb30530c88c12f4e932a0e305da043b5b7905c76c2f6424c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003e03cd4192a79a807528be5d79b781dd6fec1da2d610d5ed45e14c9d2cda9e6d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003ed92332ac0b5d6f036b3e59d2428bb6ff1e5f8530b24f5e8302f1a81d8b0365\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003f39b3cc1d5f4059049b09a6a9b930d713e33d310cb36e199487cdfa9579a5d4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003f72b91b700f8b3783dd5b926e821e587275d5c16f205063a3cd5e2dcca4bf76\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003f742431deb8cf1d205a37a93211b87b60296617f576c3dc34578eef8b848d77\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003f95be7126b58e358de3a4e1ee1a72f7639aae0bfe887e69008db4d09e18e40d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00003fb1da9edf6a5e276287ccc99657b9b87dce18b30a1c9b08f520496c81eed184\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004046fc3964800ef59539cfbcbf5f2d3c26bb728957315fa8c99d36a88ba945e6\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004049430305fab3f8ad80cd1d8f84ef011e9e5ec9b9862c82b62d9f9931a69f62\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000040d8edf9c3d131e8c02a11113d7fc32c328a7251edfd483296909f3da6b3f88d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000040ddd5bccb8de95f7987045b57caa350c2b7dd768fb9e6ab716e1584710be352\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000042542a6a33bb1359e328ac405075e16ffebd3c49cdf03b594f4f3db1271f9f7f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004257eef575485f946dbab79ae5a59d245f59b4006e3d4374fd7fd0d15095bd17\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000042847d08870213be59404c1c8fec191f6cc3d37f2d39732eaf33cbbd7075451f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000042874ec512ca910ad6a0df02b253695e84afbf2f3704420874662f46f10b1385\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000043326933880cb5eb2afb33183990164a76a9ec54a3a8e16071a7fe48702e4403\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004378017078881ead04373d41335210e8345cc05eff6d4d7fc535914f6a9e6566\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000043879a47bc497c2cb1de25438c5465bd78557f5895fca08307038e66a550d942\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000043b751be6171985de83a8845ccd40a3ff4281f589766fdfb9d3f8aefa8670ecd\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000043ba0626c4998072a93eadfcb59502f9794bbd08bf8d31d907128e0315c5bddb\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000044a495c2203b11896f4825d68aa70189755c8eabe1983cc535932ebe28855dd1\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000450b313a6fbd33f6d1e90aec881c1c4cf4816392b225f4954858419123857be3\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000045f2c1749017292ba1fc1d5293c71b4c20c923e660e9c490ca8518c01c2a8ff9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004663d6c9a4eba778c41c5dcb43417fc85e12d6ce5d82a68e0a7921322a691a59\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000046abc515131947d515517a6319cf7243eab6911b3a1304d6b2a9808d7cb67ea6\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000046dafba1365b32af3cf378fbb0e711001e70a17ffc3a12da2e3fca14e21ba87d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000046fa4b09268acbbbc8c44ebe8046a1d295d4ff1ae35afcda543bee700b4dbd38\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000476cae4452c80bd16efd8ff30c91c24b84a5dbd5e694faba71ac584c1774e413\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004841caee3be6db2cf41746b560a7f28879eaa0afc1fae2c38a771bfd19827dab\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000048590a992e56c15811f850dc557638d0f5d30c995d8803fd33cbd41ff3b033c2\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000487cd5c5c17323ba006b9cad25cb0282602330eca1f9a9b32613e7fb977514f3\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000488e93ec6e130e367c0985cde94c59a3621d2ba34f0d5b1413e090995e7f1313\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000048d3694054272f5e072ef8c8e907db5e98be6e72c2eaa29d3dd6af7bd64ecfdb\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000048d5bb054e256376402866b63f25cf992c49beb7e4491f2dfd15c85a989393ad\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000048daa91d22d06a57bc2fc606046edfe0cf323090773174aed4269b1a6d8074e4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000048e993d6dbb745d056c36464874fb9c66c0a11262c19d1f2feb7c66fe428cb8a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000048ed1b13898b127017b9571d1827115457ad42fef21691e43002a2532edd6572\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000490583a6357140da69f0ea3da34b818f25fe3772718a5bdf1d3f1d7602550030\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000490b76e4f1d1f4984a972356a3ed53c681ec2d0e89b93190c772bf0ee603114e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000495d41f0a16b4e03958be9fbda45b00452ef42745eee94970dc315559aa56d7d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004976921de983e80ef0e31494414b3138aba9535546d7bc69b00c458b13bf5843\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004981409fc315c306a9a6354d76701a4df436a3cf947a26f5ec1733beb37f1231\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004a36329da5560fd4438a37a0dd356573cf703aff958459cd9638b39789c1d41b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004a73face8decb1b6f5b0a1b5d9f3b11abf8d26a6dd164bbabc606b7741068b2b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004a815989c34eb8bb1fd7235b4d8305e54cf817434a5f30fd6128bade57b1d7da\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004b13e91ced5f3aa266662e9de24c2ac5c4e6487c036141c363677d637ae3dd79\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004b9481b15d7b66c52bd6341d11354107dc14a9edb57c32a03efcd1c3b32fab8a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004c0a63e9f8df529a25c35d854937193e38fe1fda590d7944d698e51292a988f7\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004c2f9e1d3167545c8fdd29a26e3cabbfb41ba78e8754832ff7044606baf1b294\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004cfab597abbaed41fcfca61a746e9bb5d50e08a843ced4c615e45c6601587a1d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004d024476cccf4c402c3e8e53fb681b258aa64556aeaf25f4b5a8ca311f039d4a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004d5199f1c5e05f43aae1871e8e08e64445578d25c2a39e74840b25eddbf17378\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004d6164423a525cb17d33a07553bb6c9bb5e60b5b1acdf1c078ee1ff76275df8d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004da2c59fe3b9a65d6afedde05bef8950f8a6fb2028ec73ca012e82ae303e8b52\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004e1f0b807f8ec7f9b5824cac56e3b9625c2c3103dd5deac5ad5a6b3d3eeedfff\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004e226e8f4f3818d446e7dca0d641cb76eb73aa16465aec42766d666ff14cd73b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004e4120d20062b2c9971870360cb59fbc81c1c3d2d32aabca5ac5fb01439216a3\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004e559b02285c58ead35de2586f85afc4c6eb0a351d0a86cc9def0ac308b496da\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004e80be9b1c23ba829460475d9a03edbb01d8137542e06722268ee4bcfc3e3a0d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004efad24fefad0662f267ef2026294872958c85b55770da46fca74deecb81c624\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004f50557c5b955544e108b50be438f9bdfc716ec2c813b073e6404507a4c8066e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00004fc1e9ad23e29adbfabddde0fa21be21e0e93759633ec4eccb4ed0535b25b5b3\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000050392ed6cdc1b945b86940ff4bc18d9c5768e759bbacd1ed169c69d66e963b13\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000507b28a4b8d222ed6f4afbe4d8ac352a5a7be26717cb64306c20286f2c707965\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000050a66344c56d562d8c208b86d8f462a0f6d83459f4a54fd1e9d247ea7828c3b6\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000050ce7065dc8a9d537769dc0a50f420470a2881e8e85fa0c3d859983c2e4f2270\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000050dc956ac885dbe90b67cb96e0bb5553f8da988915002679263bcfd6c5db87c8\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000051139a4e3257fac0b13514f3df85eac7ab405808ee0efcb01e9dfdd3745f5828\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000512487f387408ea158a911028d2a7d9f94d7a9cdf371c631639599b76c1fb9b3\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000524d685d8b60e973ba0613d7c5f4c2376468421d7c61061764c33fd8d242c4e4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000525cf3f271dfce37b4500cc38bdd2fadb13eb103754bfbd1f56e2870b5efc249\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005267accc6b2bde1f78937dc81b518e12a30fe21bf163cb25e815babfe00a4fa5\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000527f7baf3114ab06b04ffa9dc5a2bece794e27dd00d81fc255c282bacdc8ebf5\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000531f194619e4dd3229217e043c849b4686fbca41617dd49bdfa2966698ba29a2\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000053250b956c2f32ceac2508883605e4e33b3ddaaad0121952923c1bbf49722d8a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000537679d4e171fc43d8e99acf2ff865c2688baef77b0b6a4ad183a84738d46482\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000053a7a340b0cd0f99c99f51f475641a03b84ea55794800c974d1c724fe72ea756\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000546da415c98cbe3c5a5e42ce1a8e767ad62a956db610ecc030a96530c762e5d0\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000546f7b4fd085fa57a556b8e4b476b11290b44723988cfa8b3ebd688e4a00e58f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000551ddf091069b601435999e4f7a741e96688226c345e62d8689738ab441e40c5\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000556dccb2689a614234d5c5b57256a0e7c6b986f7f06d7143c1f20be9cdcc9b10\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000055cecfec79af1975c15e0da1d1e91441c3ddafc0c9b07086e7f505d4b25e8f63\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000056b31ccfa6179e30c31e344a78b9edbbc962fddf8c0ae36256fafea18e9c7208\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000570f15106dd357144e34abf41a28f8a389b75440677d342bee5f54df121e59d9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005734736b48042b0c45193504a22410ae5de81dbc6dd22d97aeb3be95956b1791\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005784dd0362ed598c21b9271560794f4125a46969a23630aff3f30928f905c924\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000057975303b7942c9c0e8a39dd901f06c05ba06338ad1ce0dbab0c31b9fb02fbab\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000057ed60062bca20e48fdc6104e53678931a20737729ba3b079eb54d3368f84ad0\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005859bedfbe669a2f73fb22fa85bcbc4490c8cd1c3a62823956d54284e62396ad\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000586897f2013a4547d47ecd9d458af79b099284f4a8ad306fa3a1ebfcb8b8c7ce\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000058a5a419a2edbac65077193f998b9f927818e3b5f54988561370b17129fe4006\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000596626f0481c1114adc8021d4bee58ce33bcab7a0947f91203e539e84f977320\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000059911344277eaff7d13d72d9b0615f2b67b470875105aac559419f1b29b21af4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000059cf413f852c3ac59aeacab6eaabf6d4bc956ab2df869c718467b9fb2b8d8f93\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000059e46830da0a577be56ac5a330f55c63d6a5cc65d342923e86aa44faccc29af4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005a06cbd934b96b171067f333b1b3eb77acf8a2a4509edb756ba0756c6dd27ecb\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005a348cbe5356c1bea457125098cbc2c104bceeeb8d2ccf610575f9ddafadd9bc\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005ae2c36f418b6567c8c366f6272d46fef5e569d850c82865978e377ab501580f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005b0f18641447c679cfc8d697e0825e3c650693f67865793b0d63cfb0b045b1ba\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005b64334e8259fbf4e96da16f481615c1818a16c085aa98815c1e6b90f009bf66\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005bfa338b567f27e7a8cb7ea09e27302b76f4b82b317b77af6c8dfdddb0268a7f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005ca379cbc86eef6b35b4473fa96323dc9c9881d05c6b1798992f322e4afab6ba\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005cffe750dff152e6fb615eea7ede90d2241c7b21355913e7159e673a4f9df74e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005d7e2980049ef561352794689cd21b4b2a39c4cbd680f20a2b14a2cd35045902\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005e3bbe39dec1a1eae34b53b150179bc3d121a391eaff1a6403c7b259444eb5be\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005e4b343f7794ec0e3d76b2f839bbebb14c9f992ffedbf20f03d822045c61a3ab\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005e924e5f88689642ccbec30b63ed0f2df9af6652007b569cd8edb18a8e05f9a1\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005e982859fd6d36a8b5bc1d14c6957559d163fae744ab8814b1b03ba3830f2b0e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005ea55eea509b5fd289c6f3e9973c3953eed9b8e9f56d8960d4ac6a4cec7d5386\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005ea9f11ed67c1b7ccd9c3b0e9d6dbae1ea48adfa6a8216ba8f818bb72f7da3b0\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005eb2ad7f18e19bf29e79c09cd0433504ce18418d12761560b98f9694cb686509\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005f5c76207770e3dbc344d1e75707bca81da1b108632fc7f48476bdd5eb29417b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005f9549d08d6f7fcffab4a23fdd373fd00c2385004d9438649235b3cb29275fb7\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00005f970b8804d0c76c0df7470f39136d9a840e8bb564e76f7ee5fe33c8bded40b2\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000060340ba17c64ce78654b7baa5035c3f421bb34ffa026458e4b67a3c7aa49e731\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000060398efa0cc0215cd6437a67d309693674ac63e11a3b8597985cf996ac28f7a9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000608e7a634423568ea77140b8dfb6027d216f09c686454d692b6c40fb4aa5836d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000060a523d3aaa49d0600171aa1e68b568002f24e96a30f9303acf67cada5048761\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000060fc48ab9621bfcb9a5bc22da041e3a827e96dc14a081c50b060b1525f9436a0\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00006121806ce017276580006e9859ad927bb21b8caf3c3965e8420762789a820e5e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000061219685d53ec839e535db7f728e3873d56dc6a9c167b8bd078cab0f2bd9a36c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000616e641791f05a5676eecdf5421b9844072d7b4fcb287a88d33c25ba279a7ac5\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00006173581402aa60f1d7847862bf25e900270406a7b7df58dfbabb315504e5ce54\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000618563c5a5a3b0e2f90386e21e9db6d280f5390b80e6bc07ab82230a00ac09d1\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000061d00d166c910c7a4e7ceebfd5579dd10b595b9aff7bc788da17b05e7b823a95\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000620195a504f6be49fdec7d38dbbf9e82e89b93637a0b4d44d792c3956575793b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000062157f59208124c50641338bd353fea3c3090d5ca0a8c5e6b8c1172f23c3c44a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000062618b0edae7828f92ebb1a93827c1e63df5e31998ac6f3ccba371ed4aaf2b68\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00006272be2a7763a19fc6a3ebd3ae7cd9523e121cc73a1d981cb01808d0e5f1ce0d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00006388603ee941d0038cc05e2cd09b8111fca479ffb99fe21a477faa63abb2e02c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000645772bf6a6f95644b6f79ee1063723c1a39630f66dd6a70892c989b04ea67d9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000064577d9314e648e2c36e051ce39e27e3e1b0d087c7ad4a5b6664eca23cdbfc22\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000064bac9e78a6bf101d09936f8f1deb3d42d97b4348031e3b809004aae42213767\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000065e987c17b314db8f39e4267b78356d404ba7bc093abec1856d9209f4407df13\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000065f2f4c3c53b676cabb496859fdbd6ef99908f441b999dbd476e6c68017e6635\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000066130786a790153fd2c7471c31fa604110615f1fb60f896dd8818d482a6ad393\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000671c8ba6a8d3b0c2d9e23637f0d8d4f89a1466293e97da0e9a828cb2cbcf3877\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000686e4172897c233fd63755386d24a4ab4ce7d82945fa80da2aab7cea3869a617\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000068c8ccdd34ac9b9536d93c3e7b760b264c40398a9420340e5cd9f07faa60d4af\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000068d93f15e6b4255596d8714b11d93a9a0098308e827c41fb3d7ef41aee3c3b8c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000695b5de3ce54dc26dd0456f6bc02b7464ee50b6cf5b57bc08476c15c9b56d3dd\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000069c89ae12c825ab9151279164fd822e55082cbcc6d11a35042df2f36915200f9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000069d8fc2742e4365a2f4ffb46ff87ca7912bfb0816d1bf9e8395b676798e6b02e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00006aab16c62c036f21797ecd2463240af9e0e056a01d0558db43a339d11623a1f3\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00006b37e463971034a3e5940a13ff6f9967c7fa4f1226c255f915d99cf03d143bc2\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00006ba49894f74ca633c7170aaf9e1ea821fe4480dccad5a875dd7741b3ba9a5b0e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00006bea50c06f4a807aaa563b03a0770f8bfed82513b295886a002a7d3cbbda4e5d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00006c53bd4f93cb94885716c0a3490b776c02088d5b5d5d289e26c9bde8aa0c6a21\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00006d20c00e853b9e29b652f01bece3cf155fefe97ce077476322c0a0ec45b6b98a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00006d412f2678d6c4d51a1ca51c541ec36120d8d74d64fb6d73e977451351fe23ae\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00006df4681aad57b52031cbc61e5c4dece667193397688699deda8a5e255d2e06a9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00006e11a65a6e9a50d451b39c876a262e5d8c49fef06b415a8cc13712194af20282\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00006e167d3a397b8050802ee6dab23eb0cca97d87ad47e5c438ae2a29567d2fbad4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00006e5595d464adad0ab5822b19518f1d9ed9356758dcaec8b31f6ca50b7549bd9f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00006e8e9e4593ff8bbbb50a01fec0fd736dc0e8f06f0afff69cd5e296921e816b83\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00006edac4194581809e8198722bf619c081785f17987db525474e71ba2b22f18915\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00006f52d93445324c1032942bd354b9d8030623d6c84481389648518a7a00de0655\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00006f5b7bd725a8383d0b7415d3648de5d62b2568ca0495537dea5b7412189b196c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00006fd017d5a5262fa1edd0bc407aed9fd5d50f41ad4cbfe2047b7515d8eb79d5a7\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000708f9fa8ae5772ded6f1480ce3ab2ad67618c7a4512cc22d266440840a762cac\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000070c504f8fe5743011d4cda7caa1ce4a043a1f909c007cf706b66b32ca46d02c9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000071f4847549df514e5a54db3efbbbe0f459c13a752c55c82a7c41832ae1e6f7ec\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000072a15edda82f5ef3f37b009986874a053bc6dde024eadf763c0baabbc5cd71ee\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000072d05010f9a26a2899b2089ec488dde6edca30448de6307b65a5446120153732\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000072da6af66b57adc62070ef8167a095fef9c839bf9ee42d940c53fbe789b2177a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000074c3bc3554d40c5ccf71f323a9acd73a7fc96fe03fab9df2908f5b25adf5073b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000753f965a4cbf410f8261d668948aa01beec5e6bbe9dc4cdea9661a125f5fca67\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000075590a028838bff28bd04e2fdccd66b8a2383198e52464c635a4e54138c056e6\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000756aca4d147715bd0d630305d7c9c7ed4aaa98fa088f1af8181b4a287fa78fb4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000075bb711aa7f027f0527591e94757238f263ff03cc3cbd429ac41f1dfc4b1a96f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000076193e481a77188403d254e9365ec9a0ca1b4e3d6ff414e4136b38f6851173d5\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000076849817a1f285cb9ebf72c92e586807e9d0bac7dacd2d9fc1459c49e5da2dc8\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00007701aba4ff2a37affdc0bf4b5a2e4be57bb51355d7be32f2e1e8bb34c9b9c8d7\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00007703aa87d4f8bfaa79c48c1dd0ef9eabed04ee4911545b01eb0bf977f13a7514\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000077838387be17bd2cd89f1822912229ce25a99764f6ef63f1e01fbbae9a2fe93f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000077d6b43ea428e5ede6459c150c526f024b7925598b17e4b7e58059615d7021ed\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000077e84498501385d6a747301b27c9cf17b2d02d1feb29e17434c482dd3f2646f0\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000078abfd1dd32c610938351eeda4c05012dcdae818855403063227e15e9b3bbe8d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000078f88ffe2d5522b7a1f32dbcfcda68f15dc220d1f98bdc343935069a48d47553\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000794003bb2deced31c0d7d0b0b8638d372dddd9dbbd4807576cdfbb55861fbaf3\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00007999978d585c42535ca8e3b3a7d53188d48573f0025453385e0737899ac098cd\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000079ae395693c153c2b21c8203f69cb700fe903881b823bc5f74fb68b5422a5146\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000079ba61a4199e39069316249456b2094d15fa2b3fe90383cd496c087e726722cc\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000079bad75b4efc12b897fe00c8a28e4034fbf42672c05a522cab1086ae7a343412\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000079cf60430277fd33d95d25029d43a601e11bcfa67c521da8e82ef08141d8808d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00007a023b7551828dccc00121ea99245714939bfb8b9790c80d40fb47af6c5f4a27\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00007a77271cbcd156b1ff21270b25a8d38915fba6772b33abd567ac27b35081bc59\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00007a7c7b5fe725d6f718082ade299fa84c9147aaf6e1006fb6c127086cd1119ea6\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00007b116aff09b711abd0436df58f3d28a0acf386a9a7d83c42f4a68ca655dc98c9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00007b51c83c71d751173639106f3b01e849ac10cf71746ef3e551c9bfda9f96d4cd\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00007b77eccea6e2f1934f12378e9d6bffe023b3b5ac20ca68d8575cd7087c812707\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00007bd04a83901234342dd40a7fc89ea7ee2324abff913b99f5782bcd0332e023d2\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00007c12e7fca17eac2b702c4f97717ac1aa2910bd5851b4689fa03a47a849383f67\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00007c268d2820f5ae566aeb2497321a3d4e5ed819a2b07cc3750855fe5b02db574b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00007c459ade40a0635e1b0ec39869d2e0a4217110abf125d322204b4b922ceb8ec8\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00007d0bdb8efc02e0b2fa4ebcaaef7ac285411dd7ea7b6cac670642252608bea5da\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00007d4b43910cb7b69585de9fe92f80f73a24f06f9dba633e64810fa684803e541c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00007dec5db225a71256a2295c650bc16ed79527201056b721a4076191282d58e278\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00007ff95e680eeaf8535fa6f49fb6ed3d9bc74b777d5f8b9117ec53629343e75646\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000080a6f294a71a3853c0fbcbcc78383abe6cf11dbb098e64a45475feab70656a98\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000080b105a9a123282e9877e24250e1617c6e6f80856fcc9c180f66f588cc9b0c0c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000081194da8f1e5459992cb41e1aabd5452249b9fa93348b8dfa7c181e435482f41\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008144dd3888e923b130689763cc8edcb3772f03aa4523a0b165765c7b3b5b4c67\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000817fdef74b4e028c06aa4d1c06f2f57d3c2906e7bc850fafb420bc6fbee75fa0\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000081bbd043deb299c1831ab3bbdc1c3080193b1c973d9288283dfb930869a3695a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000081e9fb69a14a996d324089675ae2d7faa3cbe99b0dc84070a44168ea99aca0ad\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000081eaf7b4e6dc45f68e4f7bed818733e75f77575973c232aa97685fb09ef1d001\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000082633eaac21f6606d76dd0abd22b3f8358c6da07631d5668a16e069250568db4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000829232dbd4baa68ef816b475f9fb8f53b352bb6048a5f8a8f604125efcf89852\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008295b0fee8efb70922acf1b4c6b12dde84e5dc7efaba5b4b29a6469859b278ed\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000829c7a6a735220ff879ae9d579043af66be11e24ac21d645d2ead7f4461c6bdb\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000829f4ddbce0823b839c920a863f43d592f1b78d75b475a80c9c4d7b7d6fa6d5f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000083193df6553c45e676105a99647bb6ee39a1bc0f90eb049645d55e49f2b72f94\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000838ec0dcb64984f156c0f8e91fede7947c2de06c44bee8c731842bfdce365a3d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000083c3ca0b1863fe8bd62002338cc4716505c6bdfa85bc5480f28a640c01803724\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000845774b23f9b036e1fbb3ba8d814d278f4bfd7fdc9f3ec6b2964da2f65298145\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000084781c3e4b48df28d8110676ab04c07f4b4b6fc8519f1535d5d3506405d8cacc\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000084e52b99f09dfc3b861845c136025747ada55df1f25dc08941605b96ff92622b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008549079d2abb58b7d44877cbd74cffec89d60a04f5fb1fc588240eab95420992\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000085bf3a3aabd98c6a4190464879aae0fe15229877aab2fae44afad884058b7c1a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000865a72121875fc1294a0c69f4f3be5ffb1f2489cd610153496c45f9a0044d59a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000086a7ce3410b53e1c4f226b53306a3a95069234a345b3e572cac0a7f90b4c91de\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000086ab1cae33ff989bb5617ef94704d136ff5fbdae01403cceb38296306bb448a1\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000087627c4720a36c54dd66ff504895ca02b0a5ffa04eb9a026d37a2e744b9ec0e9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000881590b722ab3b7105e09d958a8d59dc88004ce525fec592eb8ac7d8d97d6e8f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000884a64607eac129fdf548823dd41120fdab0357cc734eb9ebad2c674877fcf05\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000088ad8f727e86040b6804461a0c6c2aaf7d8d298898b6fe88ee0eb979beff2b9b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000088bed7fabff38192b0ba1f7dd44ea881e655b9ff849804941ff8928a5f1fd87e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008929bd80142f4404c3ef9fe9bbed16ba824384474704d574aadca3d8d627d3af\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008953cd03af5887205266a36ac07798abefec57e9bfa1c05e0f5bb3b9743f0c16\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000089655f7877055e7d65cb232caa3856feab3ecdefd494c8ab38434283ef55f23d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000089f4998ad7508683d4d0881f26a5ae4798be1adac75d5f7f2f74764d169783e9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008a272dba7aaa6aa3d55877288b77a9eab0f491de64033ed29fefadf878ff0fe4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008a37e7ed127b0a5c51e6803d02a3ac68dd4f3da3106f5045b8b37f37f21b18eb\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008a4b71f8c8cdf0ffcb0dd227ac8e3971b9a231373a1ac7ba0866ef510ad2bd52\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008ad2b14eb408ab3d853affdf1c6e95cb5f3ed92a0a68d81d632c1719142cb368\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008aeeab7117308d346267d11f407408fb8b892365ae1d434b55290150642121cf\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008af7983763503df109108585c40faeddbbc15847b3f1dbbcc5a861987b80768d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008b195201fb2723e2b2a9da325d7d742151a21b78dfb326f68ebde8f858c8758d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008b1e3d11a91b4213af47637110ae00bf47349e05a5bc23b5d184355a21ae7a4c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008b25e535a90464b7cf114736e6c0f1e91bb6772473cdb85f7c4fad22087b85e5\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008b5dbd932519db1e3685b479e1a1419b975918d7397111b3345f929bf59921cc\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008bc82c56c228e8fbb1b2fe77dc30db133e822472f0fd882b8a9a018b475c517c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008c7aaf08ca917ee195babb154191fb329d8117d43c36f55510047a336540d71b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008cbf597d0a233f0ae6e291a4655c9e716e5025b27dec2988f6e5bc0d6059b530\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008cdbb8f21ca67f541b8e89f595a70bcb3b6b10edc42591383817f96a512e6e0c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008d3d1fbbdda68c8796d65784de1d4debf1891fcf19b44583cd91e86156a293ae\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008d7f1d71ca52fa383c2b79403cb9dbdf2b8e4a3ba094a127606f76de246a164c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008dd2a4cf059d313d9611fa20d5320988b73e5b7a9f2dcc9463b88b0aefeb0fe2\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008e374abacd6bc60684a1e97f6379f4198ee117f636e6a7798f25f2d434f7a909\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008eb342ee7ac11f4cc445bd778e736d9ca7109ffb09cdacd5444c24be109f9d50\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008ecae3b5ff2df2650ea79307fa8ddc79e87dca55f375322e2fe83b5da0a3b856\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008f1ce84c2dc3164b43687ce8e235fe872d28591b1ad83ae946ac11a8711bb40c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008f2d75001747356aef8ef873562f98513c8be82079b3c9728e6796347da34cb0\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008f347317635357b5dd321cbacd103614c595239457decebed1bdc427ef6f7f23\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008f3c6c9f603a74f9b21ce9521e9810a39e8b58aae0cd9a42c9e6382998780884\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008fcf019ccfbdb02f9d6420ebbef885ac73563bcdb6d2cb36fc1195ab5854a2f4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00008ffcae24b894de5a6780bb3ffbccba2a619903eb32025b2a19804cf60049ca09\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000900af250b3985c9c141ddbd928d7bcdbb87f5f477603f03076d7966e8f71ae7a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000090280df0840269b05a4c19d491dc74f7c1e82d47aacf4ee3565b82fe97b4b8e7\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000907e0569ab0dbe4193d6593327474354f9d94bcdfcb4cc1d99e416802689edbb\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000090dbcd818a82925ab03ac1815533f96beb73dbdf0750e149c8b76ab612eb4bde\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009101ab86dde77142f9e3e2d542dc20c0782752a964da7999c4ddd6e2e74a8f4e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009146dd7413bab33e049f998d0d54ef5e59123b02a5c6b732b39d570a06f083a4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000091e852f763bb6e782c4df8c14cf163e0bf0694cf2b156666ad3bd0d93bfade78\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000920d205e517976b8d147abda234e5608851ca546bc3f7c891b990902750563cb\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000923326fc2689d97b2473cfe2dfaa8ed93ef729b390a6c432fd1c2978a45d3731\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009294e74566ce53ea21717b2fcb73d3ba6142f18be79fa7ea381e5be86d259261\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000092fc0b6ef1d988f698a8f8baf47b464cdd1bf8b1f8373ecaa905cc760a3866ae\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009332455eb667217b041a2afa0177d15dc6691ab122508da131f7327d4030ddc1\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000937452daf6a85edb76eb7f3ad0841cef6d73ddf10c3742bd7a85ab7a9b14b441\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000093aee7f7d0282acd8b065f1bf321c7139764a4bf1feb9c4c1a544af3e06f6583\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000093c8460ec044a756c91263670c53f33c670bd5b920e5d4742baf3f2343f942f1\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000093cee93b552754bd464f769bb6490669f3dc262c5903fe2abb14a6dedf56d70e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000093dc4dacdc4a5908fcf5d5f21fb6c7c6fd550fc8c61b3dbbfe4a33994e4c1abd\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000094433ec5d52ecb69baea66fdb54fc30c7234585fcf2e01bc0508f6a1850c9ea1\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000094522e622a36471fe84738a97883f9f47fc4034a331037225858b60a1d935258\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000094bd88145df61dde3a61b0bcf863566815c765a79cb0b25b58c623255b5be14b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000094eb5366bddab390367bfab8a73eb51821cb63b70b318151f7e0977c550062a3\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009535c88107904e5c8dec1b87ce09e4477860599c21c8dbcd60fa44c56541e284\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009605ec19ed44a3fd2e0c854a7158682fe7709309e15daf71150f1c6a5f4975e7\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000096581b7e9416d968d967c8b17d8b5f94f5db43e60b6e61a3864c830cd4689319\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000969982f2ef219c35d524abea1755823867781865bbf9fe0a9099bfa4989ec2fa\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000096ad95d7fa6e5f525b13e28420fe49a5a163405a7d8168846935bda81015440f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000970a7bc55cc643383b86b09bb264a65423a86de3fce9185ec9da66d27c71c3a4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000970ed29b747caf02756c821ebf7bef6d1ed66e3594d7010ffa057ad819c673f8\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000975c46da7c3a9afd0af36139379032ca93357e3cd9e67249ec163e8e196739a4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000097c5caeb174262d84ce90e11f2ef80bb9f3d36ce9cfd1a108dfd43da644ed81d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000097fe75d324336fddf2db80c3fa8d59a1fe19498f57b2d36d5a5d37ad487964cc\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000980a1a0460247d7c7a9b7a777d39cd02694a6cbbb3656f377dcd94851883f97b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000098cc6d6d71c021d6ccdfaee5e377f8441ceb66c2c4f509179c0059653fbc311e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009936d255ca27b130d49ed2c08ac795fdd8e1b34aeb6b58f04bce28e14e5c1e10\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u000099d4c82a3f5324a314fe0f33401ca10c180a11ad56e49b3d63312bc6f7859c85\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009a4d90db2cdb16be978846a9055c56ac5cf13912c802da04b632dd239d5ab487\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009a5083f78e6e342f6818425645d512c3704dd85a6b81965ff9b422e7cd2ba263\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009b3282da6035e6a6bb01ed50b1e29f1c8e7810d555e7a9c5760e2ee66d5d3109\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009b5a965a8d8ba8692fe494d67b8f66b4b35f1f321c573a0a26872420de20dcfb\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009ca58bf4dac6abae0e835863911725bf11ab842f268666f6ee42acbdc4fa2677\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009ce66b1b252ffb1555bf3c03ed5f21f667624cd64e438d49a03582b4bba7943f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009d286c51ac4b405ee0ba9ff06035f71975463c66f62f15257b350135c4a70c46\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009d33f27e404dd60981b7c16dedba071f4e1a4d95fcd2220bfc9f92e941ac4c78\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009dd1ea3bd169565971b8cd9920b0600539c4fcb5037c104ba1d6a551c12e0d7e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009dfba308f2c498d6dcfd081b9715ea657ceb5a6e93f255a8b42168d59b90614d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009e2222eee3414fa5fe5867e59d349c7cc07bd56d4aaa4af5b2580ce30d7d75ce\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009e7afd8acc0b60b9f5de8af97639d330780318a7593fd77ac88b7cd6dbb330c9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009e7e0df520b9ff316c405b26562a7b9bb0f003b4f82a896cb80bfd174ff544d9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009ef4eb01dc9b0f1a4bb83412c2276620cf6ca74a3d525c361da08864add1e694\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u00009f98691de73564c6903527e621d087df5dd57df77fae9383b69d29c301701769\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a0820dcaf85bcc17af78a338e0afa0136a92c521a289f7ba0f1e30e10bb74bd9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a0d0f027043c76ea766231166df40a3e4fd3fde364a02dd236b3bc2ef6880761\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a10ef95bcf2c63b11042715a2db03f98485da875396f52473a8977f1912378e9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a198e860492378bbf779b9b8af2bf46aede3967563d5f9268deb47234d3f61ce\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a19f5d3036c16f97785ef1025e4348435d51163356663cfdd6535aac2dbc10e1\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a1d7e6f9205811bf048727f3ad9e7087240719f0011b12810b39aed0c2d725ce\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a270d0662851b4ef366f5b1ff4210b00443c5f6aba0e3c75019d42943ef1e8eb\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a2da1b9abef91b3ae6067837d5d7f3ac68f777b5d9ab6c7244058b6c1a1594f7\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a33cb1518f773d65d908dc6b64107e20b7a7fed13fa791e8e76cd9a9c7ba3f48\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a3cbdd709a693d3bb87658f6e1806e6939fa966d81ca715ede74db1825120288\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a417d7faee77dd16f39ba32a0afde4e3bc47e171fa310cbe8dacec03f6dec823\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a468c15aad4b994d556046a8fa83a092cf733742ddf61f1cf65d91d2356ee555\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a53cef6c00d345f08b75c366b2f0ba679bfc7ec9bb75c08e5a228a65b97ec427\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a53d84df3ee6fdea5a0dd9ff87ee2de850b17960cc96d96634dcca70690cc831\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a5848539e5ef5727aec7e8fef773f54b2b9b2254e91047978da8eaba4572f4d5\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a5b2e84d5e4cce32d5b8e2a1c26c05da7f5046587e76bae020e5492e76d275e3\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a63e1cfad596e5b99b6df346e6e6176f8cbe80db9186a890c755c6098be2e0ec\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a660fba56ce8eaa079fc5a3aef86101cebe49ab5c48d47248532036b33b967de\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a6ac6a46aabb6bf42fa6561fe1b9dd2d3249481d9978d0f562676340b40c04d5\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a6e7240b7d9ecd21123bbf1e910455bc0a07d0cab8386017bfc401337c6f816c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a6ff93f4f1f1beb1315a8e6ea973219ab4018e9562e7c429ecd29ae0b65a3ecf\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a77199918ba4a2bb46362c30f57fd491151babf46a3408dec29cfe99b433c4f2\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a780c1dfe3fc51658afaf0de5fc2a67a18bf721a03effbeb2ab31b236fda8403\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a7965a9e10ccad10abf590c2735f238666d13d683f42b8d1c5761019cabf85de\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a79aab138c94ec9a45bde2d1efbc9d8bd9e8b2a039bec2147e7aefff5d24bb01\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a7f0c695551f30ba8ad605b531519585ca9de3e190fd7d6225e06c434ab45edb\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a86b8bb7df8c95e6bbd73c8d80a64f2fbf64a1ea30b3b39952aef25a5e795a8e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a931eca40bb20acc7bbb72b274a4c721e6fe12a3b06c1f379a066d48997efad5\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a975e9820815650482c30be0ad84af422e80f53dbce847de46db7dbaab56a547\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a99310a7a25c77d6a32ba2820f2f1578e074f8011133a9d2974f274d4487488a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000a9dacc9dcde325e6b78b4c236e94cf2b97d19cb85ee99baa100077b512871336\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000aa290eb3890c48b8e9fde40c6366784b1ba43674da99e9709b05b0ecee7c2ee4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000aadde754bb0827aaf3c612607ee994f2bd28074d4d242bdcc171b99ffd79b395\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000aae47553bf6f8709f2de70ebc48113210024dd3423d12ba2222183006047ac4b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000aafdc624f513e866cd1b8eb29b43cd35fee16ba827f9c25269a3b8f2de755bcd\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ab42a2689980072db801493f183e3010514cb02576524025a062a7f6fcc92114\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ac1a6d41ba99a9bd53516f5cdd9f59d76d189fbb6ecf2cb5be6de7a5bd457340\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ac589a242cfda2a7f96788d09cff3669c67bf87210e03bba2b2dcf8c55e71ceb\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ac794adf45bb4d5a096351d4f8dae56fb4c9dcc7d64d544d3e8795a91e5ccb59\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ac96c2b05044d84ff33a931beb05e6b3c1ff268464aa8871aa3a67dbae6acee4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ad6078905ff4f8c9d0eec3e0a61efda401170655792ae4869ab3efcaf0a49568\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ad859d3b7cf2d4b5cbf2f63fc22581ea5b19a6aba511fda0333467c8d95ea0e1\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ae1bbe5d3e36ab2cc482360cd7d2573e6a65a066ac84feab7b8bf5dee3ca4ace\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000af85e95bf129ff57e308751bb06d12318148ad11bd054e04a5a5614b86720a68\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000afc42de1ee1b0cbb2a602ef4d117c00388c8626cc2160c0fc39bf1255b38aced\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000afe77fac18f4a380d3798e68f3ea8580c06abf9d9d2039e15ebb0465988f2f40\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b023d46de4c88aae732a0ec5389ac5a426fea342474d18f6419abe01e8f8a084\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b0442b0ef33d7d84790654e1471b559eb1cb870ee1b40ab88fb94f37d06f8151\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b046008b96f328a0cdef2e60e00eb948c9c6693cfe17d01a24cefba51fa95aa8\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b065eee430e7d27e7715d823983bd5fede043a4b86db1b0d387a16d2031dd75b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b0c0cfe2f3c044ac5d942042374eb0c5903041677b9fd48bc99c3d0566a5690b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b113bf852b5f703033ed83172216224aadfb890daec26cc1c89fcab6f6f57496\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b1304dc3e8e635fca9134651652fe49b663743a7b9064d4db309bec471080dad\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b1336fc034d0a00a43c371a98da44a440129b68b02c89caf1cb88fd60f578cf1\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b1538fc98ad894f1bda4d838b3aaa5637fbf9c0cfa15c7bfeafdd74b7ba99834\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b1a9c1d4b40ec5377f8dc430aee02772a3f15ba5f69f91bb31ac86b0cc0598c9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b22a973f0350eb0baaf19f2a73879b185f75a109ec322c8c6edb9a821192f49d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b23867c384c4f8f752d8c9dfffa331879bc4d390ef1b20883e74bde5632a5e1f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b322838dae25e265d705e15c9a414f2bf880472019704271af95161e9a107c88\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b39d0821ecbdab632c6fe4b568ff82238f29d6f4681192f908f3f0a8e058bc69\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b3a5f1b2e524cb01c98b018bf80d068fb78cee2dcad5755169d7b574224518c5\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b4124d4d15db34628ad086c14bff85cf060b37c83d79191f4e9101572e23ed99\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b436f5aedc386142c164869f5a7558ff33c9667df17a33b90f49df854c71948a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b4ac38d6cbc8c014747c55890a6bf9a7b49d184282e63327cdbd6bb1c27ab1bb\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b528d2d70b44a48a9b3728ce654710028ad70dcad647d193e8dd8f39256481bd\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b5a10b3e0c33e6ab8e9032569a26b31f1da7a6782b5719f31877055b85bc7be9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b612c9fc474bf5fea4df3492955815bb867486e08dd1d9435bd1bfa42aa31fb4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b65b778efcb68504491d1f567281b9798101688b903ae929195be4e9fec8a27e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b6a742b9ee248ab484711beb628da130cabf659bc6bc1ab6d170a81adb2babaf\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b7419dd5fe148a5aff02f0d37765dd05688cafdd8ebfcf24fbb63c5ae1ac3e83\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b759defef6178603ddba91ed89da9e922f4583aa20ce41e960e12e3437aca381\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b7def663c9ada709727804bf59ac92f0b60c3f9ef32abd514f824c069cb57743\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b83ab0135d9b5079bc70cf70328b39640bfdf65f51df010a9b4971797a21fc32\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b91a1b21676e5ac18d86d26cd67d8a2f4aaa23549317fa62e1165ff7c523d766\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b953aef40bc54fcfa05bc12bc095fd869eb1651d2126798919613a0b0c9619ec\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000b99e5288e5900073810aacd7dadf8239728e26d4e1222eb89399afce1fb0d648\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ba9d58977675708dfdf03bdf89d84f5255b207cdf1cad4bd6cabc33195fd1fc5\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000baf5bff74b7dd60968f88873a711cfad7091aeb7fc20e0127150d8db3cb3e019\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000bbce0e17d44ad28c0d3604cbddc72d09446ae23dbe21820e187bd271b0be3ac9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000bbd9afcd2ed5c3fd1dfdd5df975af526e57a44aeac39870b371f7e3c2c558639\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000bc451ddc163ebda6834d270e3cbe2241d0db2cffc79f26fe6414b7cfc3ad9550\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000bc6e8cfbf8cc9d2a543d042abcf9a2c21f57e24ecb01083c18f8a807adf38e3c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000bd6b1680a00c21ee446c2156f88c112ee3cf62d4e0bbc87049e131466f5caceb\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000bd8682cdd73b04cc6756e3e2c102ca32590ef1ce93d22d28299711bb19837278\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000be2f549d5636b68955eeea30a6d22751c93385a7b7499f741f739ab8011aac59\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000be481563b8291520758db5116f6c9330c85f2dbbb42d2c08e25266474b203c12\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000be607944ed6c4fbe533d113474552e35ff5263f710e3b801f8d58dcddbb47ad1\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000bec0e6c653d5b58b766314c1f3f15fbc0b1c15b7556c6abb63a59f78138d2c98\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000bec2087c242ffbe5260689f6aae6420289d17e0a612a20552f66e9f57ba50c3c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000bf651847452f1654b12072c17dd6cb200fd1d46dad6b8535fef3a2d10c7395ce\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000bf80a0d069bd406459907c88d358d60c0c0410887d6ec9cf80acc3a69931c221\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000bfa3245bd3cbffee9a4131f409aa7dfcc72d355ff5964f005c728056b6e444ba\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000bfb0e13e9bf806883bb7d278ab05500d13cbeaaaafc5bec9da49677aa1f36f13\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c003ece18cf82895ad21432f8a9d066fe5728891fc11d20bf5ee9da624f34721\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c02eda66f47cf445bb5387eb3e4e4f633a0d6e0d4b45d19ff857e3d74b7c7ef3\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c1a9c01c9d9b3ed58e12fe680c00b2070ac95bd3192d5c397ac523444e929862\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c1ef81b33c00de4e3962ef98806e2d34ba01b6f7c4787bab1a504510c3390f66\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c2bf8df02f1b4dcc1b69ccd1b8bb6a84b5bf3c588391be98e274e09b203e934a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c2e12086a7b1755a7921e7974bdd678f2760aaed13e9b4af15823acbe78e7517\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c2f9d435920510f05e43f356f68cecaf70a5e399053ea5669b682ec3b623e89d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c34860773662db91829786b6a34cea6fe4552dc8d7e8b652b339759adcb96e6c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c356d72341bc6093ea7a615382fd9ea993196acdea69988f1316296120b5e3a0\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c37ac7e5f17416a8dded847f6f1c34d375a829c0cdf2d8015324a0f8711cb268\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c3dddb90d4b8546ac5e4a64d4cc8143bea0409ffab89dac61631d5318542bb96\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c3e9e8d6f0812e0b81f80f7f42ac0b1fce4205ebf3ec749e5ff4577cb7f0b5b4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c41a636e066b5e267a3fa806e0468f2929eac88bbbbf282098e25584c23aa506\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c458f6ca8c6deeb1aea508fd0cd9164ddcd14939ef2de3dc831775faa99a7dff\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c464ecd3666a1021f8615cf3aa4820a9631e6b6229aa6f2ff397ab35a8492730\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c4c85d3081fcd1ea707852dd7257317aae0a83885fa48adf9112d1e879bbb714\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c4cbe4f56473a17197051ef9b2ddbd046996745d075875936ce13da121ebd871\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c55440f04cb6bfdb8b119e94d49a3097b6d97ea52ca327aaddd2c413dd28a575\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c556efe2c97f6803f26ec48f8f0b76e24093a7dea04a95074f2b735f8801c8e8\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c568c5ba140d471098e97e1850aa800d5b393361a862ead5ce35de5875614c8c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c577e26cfd02e8affedbb2281e7e7ec01644903667fff60443db2a2dd94a4a99\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c629cb7b9ca12d3377b6a11dc67116f64c8369fb50589e7e00bf442e410ca348\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c64b4d6fa6d9cd7358425f26c3de169ff603e05b54d9fe9eba03921baf34390e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c6bf4c645b44b43536efe5260fc88e0dc5ba3c4f579fe6206f6bcac7c2126233\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c7d0d050b8c9d23954aedadd6bd0c1c4ad0ace86b8d9372b2c33eb8ca327eb15\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c7d4fed948daf077828ab4837671ce1babc377db46ed7881ecd4b46a90fa7f4d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c7dfc9021f66befd357aa41107fb7e933a8257c8580ae28321c5d7f1506007d8\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c7f5cd508f28e98a24610eb8befab4cb645d4168e202e99deb65b24ca1860717\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c7ff45e29e5f07279414615ccaf6376715839fda4b29dbdc9419fbc972646c28\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c808315b7dab0932cf7d3dd1089ebd20534a6cd1c1409051df3ff2276d309e5c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c828dce0234ed6b6104f4fd5c8e2ad70a2792e6539f105eb83456d1630f0174f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c8474e4f54257414bfa9ba39bd066c6b3bc94c5f4ed1681947de48f700e2ddf1\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c852ec6077328536953c2d5e50ae1384a08cb8a194e3488f38635468bf19ed4b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c88ee5b57f506535b2a0bc14090546839fa4e471c4db52d912bdebe3bdf5e313\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c8b600c669b292745bf5662594fe5a988ee14084023813c3aa8925cffe3d3d16\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c973a5c3434ab3a2903d98cfc1b9431529136e1e36d63efab7c0f4b306624368\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c9d010ed95cf766d7b7900e85f16ebbb33524176714dbf5c7e42a4690f9d6f45\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000c9fd4c1ffc0e3874410980e95773ac326a656d9f4c6435dc81d545cd45b9a0b8\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ca2306f62199821560f4615f9bc87a8ceff3183761c34ed3f53c3db5be72c37b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000cad9c9e11a26fec356f3f92a7b32dd722556307e1a95e53c68781bcc03d8f4c4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000cb4b525e5856393e9d745a42afceecaf2ee25ee15428442668f501f845ea74fc\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000cbd96c722e76a33d8ad7afb92ab3f74c679f892f51b3acb471e5de1ddc52347e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000cbe515bca720d9f84d1b26d7f6f9652cf976c4295718ea9877aa156cbd298b1e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000cc045c37c60b8a578553785f5a651d899754a4480f14c9c4a6f41749241cbe7d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000cc39ed544f01f47f17ca1db397d47a1c6a0e5e175841aeabf05ef9bc08bee14a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000cc3d41ea193305df3e5bee9a3fbaaaf9f30d896d1468f91428ae00d8e3f92c37\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000cc546410b02a57323b50d9964a7b911feea9556a1c74239f1a6f7c3668bf6c7f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ccf77a9a6636c6cc1c077b294e85ce550cfd666a56605212216ce1ea0a337ee4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000cdd32caf77bba71201a832d473750331f1638a4f9a601a2355b254eb2c70d842\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ce10fb2cf28ed9ad58cbeb6f2210cc3613772d8809e3ff60ee2ea00151a08697\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ce75351588b79ec2922884276f1efd09b25a8f11687ec8ffa504ad295cbf4812\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ceb72ebbbf1cc07fc81079afb8a36b16bd9ac3829142676a4a46fffefa330248\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000cf065cc6cb3711715959530ae0fb2f6c711ffced351aaec451126039da0e4ab8\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000cf1667930bcffc6123d7f9a2ab1cf0f08cb457b7caa56c8b6bb132bc3ad24557\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000cf598a6518a57620d8b2476d26b049f8e25df74384cef53ea011df9b4ee3682f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000cfbce149120278b3ef5e15b309f2ec3e7af45c72c4b3809b13e95f118cf29299\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000cfdbda699b105bf2271c4a34c5d7c69d9b8e9b6d2d5dcebf480d857a1cb92186\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d0328c3bbba7f3c0db540e80508c271e82ace6d1477e3a3e48aa1984f47559bb\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d043a0bfe23a17c248cdb56f37df2e467c7f01c137f9a03ccf2c500e683231ca\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d07a881d1f8081f5379f82eab9dc9bd0be5b5582e656ff0290d9b16bbcd51ba5\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d0b334f67b2f939581592dc3b7036894dc5009f830d724e19c59e1c848a1ebc7\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d1772bcd9077cca23b2ad9f9ffb27669e2b465cdc6217d61e9a24c9135403ef0\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d1b77d7611ec04695f29972ae0a8283be220e8b19a522406e2357263058ba846\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d20145b4cd0d699b77dc82a35311e2874a3ab2ecf673e372c7272f3830199341\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d223c74de41beb0d12200046cb434b150f730c0031bb0f15d364392a96dd24a2\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d24db43f1a5a1eca68aed7f2c88c776468d37ca39f9ea3dbb1dd6f12599d9146\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d2c0ff40b578a43f18b289655f65010952012379e8c7653bf22dbc0fff319a1d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d2c5ff452c7928b6c52671f9517c19ea5d0596ce5b408fa54a7e054f40d05a3a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d36f19fcdb421c671c0d2ea5e7599be7520871ea4dcf92fe0d514dc8cf7ef562\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d3f9fda1928ba3d0a60a3745bb2d7cb0327132ddacce10b20f88433d27bba8ae\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d40d065f4ff8f8b193006759619c154f242317fd279fe428b7646a499e8bc35e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d41b07aae285d294bca4d1c92910c29a5b1d2eb4b3e721e82b4d7de6a03aded4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d50f27a9c27f2a9c03cf07e6a05acfcf69e1f3d2c1082d0e0bba3c5aa39265cc\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d519d4e00600499fb7bd8f05f9cc447650e9389800b15f18340af612baad3dc4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d528bde50e90253ddc62a50b0ba2001a6aaa3f6bb74bc42c4029a1fe0b156bf2\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d590f59ab2c046352c01dbb13ae9e414122b3dca75a397eb8dd045420b78b38f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d5f709f6d8d8176da357d6f8a2691f0203eaa8ce512cbd707dc88d8208699c0a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d652e8e18d732df9bbb8f82b463af9ee007286c491c65245520e456403fbeb0b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d6aba8f6f43b23640f07be719c4d2693456c4df170e23feb497c4740aa33a018\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d6b4b49b373bc3e3be5a8864ea36edacdba561778964ef842849989db5c80914\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d6bdece662e0d9941e77be58881179930e1c4874191e973025a9ecd41e68580f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d75827c08a180d2bcaee3a48d9c664f8c99060a6df46693284c2895b8c5e646e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d7675fc5df4228131fa1e2fb2075bca0fd2f68ace7c964a73ab7a1c20e0fc4de\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d78b6f4a1df276b0a0a418dd0e38d032aeef0d6d23e52d62301dc1a2e93f490f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d792ddbecbdd3723b0e2296a61518e684813acb1b35bc727f51b965a986ac26e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d80cc13506a1c425aba53009ec3ea79852c6d071cbf614d3c779dee4503eeec4\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d81e381d13a5c15409b611eb0bb96723180584cd3c74066da9554dd111145d6b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d82cdbb0ec09b4e7b6835a284f3228071cce1784e6fa3a53ac57b986498dd398\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d83c4b49009496d8161fe0deef96197ff3e590f567648bda5b995f1ab4825900\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d8b5e89c4ea204c4e30c4c9833c6050e559cccd845cfe3d33cba13dd4a507553\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d8f9a414b7e71b91340d5517e0b165fe064cedae9ae16aefd51a0d87e0b55fe6\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d91f590b01b44d4da4482f0f324e0cb02eb070129ce0014d31b5eb9b51107492\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d9484b3dd39823d1f8c9dba7dd178ad84fe69beda2025b2b3e399f9c94908ab5\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000d9ecc256d29c537397869e51dff6176e577d16ad317120de0bb598f685fd69bb\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000dae155d5f8fe3f4415e30df2c1594c58811274619c3bad2a28e259d80e6afb9f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000db3c66d509f238b69e11b54135aeed544fc86c8a3cd7def4fdc3354039a49f54\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000db633870617d2a87e75ce8b33c08cb92fac5db1850e7e693c4a8d44f1e123c39\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000dba50be4fa800d7baf576f853f6f6489229f974c6793e7f6246818364665794f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000dc35a537a22593561c4270262ed3332f2ff69c07ffb38eba7ef6af4dc3e9397d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000dc92fdd70923fe5c565222080687eb51f65f18fcabf6d323cbe8dd7925e4c013\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000dc9344536c8598cc92e2aece37df10545c32797c84f4366355f1606aae3e775d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000dd043d8ebade9227be60fd5e7fd233eb40c1dad838ddef0b108ab5468312f374\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000dd09465933cbf6db01b3e34d2f3f099ceab50d9ff6f4dba5472021432bdc26b6\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000dde8fb8aeed7cd686ce8e6b5d2a9dd7f057afc5b5e4aa323f8f6ce9231c1e308\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000de063b6e62225c272ec86ee8b3614f8326edae0e38c37dc537b71bd5870865fb\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000de269adbc3abdbb34d0781c50631981d6e9ee4ac1b84f4bbca4ed5b23dea80e7\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000df771818da0af72292fdb193a1219775ae7dd0a9e3132f5c4a11a415ee921903\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000dfd8904cce99666f889c618c7ad69058766e39edc5d42785ff9a8d5c3127852c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e00a998d6b64d475f706ca20863c0c34d4b51c84fb42dbabbd1ec5641fad18f2\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e03019a8a4bff6f591873dbed4bd6af2996c6e757b8ebe4bac68232004a7d430\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e0ba5f1f603492a4a0e82825d5aea891fc3c03fd50f3c46797fa0ebd0fb5ecd3\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e0c222b0b8efd22841797421c2a2610b84a2a521a4d12a44cebdc3b961851986\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e0c91b53646e6ed3653702e3587a122b6406ce98a64fba6382b8ad621e712ff5\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e0d230518b841b250838311961fe6aa324a05e20369b4835df6e7b4f575cbe19\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e1bc4eef4b96585113c8a914e745c293aca76cab08de7eed99ae86713210604a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e3272fc98aec9662b52dab23bf9375c3c9c47d2bdc04873b8b235224f114ece0\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e33dd8d7161b430e8af6456517f4b44f892b4d0338c970580acb3feec7fb67d9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e44927a5fedc634d08da96a955c378c03ac92ed48be40291d7fd9a22add8d576\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e475864fbe8fd13134c7755afb491577e24de309035f2afadb914eca14e5731f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e4f57f96e1b72bd686da2603258051368708e65542996bc2ef845d68fbf5a7d9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e52352a5ff102ed953c2f2e4cad453a0c8c2da239c2d2896dfbdf0a09a6a7f5e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e537f3ea87a7b316f932a8441811373e0ee753627f1a8ef0fcdec1abd2c40e5d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e5a3022204045968329e5f9a74d085eea591f98124fe515ba6e9cea1fb039674\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e649d4d21a34a3b2c6889414149c6da769abd37f778ddef0373c40135a01e8ba\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e66e6b657e1c95fffa21793a0cb45ed049a07da6e5b9abb5030e4eaece0a72bf\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e6a0aaedf42dbccb78a3437a5fce29315b695aa6b0768cc91ae6c45b7b38f89d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e6b26d41d35c23926377e2b93c1b56fc8030d5bdf5b3947107f6875283a16ffc\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e700f2b468ad47fe63cee0fa646b0ec526485fbf0ce31d56e9a515e1a44f1f2b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e708edb5aff0f617929ac70745818f8eda917cc86bb20d69cf073fd07abae96c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e786cb2eb99dc62650e808ffd8b0d0ed32f1bceb91bf89bcf0e7f52e9fea6482\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e82abea1f26d2209ce7bf9974ab1f493a2c60013e1f43f03e22f4b3b4c363397\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e890a9aa8ee1caca3500893f1a3c2bb7a8d4e0a788932759d2ad3c76f8aefe58\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e8a96835444809cf01a89214e8693fbcbb67b90294d1e93b347665d77d3fe2bd\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e963258b82066f44a90cf7bb62ee3ed03aac96e3bda062bee9e1e91abe6384ab\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000e9e33ea6d6ff2ef61e7d98fb55eb355671186af5273ee265338f595a4b2d392d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ea2505ba287890b7209f1af1db0cbd3a10a4a02f2540a2f61369488b24f6fbf8\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ea70f56f9c1098cc9a73ca677a5b4b363bcfa1b8103f575ef2c94c0fc87ec984\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000eb271fa33c668b134049649f21c8ea29cde720a976130a769f3ed3dff8fa58e1\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ebb43f34e767f82fdf5f63a5411c2306ebd8cf023b039a600a9780346bafded6\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ec6d8e38d91761a2ba741bd6d8e7cf661a3b5c2e86dc0d997f76b253a7fd1afe\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000eca19ef4464cb76ba4f07811f661578653445b8b25a3e87ba5b910c5bdad3154\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ecabff0fcfa28899acbddc829c552f6bca747c30c3d85d08198962175e539dec\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ed2607e75ec647393e8757c722867a9ba959a8e3ec10f87049a2314a2b93324c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ed2b257a23362e6afdb329539d8b84ba8b44a5ad7314d36c4ff5987d13cbb477\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ed33ccb6b9af56b8e84bc80b3b43bf6d6e5b8d16539dca2ddd364e64b195891f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ed56e9340f5c87ea1b3ba9fbdb664fada9225e8725d1c0a82e651fb8936b1b67\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ed96170fa06d03fb815378342bb1152ed862f59cf32dd8e1ae2b16c0012b87c3\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ee5d4a7fe36f551ec3b8c8bcede28a9509ceb5ee382a5be79acc0ef7bfa20c8c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000eeecad14423d800d1f9505398cf6ced8fffa801cb753b77fd2aaed6a19c14415\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ef0d631e2ea13b6fe2afc007fd104dd5d2418e6c7257c54b52ca7030947254bd\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ef12ede03877348f8d6941e45a4519357201616d0b7eaa341b4ada8bdb9f41b0\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ef838df94d573f7a4dee622103e8fe4d0237f357aea242101820b7b52548a3a9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000efe23827098b2020b46925053029f11cbdc85e0e3e982d0e684c139208003970\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f017deb6f7a3829f96e8d8a41f255f6a25cdbd9c27cb8c813f1e03c48f9500e9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f04aaf5d7d5a4c0df7098002ceab3dd29756c3785fb2670191435c6a62742c2b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f05960b4f34777ae980f29ffb54e7552fe89e6a14420b160468ce9641bdac1e0\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f094b69df87c320cfedc9001c20dc96508478bdb7a06d5fac1358574cdd06562\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f11f1ffc4d9b2652460fef6eea8094878c979538c61e28ae3569c1e47bcd0eb5\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f17f5325ccb2461da6eb6947cefb500b990d43a2fb6180c78631958fbbaa4185\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f19324aee62fe8b79ff67b28f7363c42f363685d57a91151e4ff1ffd1a93f05c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f1b5d27ea7955d142a505fcefa2e91e301b928edcf48f946c1eea52e675818da\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f1d7e61c68b62769107e91d6bb8ca87fc75c037b06ba1d43ed5fa0bf01277342\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f20e17a5b59e01c95326d84ced108da632016022f1f18b695c21a7291607cdf7\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f2d711969ae420343788a90d8430bbe5996943ffe546b88503917daccadec0a3\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f31fc1092181465c5e3e5b00dcff4efb2582e502573203b88ca30420840ec865\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f4293bf800de731b88a4a18a0399870545e000c3d3299be96af7ec179414585f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f4b57c4d4b9cd4bc3ca39794ed4ab52105f7b085f4009fc75c2cd8642e6bbdaa\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f4d099a3d303aaa9c62469433a3ed266e4767b51c9c7ccf417395f1d042cec67\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f51b33aba67c6d7d3653d3041df978d0aee2779a881b0dd3410450ad3c30bb21\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f540ffbd53ccba6be132e1b6d3364ab909cbcdd7a2c76c2833bf9dbf8d2dd228\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f5bf28e2c408353e5091078926de9d2e61143705bb957583e970084607c15f42\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f60728013f8c83734ccbadf1756014a7151a351db4eac5f5dd8c5543dbf26806\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f650e3c17697eb5da6ee7da9a5507ffb7a26268ac2af4b13bb318f29cf31b992\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f669dc0bcc97251dcbccb40dd268776de453bfbcc54e6f9de2dc2b26e6d617f9\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f6d209c2ab065272cdf8ebc0525d28217ac01b6b1859d633ffd919e46b74e04d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f6eb93403ff694a4b7c0a89b0d07496623644c516a28a151963a2d0815f30362\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f71b6a4f09c45e5f29d16dd1da217cdfd69b5d7201889d76b1689d18f93fdd7d\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f7332ea7e80f208fd3cd00efeea833a07c76b36487f388911ec41605f0b49c9a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f79483754ea343b2553536e8fefe136f7274da516bd73f744d4a10687821695f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f7f71bb09668a33e16ed51955fe332cf9c0617ab62e482072f6448b581195509\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f87e37e0f4f4f0362fe7ad8de3bf7af943f3965252f3e52efc80bf624cdc574f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f8ef8ffd14b25d116c424cfcc2e14f76ad56b174cc59a4a3fe046a9a94b2282a\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f948fe3e9505abdad8c961dccc5166e5c4c08b9b26db5d9f38c414541e428fee\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f9a48edccf7496c540a497d8eb55e1bc795ad96ad9a9c5e767c1e8ac6be72762\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000f9ebcb2c1347d928f268f98f64edb41b8bd1ec779ba7577fc985e192b5220a7e\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000fa0469b285963404bf7008e20ef06d7f84ab3a52b5e3eeb5f953329806fd5879\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000fa635c7048b2f9efa687bbf30c46abff02a58d481792530e37029fece0cef617\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000fa9bab26de929657656edfdaca364060f8f601397fa9d31f0e2fe5e8b148b457\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000faa9dd2b1cd121c88c5bff0bbb450220f8db9f7ac28e36c28321d778e6bb12b6\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000fb145d9b60296bcf544dddaf18f36577955c7ba071928efeb87170588d54839f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000fb217f6c670af9b02b93acd6c652f8858cf91f674edfd16f53a9cd033f7d0c27\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000fb2269e0a5d59267bd66c5881cb10d0a6fdea0a495f82298209ded7ed96d9b34\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000fb4cd59144a767d270c923da89edd769d48afef3ffcf655f478dfb6de7a0f4fb\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000fb572bd9248444ab9c0c6c1e0f94ce2b15ac47310f81a459414061576bc5455b\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000fc46792e79b02eebe5205107fcb2461d8e27d8342642d550a0e67ef327b6f230\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000fcac5bce292099fb7c8beaeb305a659e5c608315b0215922e38f0d092c5b780c\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000fcbeffad8bb9d6c3bc8e661bfe5a73f71eab60e44ece818e25455aa47ddf5c27\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000fd368556fd56b3e72cb32b30b961e6039a2e6c2241746c9be9bb604349d329a6\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000fdbf6b7ef3d200ec9f4fe3762914c6f005794a5c04edb84f7e8b36ac9afcd49f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000fdea91f7032588604b8b663d5cb5fb2680b2cdc20976171c1f6378da01386866\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000fe1548915e23d71a9c79a74134beb98fd29f9861d0fdf0a34325832763b2f7fd\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ff138691347b4b721225c02e0dfc490701f2be4a22b018d85f920525e6d5bc3f\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-address\u0000/run/containerd/containerd.sock\u0000-publish-binary\u0000/usr/bin/containerd\u0000-id\u0000ffa3bbee720219086deb8088062bb95dec90caf79f34d96d2d22c2cd4a9360e5\u0000start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000022c96f7bdb76129554efa0279594df41ecbd8b96a4fa22855a25299f1816c7e\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000004fb7f134ffe8a6e6204dbf627c9c2cc88dd0427b4476021ab40ddcdc672e617\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000009182d414cee756ceabb2ac9ac91f74a7d90ef38ba8d597f74bf279938fcf484\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000098e3d505e0266bab4c19bc1a824f5f2b359b745380cbeca4620f6ba8d5de92e\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00000c0960c26a93a6e770b146f3524a9f5ebc40803670293d77937988761184519d\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00000c69138904b28ec0f83b349587f48d14fe80c4cab80cc6a8799a6bb99ef21631\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000013436b9c0f01ebe152cb46f11ec52ec37468b6bb4684550a52c63aa79a87ab25\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000139a6746ed9f9cc9befa094303480d2363db41ce3a4c77b7091fdcc9630033e7\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000013a11667a2231105d3f04a62bc5fecfd4eb2dafa6bfc3760f279873a21207f2d\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000148dfe8d7522117e0a4f54064464c3f5e0e079ff5b35fdb292954ac5b1af2f52\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00001a3f7e3469bcdcce3c341fb698a4b61c6038ab6c727edad2ccd811b392ca60ce\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00001b8496a591b68476fb1507f290ddcefb1249369965023cec23d7b6656cfa3fc6\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00001ca1ef1869643242485123049b3737ae5dd02afa95207d8ba0e3c5d74803b821\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00001dba5588172d1862baaf4c40e1af3ef706b1f0464947b7c32f29763d5be2666b\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00001f96866acc41a39ae2aa56096c6d1b8bfa25b36b291d0a715c1eec52eca54e18\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00001ff2992ae6e0ca0e10e9c0b2f1de4a10ee77b42dd3746bbe3eb6c8c71682b42d\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000020bb45a57005c5e806c6d4c2c53e685185b991e6f13cdd0395da476dfba37bfb\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000021b5e864386890a13ad4e307d42a1e334ddc2d200362d4a00c4c12d9368826aa\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000024652e7f422c05f34710d627e48bab4ed1557da197fdf72400a0836611edba47\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000025dd76ff549c177a07e4d3ec6e61a399e785e72ad6f724037f260150c2a39f85\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00002c16a30d47cd89860191fbf0202cad23dfe0045748e0c4ce8983db7887ca2790\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00002cea86434f8f5f63c9c12c3f77ce7fb6b65407692d21f2e7ba374c3fd01e847f\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00002d26d25b46cfb1b8fc23075bf80b400fd07dbc2d66e6220a79702c2d8778a3a7\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000030183e14e34391c2bc173b051bbe7f4b5cca3361c2368ad4c314432a32c68e77\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000302d90a207d6b886e5a452b0b41af4b7dd91cda73379e1f67996692c20055f79\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000305dcd1a72c01fb9eccc3fd22c1b0f326c23bf45a04c1d0d40651a79b69c225b\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000320440a7197d3037004514d778299cc1bb4491bb91361c5427ad23a87a80e741\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000332af505d44271644c921d787e1c0b6643f375e6814673b5d63f00cecee48b5e\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00003446272e40df7db62df79875b9d32e744181590adf29cac8d5a64983f790fe68\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000034615924cfce24537d44026302ddf6c997970be5843acbe04c0b52a402dafe9c\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000036a8d2ff1d8fa4af09c9931f410c5152a442f16590b7b746ebb69e4fe4773d8d\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00003931cbb6f97406df6966662b36169af13e59a5c9358f13e289e9f1ad5180e4da\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000039d4e70eaea0e38e1100e0331186103d9952d7127695b62a2027a2a07eb62043\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00003b405692323f4d094822c35621d7c1b44d0d592211012a8f37b59d5e8e48e503\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00003b884654adf326afba42b3a6f955e81df318baa742272cf278ed68ca2380ad70\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00003bd075da236be3b11e328cc4223f42aa95f18e13493f0e035ccae7c9ef7ee308\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00003f742431deb8cf1d205a37a93211b87b60296617f576c3dc34578eef8b848d77\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00003fb1da9edf6a5e276287ccc99657b9b87dce18b30a1c9b08f520496c81eed184\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000043326933880cb5eb2afb33183990164a76a9ec54a3a8e16071a7fe48702e4403\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000045f2c1749017292ba1fc1d5293c71b4c20c923e660e9c490ca8518c01c2a8ff9\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00004841caee3be6db2cf41746b560a7f28879eaa0afc1fae2c38a771bfd19827dab\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000487cd5c5c17323ba006b9cad25cb0282602330eca1f9a9b32613e7fb977514f3\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000048d3694054272f5e072ef8c8e907db5e98be6e72c2eaa29d3dd6af7bd64ecfdb\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00004a36329da5560fd4438a37a0dd356573cf703aff958459cd9638b39789c1d41b\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00004e226e8f4f3818d446e7dca0d641cb76eb73aa16465aec42766d666ff14cd73b\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000524d685d8b60e973ba0613d7c5f4c2376468421d7c61061764c33fd8d242c4e4\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000537679d4e171fc43d8e99acf2ff865c2688baef77b0b6a4ad183a84738d46482\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000570f15106dd357144e34abf41a28f8a389b75440677d342bee5f54df121e59d9\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00005859bedfbe669a2f73fb22fa85bcbc4490c8cd1c3a62823956d54284e62396ad\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000586897f2013a4547d47ecd9d458af79b099284f4a8ad306fa3a1ebfcb8b8c7ce\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000596626f0481c1114adc8021d4bee58ce33bcab7a0947f91203e539e84f977320\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000059e46830da0a577be56ac5a330f55c63d6a5cc65d342923e86aa44faccc29af4\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00005b64334e8259fbf4e96da16f481615c1818a16c085aa98815c1e6b90f009bf66\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00005d7e2980049ef561352794689cd21b4b2a39c4cbd680f20a2b14a2cd35045902\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00005f5c76207770e3dbc344d1e75707bca81da1b108632fc7f48476bdd5eb29417b\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00005f970b8804d0c76c0df7470f39136d9a840e8bb564e76f7ee5fe33c8bded40b2\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000060340ba17c64ce78654b7baa5035c3f421bb34ffa026458e4b67a3c7aa49e731\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000645772bf6a6f95644b6f79ee1063723c1a39630f66dd6a70892c989b04ea67d9\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000064577d9314e648e2c36e051ce39e27e3e1b0d087c7ad4a5b6664eca23cdbfc22\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000695b5de3ce54dc26dd0456f6bc02b7464ee50b6cf5b57bc08476c15c9b56d3dd\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00006ba49894f74ca633c7170aaf9e1ea821fe4480dccad5a875dd7741b3ba9a5b0e\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00006c53bd4f93cb94885716c0a3490b776c02088d5b5d5d289e26c9bde8aa0c6a21\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00006d412f2678d6c4d51a1ca51c541ec36120d8d74d64fb6d73e977451351fe23ae\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00006e8e9e4593ff8bbbb50a01fec0fd736dc0e8f06f0afff69cd5e296921e816b83\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000756aca4d147715bd0d630305d7c9c7ed4aaa98fa088f1af8181b4a287fa78fb4\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00007703aa87d4f8bfaa79c48c1dd0ef9eabed04ee4911545b01eb0bf977f13a7514\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000077e84498501385d6a747301b27c9cf17b2d02d1feb29e17434c482dd3f2646f0\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00007a023b7551828dccc00121ea99245714939bfb8b9790c80d40fb47af6c5f4a27\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00008144dd3888e923b130689763cc8edcb3772f03aa4523a0b165765c7b3b5b4c67\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000838ec0dcb64984f156c0f8e91fede7947c2de06c44bee8c731842bfdce365a3d\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000087627c4720a36c54dd66ff504895ca02b0a5ffa04eb9a026d37a2e744b9ec0e9\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000881590b722ab3b7105e09d958a8d59dc88004ce525fec592eb8ac7d8d97d6e8f\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00008eb342ee7ac11f4cc445bd778e736d9ca7109ffb09cdacd5444c24be109f9d50\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00008f1ce84c2dc3164b43687ce8e235fe872d28591b1ad83ae946ac11a8711bb40c\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000900af250b3985c9c141ddbd928d7bcdbb87f5f477603f03076d7966e8f71ae7a\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u000090dbcd818a82925ab03ac1815533f96beb73dbdf0750e149c8b76ab612eb4bde\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000920d205e517976b8d147abda234e5608851ca546bc3f7c891b990902750563cb\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000923326fc2689d97b2473cfe2dfaa8ed93ef729b390a6c432fd1c2978a45d3731\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00009a4d90db2cdb16be978846a9055c56ac5cf13912c802da04b632dd239d5ab487\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00009a5083f78e6e342f6818425645d512c3704dd85a6b81965ff9b422e7cd2ba263\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u00009b5a965a8d8ba8692fe494d67b8f66b4b35f1f321c573a0a26872420de20dcfb\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000a1d7e6f9205811bf048727f3ad9e7087240719f0011b12810b39aed0c2d725ce\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000a77199918ba4a2bb46362c30f57fd491151babf46a3408dec29cfe99b433c4f2\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000a79aab138c94ec9a45bde2d1efbc9d8bd9e8b2a039bec2147e7aefff5d24bb01\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000a931eca40bb20acc7bbb72b274a4c721e6fe12a3b06c1f379a066d48997efad5\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000a975e9820815650482c30be0ad84af422e80f53dbce847de46db7dbaab56a547\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000aafdc624f513e866cd1b8eb29b43cd35fee16ba827f9c25269a3b8f2de755bcd\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000ae1bbe5d3e36ab2cc482360cd7d2573e6a65a066ac84feab7b8bf5dee3ca4ace\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000b113bf852b5f703033ed83172216224aadfb890daec26cc1c89fcab6f6f57496\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000b1304dc3e8e635fca9134651652fe49b663743a7b9064d4db309bec471080dad\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000b1336fc034d0a00a43c371a98da44a440129b68b02c89caf1cb88fd60f578cf1\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000b4ac38d6cbc8c014747c55890a6bf9a7b49d184282e63327cdbd6bb1c27ab1bb\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000b6a742b9ee248ab484711beb628da130cabf659bc6bc1ab6d170a81adb2babaf\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000b7419dd5fe148a5aff02f0d37765dd05688cafdd8ebfcf24fbb63c5ae1ac3e83\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000b759defef6178603ddba91ed89da9e922f4583aa20ce41e960e12e3437aca381\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000b91a1b21676e5ac18d86d26cd67d8a2f4aaa23549317fa62e1165ff7c523d766\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000baf5bff74b7dd60968f88873a711cfad7091aeb7fc20e0127150d8db3cb3e019\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000c02eda66f47cf445bb5387eb3e4e4f633a0d6e0d4b45d19ff857e3d74b7c7ef3\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000c2bf8df02f1b4dcc1b69ccd1b8bb6a84b5bf3c588391be98e274e09b203e934a\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000c2e12086a7b1755a7921e7974bdd678f2760aaed13e9b4af15823acbe78e7517\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000c37ac7e5f17416a8dded847f6f1c34d375a829c0cdf2d8015324a0f8711cb268\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000c3dddb90d4b8546ac5e4a64d4cc8143bea0409ffab89dac61631d5318542bb96\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000c41a636e066b5e267a3fa806e0468f2929eac88bbbbf282098e25584c23aa506\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000c458f6ca8c6deeb1aea508fd0cd9164ddcd14939ef2de3dc831775faa99a7dff\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000c577e26cfd02e8affedbb2281e7e7ec01644903667fff60443db2a2dd94a4a99\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000c6bf4c645b44b43536efe5260fc88e0dc5ba3c4f579fe6206f6bcac7c2126233\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000c7d4fed948daf077828ab4837671ce1babc377db46ed7881ecd4b46a90fa7f4d\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000c828dce0234ed6b6104f4fd5c8e2ad70a2792e6539f105eb83456d1630f0174f\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000ca2306f62199821560f4615f9bc87a8ceff3183761c34ed3f53c3db5be72c37b\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000ccf77a9a6636c6cc1c077b294e85ce550cfd666a56605212216ce1ea0a337ee4\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000ce10fb2cf28ed9ad58cbeb6f2210cc3613772d8809e3ff60ee2ea00151a08697\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000d2c0ff40b578a43f18b289655f65010952012379e8c7653bf22dbc0fff319a1d\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000d519d4e00600499fb7bd8f05f9cc447650e9389800b15f18340af612baad3dc4\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000d792ddbecbdd3723b0e2296a61518e684813acb1b35bc727f51b965a986ac26e\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000d81e381d13a5c15409b611eb0bb96723180584cd3c74066da9554dd111145d6b\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000dd09465933cbf6db01b3e34d2f3f099ceab50d9ff6f4dba5472021432bdc26b6\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000df771818da0af72292fdb193a1219775ae7dd0a9e3132f5c4a11a415ee921903\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000e52352a5ff102ed953c2f2e4cad453a0c8c2da239c2d2896dfbdf0a09a6a7f5e\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000e649d4d21a34a3b2c6889414149c6da769abd37f778ddef0373c40135a01e8ba\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000e66e6b657e1c95fffa21793a0cb45ed049a07da6e5b9abb5030e4eaece0a72bf\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000e6a0aaedf42dbccb78a3437a5fce29315b695aa6b0768cc91ae6c45b7b38f89d\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000ea70f56f9c1098cc9a73ca677a5b4b363bcfa1b8103f575ef2c94c0fc87ec984\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000ebb43f34e767f82fdf5f63a5411c2306ebd8cf023b039a600a9780346bafded6\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000ed2607e75ec647393e8757c722867a9ba959a8e3ec10f87049a2314a2b93324c\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000f6d209c2ab065272cdf8ebc0525d28217ac01b6b1859d633ffd919e46b74e04d\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000f6eb93403ff694a4b7c0a89b0d07496623644c516a28a151963a2d0815f30362\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000fa0469b285963404bf7008e20ef06d7f84ab3a52b5e3eeb5f953329806fd5879\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace\u0000k8s.io\u0000-id\u0000faa9dd2b1cd121c88c5bff0bbb450220f8db9f7ac28e36c28321d778e6bb12b6\u0000-address\u0000/run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/cp",
          arguments: "/cni/loopback\u0000/host/opt/cni/bin/.loopback.new",
        },
        {
          name: "/usr/bin/cp",
          arguments:
            "/opt/cni/bin/cilium-cni\u0000/host/opt/cni/bin/.cilium-cni.new",
        },
        {
          name: "/usr/bin/cp",
          arguments: "/usr/bin/cilium-mount\u0000/hostbin/cilium-mount",
        },
        {
          name: "/usr/bin/cp",
          arguments: "/usr/bin/cilium-sysctlfix\u0000/hostbin/cilium-sysctlfix",
        },
        { name: "/usr/bin/cut", arguments: "-f\u00001\u0000-d\u0000 " },
        {
          name: "/usr/bin/dash",
          arguments:
            '-c\u0000until test -s "/tmp/cilium-bootstrap.d/cilium-bootstrap-time"; do\n  echo "Waiting on node-init to run...";\n  sleep 1;\ndone\n',
        },
        {
          name: "/usr/bin/dash",
          arguments:
            '-ec\u0000cp /usr/bin/cilium-mount /hostbin/cilium-mount;\nnsenter --cgroup=/hostproc/1/ns/cgroup --mount=/hostproc/1/ns/mnt "${BIN_PATH}/cilium-mount" $CGROUP_ROOT;\nrm /hostbin/cilium-mount\n',
        },
        {
          name: "/usr/bin/dash",
          arguments:
            '-ec\u0000cp /usr/bin/cilium-sysctlfix /hostbin/cilium-sysctlfix;\nnsenter --mount=/hostproc/1/ns/mnt "${BIN_PATH}/cilium-sysctlfix";\nrm /hostbin/cilium-sysctlfix\n',
        },
        {
          name: "/usr/bin/dash",
          arguments: "/bin/entrypoint.sh\u0000fluentd",
        },
        { name: "/usr/bin/dash", arguments: "/init-container.sh" },
        { name: "/usr/bin/dash", arguments: "/usr/sbin/iptables-save" },
        {
          name: "/usr/bin/gawk",
          arguments:
            "-v\u0000bdi=259:4\u0000BEGIN{ret=1} {if ($4 == bdi) {ret=0}} END{exit ret}\u0000/proc/fs/nfsfs/volumes",
        },
        {
          name: "/usr/bin/gawk",
          arguments:
            "-v\u0000bdi=259:5\u0000BEGIN{ret=1} {if ($4 == bdi) {ret=0}} END{exit ret}\u0000/proc/fs/nfsfs/volumes",
        },
        {
          name: "/usr/bin/gawk",
          arguments:
            'function pline() { printf any?"%s\\n":"\\n%s\\n", $0; any=1; }\n         /newer release.*is available/  { sub("^ *", ""); pline(); }\n         /new v',
        },
        {
          name: "/usr/bin/grep",
          arguments: "-E\u0000-c\u0000AWS-SNAT-CHAIN|AWS-CONNMARK-CHAIN",
        },
        {
          name: "/usr/bin/grep",
          arguments: "-E\u0000^:(KUBE-IPTABLES-HINT|KUBE-PROXY-CANARY)",
        },
        { name: "/usr/bin/grep", arguments: "-Pzo\u0000.*Updates(.*\\n)*" },
        {
          name: "/usr/bin/grep",
          arguments: "-e\u0000 \\-c\u0000-e\u0000 \\-\\-config",
        },
        {
          name: "/usr/bin/grep",
          arguments: "-e\u0000 \\-p\u0000-e\u0000 \\-\\-plugin",
        },
        { name: "/usr/bin/grep", arguments: "-q\u0000kmod-nvidia" },
        { name: "/usr/bin/grep", arguments: "/sys/fs/bpf type bpf" },
        {
          name: "/usr/bin/grep",
          arguments: "^md.*: active\u0000/proc/mdstat",
        },
        { name: "/usr/bin/gzip" },
        { name: "/usr/bin/hostname", arguments: "--fqdn" },
        { name: "/usr/bin/id", arguments: "-u" },
        { name: "/usr/bin/kmod", arguments: "-q\u0000--\u0000cls_bpf" },
        { name: "/usr/bin/kmod", arguments: "-q\u0000--\u0000fs-ext4" },
        {
          name: "/usr/bin/kmod",
          arguments: "-q\u0000--\u0000ip_set_hash:ip",
        },
        {
          name: "/usr/bin/kmod",
          arguments: "-q\u0000--\u0000ipt_CONNMARK",
        },
        { name: "/usr/bin/kmod", arguments: "-q\u0000--\u0000ipt_CT" },
        { name: "/usr/bin/kmod", arguments: "-q\u0000--\u0000ipt_TPROXY" },
        { name: "/usr/bin/kmod", arguments: "-q\u0000--\u0000ipt_set" },
        {
          name: "/usr/bin/kmod",
          arguments: "-q\u0000--\u0000net-pf-16-proto-6",
        },
        {
          name: "/usr/bin/kmod",
          arguments: "-q\u0000--\u0000netdev-tmp70de9",
        },
        {
          name: "/usr/bin/kmod",
          arguments: "-q\u0000--\u0000netdev-tmpc02ed",
        },
        {
          name: "/usr/bin/kmod",
          arguments: "-q\u0000--\u0000nfnetlink-subsys-6",
        },
        {
          name: "/usr/bin/kmod",
          arguments: "-q\u0000--\u0000rtnl-link-veth",
        },
        { name: "/usr/bin/kmod", arguments: "-q\u0000--\u0000sch_clsact" },
        {
          name: "/usr/bin/kubelet",
          connections: [
            { destination_name: "10.3.6.8", destination_port: "443" },
            { destination_name: "10.3.7.177", destination_port: "443" },
            {
              destination_name: "127.0.0.1",
              destination_port: "9879",
              bytes_sent: "23772",
              bytes_received: "19116",
            },
            {
              destination_name: "127.0.0.1",
              destination_port: "33275",
              bytes_sent: "3656",
              bytes_received: "3944",
            },
            {
              destination_name:
                "3BE81FD965B44E29EE37641B4D0F95CD.gr7.us-west-2.eks.amazonaws.com",
              destination_port: "443",
              bytes_sent: "4635",
              bytes_received: "4678",
            },
            {
              destination_name:
                "3be81fd965b44e29ee37641b4d0f95cd.gr7.us-west-2.eks.amazonaws.com",
              destination_port: "443",
              bytes_sent: "14434664",
              bytes_received: "30973788",
            },
            {
              destination_name: "alloy/Deployment:alloy",
              destination_port: "12345",
              bytes_sent: "810",
              bytes_received: "788",
            },
            {
              destination_name: "argocd/Deployment:argo-cd-argocd-repo-server",
              destination_port: "8084",
              bytes_sent: "1584",
              bytes_received: "1624",
            },
            {
              destination_name: "argocd/Deployment:argo-cd-argocd-server",
              destination_port: "8080",
              bytes_sent: "2704",
              bytes_received: "8304",
            },
            {
              destination_name: "cert-manager/Deployment:cert-manager-webhook",
              destination_port: "6080",
              bytes_sent: "1290",
              bytes_received: "930",
            },
            {
              destination_name: "dex/Deployment:dex",
              destination_port: "5558",
              bytes_sent: "32427",
              bytes_received: "36169",
            },
            {
              destination_name:
                "hubble-timescape/StatefulSet:hubble-timescape-lite",
              destination_port: "8123",
              bytes_sent: "29997594",
              bytes_received: "126022657",
            },
            {
              destination_name: "ip-10-3-5-195.us-west-2.compute.internal",
              destination_port: "6789",
              bytes_sent: "870",
              bytes_received: "602",
            },
            {
              destination_name: "ip-10-3-5-195.us-west-2.compute.internal",
              destination_port: "9100",
              bytes_sent: "1588",
              bytes_received: "5356",
            },
            {
              destination_name: "ip-10-3-5-195.us-west-2.compute.internal",
              destination_port: "30001",
              bytes_sent: "11300",
              bytes_received: "6256",
            },
            {
              destination_name: "ip-10-3-5-215.us-west-2.compute.internal",
              destination_port: "6789",
              bytes_sent: "922",
              bytes_received: "602",
            },
            {
              destination_name: "ip-10-3-5-215.us-west-2.compute.internal",
              destination_port: "9100",
              bytes_sent: "16317",
              bytes_received: "58383",
            },
            {
              destination_name: "ip-10-3-5-215.us-west-2.compute.internal",
              destination_port: "30001",
              bytes_sent: "105337",
              bytes_received: "62781",
            },
            {
              destination_name: "ip-10-3-5-231.us-west-2.compute.internal",
              destination_port: "6789",
              bytes_sent: "3740",
              bytes_received: "2546",
            },
            {
              destination_name: "ip-10-3-5-231.us-west-2.compute.internal",
              destination_port: "9100",
              bytes_sent: "81925",
              bytes_received: "298363",
            },
            {
              destination_name: "ip-10-3-5-231.us-west-2.compute.internal",
              destination_port: "30001",
              bytes_sent: "291571097",
              bytes_received: "4942211",
            },
            {
              destination_name: "ip-10-3-6-166.us-west-2.compute.internal",
              destination_port: "6789",
              bytes_sent: "3220",
              bytes_received: "1940",
            },
            {
              destination_name: "ip-10-3-6-166.us-west-2.compute.internal",
              destination_port: "9100",
              bytes_sent: "268695",
              bytes_received: "318804",
            },
            {
              destination_name: "ip-10-3-6-166.us-west-2.compute.internal",
              destination_port: "30001",
              bytes_sent: "530133",
              bytes_received: "317509",
            },
            {
              destination_name: "ip-10-3-6-179.us-west-2.compute.internal",
              destination_port: "6789",
              bytes_sent: "205683",
              bytes_received: "131477",
            },
            {
              destination_name: "ip-10-3-6-179.us-west-2.compute.internal",
              destination_port: "9100",
              bytes_sent: "6165955",
              bytes_received: "20123441",
            },
            {
              destination_name: "ip-10-3-6-179.us-west-2.compute.internal",
              destination_port: "30001",
              bytes_sent: "58532509",
              bytes_received: "3071705999",
            },
            {
              destination_name: "ip-10-3-6-198.us-west-2.compute.internal",
              destination_port: "6789",
              bytes_sent: "1636",
              bytes_received: "1065",
            },
            {
              destination_name: "ip-10-3-6-198.us-west-2.compute.internal",
              destination_port: "9100",
              bytes_sent: "63215",
              bytes_received: "216593",
            },
            {
              destination_name: "ip-10-3-6-198.us-west-2.compute.internal",
              destination_port: "30001",
              bytes_sent: "369594",
              bytes_received: "201299",
            },
            {
              destination_name: "ip-10-3-6-44.us-west-2.compute.internal",
              destination_port: "6789",
              bytes_sent: "766",
              bytes_received: "446",
            },
            {
              destination_name: "ip-10-3-6-44.us-west-2.compute.internal",
              destination_port: "9100",
              bytes_sent: "7810",
              bytes_received: "25363",
            },
            {
              destination_name: "ip-10-3-6-44.us-west-2.compute.internal",
              destination_port: "30001",
              bytes_sent: "81137",
              bytes_received: "27404",
            },
            {
              destination_name: "ip-10-3-6-99.us-west-2.compute.internal",
              destination_port: "6789",
              bytes_sent: "974",
              bytes_received: "671",
            },
            {
              destination_name: "ip-10-3-6-99.us-west-2.compute.internal",
              destination_port: "9100",
              bytes_sent: "2058",
              bytes_received: "6617",
            },
            {
              destination_name: "ip-10-3-6-99.us-west-2.compute.internal",
              destination_port: "30001",
              bytes_sent: "156002",
              bytes_received: "25685",
            },
            {
              destination_name: "ip-10-3-8-128.us-west-2.compute.internal",
              destination_port: "6789",
              bytes_sent: "922",
              bytes_received: "619",
            },
            {
              destination_name: "ip-10-3-8-128.us-west-2.compute.internal",
              destination_port: "9100",
              bytes_sent: "8793",
              bytes_received: "31187",
            },
            {
              destination_name: "ip-10-3-8-128.us-west-2.compute.internal",
              destination_port: "30001",
              bytes_sent: "285749",
              bytes_received: "12708452",
            },
            {
              destination_name: "ip-10-3-8-154.us-west-2.compute.internal",
              destination_port: "6789",
              bytes_sent: "714",
              bytes_received: "515",
            },
            {
              destination_name: "ip-10-3-8-154.us-west-2.compute.internal",
              destination_port: "9100",
              bytes_sent: "19174",
              bytes_received: "67886",
            },
            {
              destination_name: "ip-10-3-8-154.us-west-2.compute.internal",
              destination_port: "30001",
              bytes_sent: "690024",
              bytes_received: "492394",
            },
            {
              destination_name: "ip-10-3-8-80.us-west-2.compute.internal",
              destination_port: "6789",
              bytes_sent: "922",
              bytes_received: "602",
            },
            {
              destination_name: "ip-10-3-8-80.us-west-2.compute.internal",
              destination_port: "9100",
              bytes_sent: "5654",
              bytes_received: "20371",
            },
            {
              destination_name: "ip-10-3-8-80.us-west-2.compute.internal",
              destination_port: "30001",
              bytes_sent: "79312",
              bytes_received: "23932",
            },
            {
              destination_name: "kube-system/DaemonSet:ebs-csi-node",
              destination_port: "9808",
              bytes_sent: "32162",
              bytes_received: "28938",
            },
            {
              destination_name: "kube-system/Deployment:coredns",
              destination_port: "8080",
              bytes_sent: "858",
              bytes_received: "810",
            },
            {
              destination_name: "kube-system/Deployment:ebs-csi-controller",
              destination_port: "9808",
              bytes_sent: "1668",
              bytes_received: "1516",
            },
            {
              destination_name: "kube-system/Deployment:hubble-ui",
              destination_port: "4180",
              bytes_sent: "6212790",
              bytes_received: "55906683",
            },
            {
              destination_name: "kube-system/Deployment:hubble-ui",
              destination_port: "8081",
              bytes_sent: "3012012",
              bytes_received: "3209260",
            },
            {
              destination_name: "kube-system/Deployment:hubble-ui",
              destination_port: "8090",
              bytes_sent: "3056542",
              bytes_received: "2831940",
            },
            {
              destination_name: "kube-system/Deployment:onepassword-connect",
              destination_port: "8080",
              bytes_sent: "35101",
              bytes_received: "58229",
            },
            {
              destination_name: "kube-system/Deployment:onepassword-connect",
              destination_port: "8081",
              bytes_sent: "34932",
              bytes_received: "35230",
            },
            {
              destination_name:
                "kubernetes-event-exporter/Deployment:kubernetes-event-exporter",
              destination_port: "2112",
              bytes_sent: "1516",
              bytes_received: "1620",
            },
            {
              destination_name: "logging/DaemonSet:promtail",
              destination_port: "3101",
              bytes_sent: "30851",
              bytes_received: "29544",
            },
            {
              destination_name: "logging/StatefulSet:loki-ingester",
              destination_port: "3100",
              bytes_sent: "804",
              bytes_received: "964",
            },
            {
              destination_name: "logging/StatefulSet:loki-memcached-chunks",
              destination_port: "11211",
              bytes_sent: "432",
              bytes_received: "224",
            },
            {
              destination_name: "logging/StatefulSet:loki-memcached-frontend",
              destination_port: "11211",
              bytes_sent: "3243204",
              bytes_received: "1699064",
            },
            {
              destination_name: "loki-memberlist.logging.svc.cluster.local",
              destination_port: "3100",
              bytes_sent: "72608",
              bytes_received: "75374",
            },
            {
              destination_name:
                "loki-memcached-chunks-0.loki-memcached-chunks.logging.svc.cluster.local",
              destination_port: "11211",
              bytes_sent: "164",
              bytes_received: "112",
            },
            {
              destination_name:
                "loki-memcached-chunks-1.loki-memcached-chunks.logging.svc.cluster.local",
              destination_port: "11211",
              bytes_sent: "164",
              bytes_received: "112",
            },
            {
              destination_name:
                "monitoring/DaemonSet:prometheus-prometheus-node-exporter",
              destination_port: "6789",
              bytes_sent: "922",
              bytes_received: "602",
            },
            {
              destination_name:
                "monitoring/DaemonSet:prometheus-prometheus-node-exporter",
              destination_port: "9100",
              bytes_sent: "1907",
              bytes_received: "6773",
            },
            {
              destination_name:
                "monitoring/DaemonSet:prometheus-prometheus-node-exporter",
              destination_port: "30001",
              bytes_sent: "10727",
              bytes_received: "5969",
            },
            {
              destination_name: "monitoring/Deployment:prometheus-grafana",
              destination_port: "3000",
              bytes_sent: "161372",
              bytes_received: "138971",
            },
            {
              destination_name:
                "monitoring/Deployment:prometheus-kube-state-metrics",
              destination_port: "8080",
              bytes_sent: "72374",
              bytes_received: "164394",
            },
            {
              destination_name:
                "monitoring/StatefulSet:alertmanager-prometheus-kube-prometheus-alertmanager",
              destination_port: "9093",
              bytes_sent: "1188",
              bytes_received: "1163",
            },
            {
              destination_name:
                "monitoring/StatefulSet:prometheus-prometheus-kube-prometheus-prometheus",
              destination_port: "9090",
              bytes_sent: "167404",
              bytes_received: "164134",
            },
            {
              destination_name:
                "otel-collector/Deployment:otel-targetallocator",
              destination_port: "8080",
              bytes_sent: "6124449",
              bytes_received: "67732181",
            },
            {
              destination_name: "otel-demo/StatefulSet:otel-demo-opensearch",
              destination_port: "9200",
              bytes_sent: "120",
              bytes_received: "80",
            },
            {
              destination_name: "tempo/Deployment:tempo-distributor",
              destination_port: "3100",
              bytes_sent: "3141436",
              bytes_received: "42765043",
            },
            {
              destination_name: "tempo/StatefulSet:tempo-ingester",
              destination_port: "3100",
              bytes_sent: "428",
              bytes_received: "485",
            },
            {
              destination_name:
                "tenant-jobs/Deployment:jobs-app-entity-operator",
              destination_port: "8080",
              bytes_sent: "6133243",
              bytes_received: "99438427",
            },
            {
              destination_name:
                "tenant-jobs/Deployment:jobs-app-entity-operator",
              destination_port: "8081",
              bytes_sent: "6168865",
              bytes_received: "238982622",
            },
            {
              destination_name:
                "tenant-jobs/Deployment:strimzi-cluster-operator",
              destination_port: "8080",
              bytes_sent: "2155302",
              bytes_received: "80358085",
            },
            {
              destination_name: "tetragon-tracing-demo/Pod:tls-weak-version",
              destination_port: "9100",
              bytes_sent: "742",
              bytes_received: "2730",
            },
            {
              destination_name: "tetragon-tracing-demo/Pod:tls-weak-version",
              destination_port: "30001",
              bytes_sent: "3888",
              bytes_received: "2016",
            },
            {
              destination_name: "tetragon/DaemonSet:tetragon",
              destination_port: "6789",
              bytes_sent: "714",
              bytes_received: "515",
            },
            {
              destination_name: "tetragon/DaemonSet:tetragon",
              destination_port: "9100",
              bytes_sent: "846",
              bytes_received: "2626",
            },
            {
              destination_name: "tetragon/DaemonSet:tetragon",
              destination_port: "30001",
              bytes_sent: "58696",
              bytes_received: "73655",
            },
            {
              destination_name: "tetragon/Deployment:tetragon-grafana",
              destination_port: "3000",
              bytes_sent: "180",
              bytes_received: "120",
            },
            {
              destination_name: "tetragon/StatefulSet:tetragon-prometheus",
              destination_port: "9090",
              bytes_sent: "151430",
              bytes_received: "153482",
            },
          ],
        },
        {
          name: "/usr/bin/ln",
          arguments:
            "-s\u0000/usr/sbin/xtables-nft-multi\u0000/usr/sbin/ip6tables",
        },
        {
          name: "/usr/bin/ln",
          arguments:
            "-s\u0000/usr/sbin/xtables-nft-multi\u0000/usr/sbin/ip6tables-restore",
        },
        {
          name: "/usr/bin/ln",
          arguments:
            "-s\u0000/usr/sbin/xtables-nft-multi\u0000/usr/sbin/ip6tables-save",
        },
        {
          name: "/usr/bin/ln",
          arguments:
            "-s\u0000/usr/sbin/xtables-nft-multi\u0000/usr/sbin/iptables",
        },
        {
          name: "/usr/bin/ln",
          arguments:
            "-s\u0000/usr/sbin/xtables-nft-multi\u0000/usr/sbin/iptables-restore",
        },
        {
          name: "/usr/bin/ln",
          arguments:
            "-s\u0000/usr/sbin/xtables-nft-multi\u0000/usr/sbin/iptables-save",
        },
        {
          name: "/usr/bin/mktemp",
          arguments: "--tmpdir\u0000motd.partXXXXX",
        },
        {
          name: "/usr/bin/mktemp",
          arguments: "--tmpdir=/var/lib/update-motd/",
        },
        { name: "/usr/bin/mount" },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2151/fd/29\u0000/var/lib/kubelet/pods/41a615f3-f97f-459c-b746-a862f275e9c4/volume-subpaths/config/download-dashboards/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2151/fd/29\u0000/var/lib/kubelet/pods/41a615f3-f97f-459c-b746-a862f275e9c4/volume-subpaths/config/grafana/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2151/fd/29\u0000/var/lib/kubelet/pods/41a615f3-f97f-459c-b746-a862f275e9c4/volume-subpaths/config/grafana/3",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2151/fd/29\u0000/var/lib/kubelet/pods/41a615f3-f97f-459c-b746-a862f275e9c4/volume-subpaths/hubble-ui-grafana-public-jwks/grafana/1",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2151/fd/29\u0000/var/lib/kubelet/pods/41a615f3-f97f-459c-b746-a862f275e9c4/volume-subpaths/sc-dashboard-provider/grafana/5",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2204/fd/26\u0000/var/lib/kubelet/pods/5e5ec66c-9d9c-4270-ade6-8b5616d7d5a2/volume-subpaths/web-config/prometheus/4",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2204/fd/27\u0000/var/lib/kubelet/pods/5e5ec66c-9d9c-4270-ade6-8b5616d7d5a2/volume-subpaths/pvc-65b6c910-afd9-4ccb-99f7-46a29ab952a0/prometheus/2",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2245/fd/23\u0000/var/lib/kubelet/pods/05ac4801-0a14-4aca-b04e-a2c1515c26b1/volume-subpaths/config/grafana/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2245/fd/23\u0000/var/lib/kubelet/pods/05ac4801-0a14-4aca-b04e-a2c1515c26b1/volume-subpaths/config/grafana/8",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2245/fd/23\u0000/var/lib/kubelet/pods/05ac4801-0a14-4aca-b04e-a2c1515c26b1/volume-subpaths/config/grafana/9",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2245/fd/23\u0000/var/lib/kubelet/pods/92169e69-a62b-4065-a709-de028db31122/volume-subpaths/config/configfile/1",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2245/fd/23\u0000/var/lib/kubelet/pods/e34ed263-6619-45ef-b311-656b9397864e/volume-subpaths/web-config/alertmanager/4",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2245/fd/27\u0000/var/lib/kubelet/pods/92169e69-a62b-4065-a709-de028db31122/volume-subpaths/config-emptydir/opensearch/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2313/fd/18\u0000/var/lib/kubelet/pods/0be8cabb-910b-426a-b33d-e660c86bda7d/volume-subpaths/config/configfile/1",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2313/fd/18\u0000/var/lib/kubelet/pods/9591e83b-04de-4535-8766-d262f904abf1/volume-subpaths/web-config/alertmanager/4",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2313/fd/18\u0000/var/lib/kubelet/pods/f1399dee-05c9-409f-bbe9-ec39daee5e27/volume-subpaths/config/grafana/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2313/fd/18\u0000/var/lib/kubelet/pods/f1399dee-05c9-409f-bbe9-ec39daee5e27/volume-subpaths/config/grafana/8",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2313/fd/18\u0000/var/lib/kubelet/pods/f1399dee-05c9-409f-bbe9-ec39daee5e27/volume-subpaths/config/grafana/9",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2313/fd/21\u0000/var/lib/kubelet/pods/0be8cabb-910b-426a-b33d-e660c86bda7d/volume-subpaths/config-emptydir/opensearch/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2337/fd/27\u0000/var/lib/kubelet/pods/486c678b-7ca5-43d6-8f33-3633249f2a4b/volume-subpaths/config/download-dashboards/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2337/fd/28\u0000/var/lib/kubelet/pods/486c678b-7ca5-43d6-8f33-3633249f2a4b/volume-subpaths/config/grafana/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2337/fd/28\u0000/var/lib/kubelet/pods/486c678b-7ca5-43d6-8f33-3633249f2a4b/volume-subpaths/config/grafana/3",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2337/fd/28\u0000/var/lib/kubelet/pods/486c678b-7ca5-43d6-8f33-3633249f2a4b/volume-subpaths/hubble-ui-grafana-public-jwks/grafana/1",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2337/fd/28\u0000/var/lib/kubelet/pods/486c678b-7ca5-43d6-8f33-3633249f2a4b/volume-subpaths/sc-dashboard-provider/grafana/5",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2384/fd/28\u0000/var/lib/kubelet/pods/6bddb9c6-45ff-45e2-bb3e-4c29fac6d8d2/volume-subpaths/prometheus-db/prometheus/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2390/fd/28\u0000/var/lib/kubelet/pods/0c44c882-6607-4195-8ed4-4d54cc095211/volume-subpaths/prometheus-db/prometheus/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2401/fd/25\u0000/var/lib/kubelet/pods/5f4ab5df-1e06-4b24-8640-f4ba10bb3c29/volume-subpaths/web-config/prometheus/4",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2401/fd/26\u0000/var/lib/kubelet/pods/5f4ab5df-1e06-4b24-8640-f4ba10bb3c29/volume-subpaths/pvc-65b6c910-afd9-4ccb-99f7-46a29ab952a0/prometheus/2",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind\u0000/proc/2666/fd/31\u0000/var/lib/kubelet/pods/003227ee-18c5-43c4-839b-d4275fdc4943/volume-subpaths/nginx-conf/frontend/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2151/fd/29\u0000/var/lib/kubelet/pods/41a615f3-f97f-459c-b746-a862f275e9c4/volume-subpaths/config/download-dashboards/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2151/fd/29\u0000/var/lib/kubelet/pods/41a615f3-f97f-459c-b746-a862f275e9c4/volume-subpaths/config/grafana/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2151/fd/29\u0000/var/lib/kubelet/pods/41a615f3-f97f-459c-b746-a862f275e9c4/volume-subpaths/config/grafana/3",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2151/fd/29\u0000/var/lib/kubelet/pods/41a615f3-f97f-459c-b746-a862f275e9c4/volume-subpaths/hubble-ui-grafana-public-jwks/grafana/1",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2151/fd/29\u0000/var/lib/kubelet/pods/41a615f3-f97f-459c-b746-a862f275e9c4/volume-subpaths/sc-dashboard-provider/grafana/5",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2204/fd/26\u0000/var/lib/kubelet/pods/5e5ec66c-9d9c-4270-ade6-8b5616d7d5a2/volume-subpaths/web-config/prometheus/4",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2204/fd/27\u0000/var/lib/kubelet/pods/5e5ec66c-9d9c-4270-ade6-8b5616d7d5a2/volume-subpaths/pvc-65b6c910-afd9-4ccb-99f7-46a29ab952a0/prometheus/2",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2245/fd/23\u0000/var/lib/kubelet/pods/05ac4801-0a14-4aca-b04e-a2c1515c26b1/volume-subpaths/config/grafana/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2245/fd/23\u0000/var/lib/kubelet/pods/05ac4801-0a14-4aca-b04e-a2c1515c26b1/volume-subpaths/config/grafana/8",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2245/fd/23\u0000/var/lib/kubelet/pods/05ac4801-0a14-4aca-b04e-a2c1515c26b1/volume-subpaths/config/grafana/9",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2245/fd/23\u0000/var/lib/kubelet/pods/92169e69-a62b-4065-a709-de028db31122/volume-subpaths/config/configfile/1",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2245/fd/23\u0000/var/lib/kubelet/pods/e34ed263-6619-45ef-b311-656b9397864e/volume-subpaths/web-config/alertmanager/4",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2245/fd/27\u0000/var/lib/kubelet/pods/92169e69-a62b-4065-a709-de028db31122/volume-subpaths/config-emptydir/opensearch/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2313/fd/18\u0000/var/lib/kubelet/pods/0be8cabb-910b-426a-b33d-e660c86bda7d/volume-subpaths/config/configfile/1",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2313/fd/18\u0000/var/lib/kubelet/pods/9591e83b-04de-4535-8766-d262f904abf1/volume-subpaths/web-config/alertmanager/4",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2313/fd/18\u0000/var/lib/kubelet/pods/f1399dee-05c9-409f-bbe9-ec39daee5e27/volume-subpaths/config/grafana/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2313/fd/18\u0000/var/lib/kubelet/pods/f1399dee-05c9-409f-bbe9-ec39daee5e27/volume-subpaths/config/grafana/8",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2313/fd/18\u0000/var/lib/kubelet/pods/f1399dee-05c9-409f-bbe9-ec39daee5e27/volume-subpaths/config/grafana/9",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2313/fd/21\u0000/var/lib/kubelet/pods/0be8cabb-910b-426a-b33d-e660c86bda7d/volume-subpaths/config-emptydir/opensearch/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2337/fd/27\u0000/var/lib/kubelet/pods/486c678b-7ca5-43d6-8f33-3633249f2a4b/volume-subpaths/config/download-dashboards/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2337/fd/28\u0000/var/lib/kubelet/pods/486c678b-7ca5-43d6-8f33-3633249f2a4b/volume-subpaths/config/grafana/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2337/fd/28\u0000/var/lib/kubelet/pods/486c678b-7ca5-43d6-8f33-3633249f2a4b/volume-subpaths/config/grafana/3",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2337/fd/28\u0000/var/lib/kubelet/pods/486c678b-7ca5-43d6-8f33-3633249f2a4b/volume-subpaths/hubble-ui-grafana-public-jwks/grafana/1",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2337/fd/28\u0000/var/lib/kubelet/pods/486c678b-7ca5-43d6-8f33-3633249f2a4b/volume-subpaths/sc-dashboard-provider/grafana/5",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2384/fd/28\u0000/var/lib/kubelet/pods/6bddb9c6-45ff-45e2-bb3e-4c29fac6d8d2/volume-subpaths/prometheus-db/prometheus/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2390/fd/28\u0000/var/lib/kubelet/pods/0c44c882-6607-4195-8ed4-4d54cc095211/volume-subpaths/prometheus-db/prometheus/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2401/fd/25\u0000/var/lib/kubelet/pods/5f4ab5df-1e06-4b24-8640-f4ba10bb3c29/volume-subpaths/web-config/prometheus/4",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2401/fd/26\u0000/var/lib/kubelet/pods/5f4ab5df-1e06-4b24-8640-f4ba10bb3c29/volume-subpaths/pvc-65b6c910-afd9-4ccb-99f7-46a29ab952a0/prometheus/2",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize\u0000-o\u0000bind,remount\u0000/proc/2666/fd/31\u0000/var/lib/kubelet/pods/003227ee-18c5-43c4-839b-d4275fdc4943/volume-subpaths/nginx-conf/frontend/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=1024\u0000tmpfs\u0000/var/lib/kubelet/pods/04d607ff-813b-4aac-8c29-c9a0716d54e2/volumes/kubernetes.io~empty-dir/ready-files",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=1024\u0000tmpfs\u0000/var/lib/kubelet/pods/c2370d91-6e9d-4b5b-b423-32f019cb3b00/volumes/kubernetes.io~empty-dir/ready-files",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=10485760\u0000tmpfs\u0000/var/lib/kubelet/pods/1beb1010-370c-4274-a462-a215ba9c3ad8/volumes/kubernetes.io~projected/kube-api-access-f2sl9",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=10485760\u0000tmpfs\u0000/var/lib/kubelet/pods/8cdc7674-96ad-48bf-b902-a623c1bfd4cf/volumes/kubernetes.io~projected/kube-api-access-t65xh",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=104857600\u0000tmpfs\u0000/var/lib/kubelet/pods/5b749f79-3651-4f62-9b04-c026183fc9a4/volumes/kubernetes.io~projected/kube-api-access-lrx4m",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=1073741824\u0000tmpfs\u0000/var/lib/kubelet/pods/07fe947f-6a6b-4663-87ce-f0d43fe3ac97/volumes/kubernetes.io~projected/kube-api-access-7q54t",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=1073741824\u0000tmpfs\u0000/var/lib/kubelet/pods/0c44c882-6607-4195-8ed4-4d54cc095211/volumes/kubernetes.io~projected/kube-api-access-g2rhb",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=1073741824\u0000tmpfs\u0000/var/lib/kubelet/pods/6bddb9c6-45ff-45e2-bb3e-4c29fac6d8d2/volumes/kubernetes.io~projected/kube-api-access-dlwpb",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=1073741824\u0000tmpfs\u0000/var/lib/kubelet/pods/88b222bd-efa7-426f-90a3-929f035b5ba2/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=1073741824\u0000tmpfs\u0000/var/lib/kubelet/pods/f02d26d0-73e2-4dab-aeea-57df5e86d06b/volumes/kubernetes.io~projected/kube-api-access-9mg2v",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=1073741824\u0000tmpfs\u0000/var/lib/kubelet/pods/f02d26d0-73e2-4dab-aeea-57df5e86d06b/volumes/kubernetes.io~projected/saml-x509-volume",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=12884901888\u0000tmpfs\u0000/var/lib/kubelet/pods/4613cfaf-2bd7-4703-bb20-49e1ea422e5c/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=12884901888\u0000tmpfs\u0000/var/lib/kubelet/pods/4613cfaf-2bd7-4703-bb20-49e1ea422e5c/volumes/kubernetes.io~projected/kube-api-access-bghsb",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=12884901888\u0000tmpfs\u0000/var/lib/kubelet/pods/f45f9fd3-9ae1-4b2b-8db6-da7220058ee5/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=12884901888\u0000tmpfs\u0000/var/lib/kubelet/pods/f45f9fd3-9ae1-4b2b-8db6-da7220058ee5/volumes/kubernetes.io~projected/kube-api-access-tdsdn",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=134217728\u0000tmpfs\u0000/var/lib/kubelet/pods/10d70cef-1905-48fb-9a50-2bcd8b1a198b/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=134217728\u0000tmpfs\u0000/var/lib/kubelet/pods/285d48ab-d9e5-41f6-aa47-4b38e16cb1dd/volumes/kubernetes.io~projected/kube-api-access-rtzwz",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=134217728\u0000tmpfs\u0000/var/lib/kubelet/pods/285d48ab-d9e5-41f6-aa47-4b38e16cb1dd/volumes/kubernetes.io~secret/argocd-repo-server-tls",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=134217728\u0000tmpfs\u0000/var/lib/kubelet/pods/2bf27566-edd7-45af-aae1-494bbf4ed5d3/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=134217728\u0000tmpfs\u0000/var/lib/kubelet/pods/432696fc-a956-4158-9df8-7e0536f4cab8/volumes/kubernetes.io~projected/kube-api-access-2sqmg",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=134217728\u0000tmpfs\u0000/var/lib/kubelet/pods/432696fc-a956-4158-9df8-7e0536f4cab8/volumes/kubernetes.io~secret/argocd-repo-server-tls",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=134217728\u0000tmpfs\u0000/var/lib/kubelet/pods/9a56d223-4e63-49db-b7f9-a14635327640/volumes/kubernetes.io~projected/kube-api-access-gvd45",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=134217728\u0000tmpfs\u0000/var/lib/kubelet/pods/9a56d223-4e63-49db-b7f9-a14635327640/volumes/kubernetes.io~secret/argocd-repo-server-tls",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=134217728\u0000tmpfs\u0000/var/lib/kubelet/pods/c8aa61a2-39a1-4563-abbd-559f4b3d185e/volumes/kubernetes.io~projected/kube-api-access-frlh8",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=134217728\u0000tmpfs\u0000/var/lib/kubelet/pods/ca041556-5f4e-46c9-9ffd-64f7e400efb0/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=134217728\u0000tmpfs\u0000/var/lib/kubelet/pods/ca041556-5f4e-46c9-9ffd-64f7e400efb0/volumes/kubernetes.io~projected/kube-api-access-9nm4w",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=134217728\u0000tmpfs\u0000/var/lib/kubelet/pods/d6fe75ab-6cc9-4599-b857-1163282ef264/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=134217728\u0000tmpfs\u0000/var/lib/kubelet/pods/e9f204e0-6844-4405-bb92-902165deb439/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=134217728\u0000tmpfs\u0000/var/lib/kubelet/pods/fa39db21-1e81-46b0-8693-905bc1fa49ad/volumes/kubernetes.io~projected/kube-api-access-9x86w",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=134217728\u0000tmpfs\u0000/var/lib/kubelet/pods/fa39db21-1e81-46b0-8693-905bc1fa49ad/volumes/kubernetes.io~secret/argocd-repo-server-tls",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=15418478592\u0000tmpfs\u0000/var/lib/kubelet/pods/3b4fa1ea-0dec-4206-bc76-ffed2b48e163/volumes/kubernetes.io~projected/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=15418478592\u0000tmpfs\u0000/var/lib/kubelet/pods/3b4fa1ea-0dec-4206-bc76-ffed2b48e163/volumes/kubernetes.io~projected/kube-api-access-vsckv",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=15418486784\u0000tmpfs\u0000/var/lib/kubelet/pods/1e53d6a1-3eb0-4702-b48d-08b727175638/volumes/kubernetes.io~projected/kube-api-access-5km4n",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=15418486784\u0000tmpfs\u0000/var/lib/kubelet/pods/288b73b4-e65f-4546-bd47-a3ba1b63724b/volumes/kubernetes.io~projected/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=15418486784\u0000tmpfs\u0000/var/lib/kubelet/pods/288b73b4-e65f-4546-bd47-a3ba1b63724b/volumes/kubernetes.io~projected/kube-api-access-st9gm",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=15418486784\u0000tmpfs\u0000/var/lib/kubelet/pods/3cd144fa-2022-44ed-a476-208e6276feee/volumes/kubernetes.io~projected/kube-api-access-drv88",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=15418486784\u0000tmpfs\u0000/var/lib/kubelet/pods/4a80a026-d8bc-478d-b434-ad5708a63dfe/volumes/kubernetes.io~projected/kube-api-access-hhm6r",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=15418486784\u0000tmpfs\u0000/var/lib/kubelet/pods/a9adef8c-8e40-4fe6-ac08-5df058be1119/volumes/kubernetes.io~projected/kube-api-access-h945w",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=15418486784\u0000tmpfs\u0000/var/lib/kubelet/pods/d86ef51c-829e-438c-810a-b9e13d5a3061/volumes/kubernetes.io~projected/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=15418486784\u0000tmpfs\u0000/var/lib/kubelet/pods/d86ef51c-829e-438c-810a-b9e13d5a3061/volumes/kubernetes.io~projected/kube-api-access-vm9x9",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=1610612736\u0000tmpfs\u0000/var/lib/kubelet/pods/06098090-d8f3-4a8d-989e-a6c509ea91d9/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=1610612736\u0000tmpfs\u0000/var/lib/kubelet/pods/06098090-d8f3-4a8d-989e-a6c509ea91d9/volumes/kubernetes.io~projected/kube-api-access-xffxl",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=178257920\u0000tmpfs\u0000/var/lib/kubelet/pods/5f5ae38a-d6e5-47e3-a7cc-7cfe1ffc6391/volumes/kubernetes.io~projected/kube-api-access-2l5rl",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=178257920\u0000tmpfs\u0000/var/lib/kubelet/pods/916bb269-d530-4735-904e-b0d2c0449d29/volumes/kubernetes.io~projected/kube-api-access-b9qvc",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=178257920\u0000tmpfs\u0000/var/lib/kubelet/pods/f14d78a1-b521-477d-9512-532312ae3da8/volumes/kubernetes.io~projected/kube-api-access-97kvl",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=20971520\u0000tmpfs\u0000/var/lib/kubelet/pods/170da5b8-a5ee-4896-9490-f952ca109c1c/volumes/kubernetes.io~projected/kube-api-access-m88kl",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=20971520\u0000tmpfs\u0000/var/lib/kubelet/pods/84cc34b9-3d9c-4312-8bdf-e4bf132ee449/volumes/kubernetes.io~projected/kube-api-access-8kj6s",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=2147483648\u0000tmpfs\u0000/var/lib/kubelet/pods/9b81e4ed-980c-450d-9ec4-9e019c9a84bd/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=262144000\u0000tmpfs\u0000/var/lib/kubelet/pods/0f584e09-57fa-4898-a68e-5ad4ff95aa6f/volumes/kubernetes.io~projected/kube-api-access-h7qw2",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=262144000\u0000tmpfs\u0000/var/lib/kubelet/pods/4e35af66-b8c0-4ef1-a1f2-68e15a674e79/volumes/kubernetes.io~projected/kube-api-access-dhqf9",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/05ac4801-0a14-4aca-b04e-a2c1515c26b1/volumes/kubernetes.io~projected/kube-api-access-zch5d",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/0b25af45-1786-44f4-bedb-548a786ffbc9/volumes/kubernetes.io~projected/kube-api-access-kdjvq",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/0b25af45-1786-44f4-bedb-548a786ffbc9/volumes/kubernetes.io~secret/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/0c034604-9f5f-4c15-8e41-867dcda2cdc7/volumes/kubernetes.io~projected/kube-api-access-7jc6t",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/0c034604-9f5f-4c15-8e41-867dcda2cdc7/volumes/kubernetes.io~secret/webhook-cert",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/0ffd46db-f39f-405b-8314-7e9fc223e44e/volumes/kubernetes.io~projected/kube-api-access-spvx4",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/0ffd46db-f39f-405b-8314-7e9fc223e44e/volumes/kubernetes.io~secret/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/28e05a04-585f-4396-b813-2483496b80e4/volumes/kubernetes.io~projected/kube-api-access-nqz9z",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/28e05a04-585f-4396-b813-2483496b80e4/volumes/kubernetes.io~secret/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/31b7c7c4-9103-49cb-a34b-abe9d17bd784/volumes/kubernetes.io~projected/kube-api-access-zpd5x",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/31b7c7c4-9103-49cb-a34b-abe9d17bd784/volumes/kubernetes.io~secret/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/54623e0a-9e71-440f-8365-392d8a6eeb25/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/572ac962-22e5-4c81-916d-7df3969a5dbe/volumes/kubernetes.io~projected/kube-api-access-fzr66",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/572ac962-22e5-4c81-916d-7df3969a5dbe/volumes/kubernetes.io~secret/argocd-dex-server-tls",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/572ac962-22e5-4c81-916d-7df3969a5dbe/volumes/kubernetes.io~secret/argocd-repo-server-tls",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/5849dbfd-c7e5-4e19-b29c-db7fbe308a8c/volumes/kubernetes.io~projected/kube-api-access-79gbq",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/5849dbfd-c7e5-4e19-b29c-db7fbe308a8c/volumes/kubernetes.io~secret/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/73e6c269-4918-43f6-b414-311ca787bb69/volumes/kubernetes.io~projected/kube-api-access-cvtch",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/73e6c269-4918-43f6-b414-311ca787bb69/volumes/kubernetes.io~secret/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/85a45f99-448b-4b98-9f1c-6123a861de3d/volumes/kubernetes.io~projected/kube-api-access-qfssp",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/85a45f99-448b-4b98-9f1c-6123a861de3d/volumes/kubernetes.io~secret/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/880f9a15-7ae7-4a94-af7c-37e2202c5ecb/volumes/kubernetes.io~projected/kube-api-access-gp4gc",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/880f9a15-7ae7-4a94-af7c-37e2202c5ecb/volumes/kubernetes.io~secret/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/976b1ad6-d46f-480f-8a72-0a6e154eae99/volumes/kubernetes.io~projected/kube-api-access-9h9z2",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/976b1ad6-d46f-480f-8a72-0a6e154eae99/volumes/kubernetes.io~secret/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/a6ccd50c-47cd-4add-995e-b14478911ad8/volumes/kubernetes.io~projected/kube-api-access-7txhh",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/a6ccd50c-47cd-4add-995e-b14478911ad8/volumes/kubernetes.io~secret/argocd-dex-server-tls",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/a6ccd50c-47cd-4add-995e-b14478911ad8/volumes/kubernetes.io~secret/argocd-repo-server-tls",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/e3c77865-0bcc-45f0-984a-3e5fcf2979bf/volumes/kubernetes.io~projected/kube-api-access-c4v24",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/e3c77865-0bcc-45f0-984a-3e5fcf2979bf/volumes/kubernetes.io~secret/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=268435456\u0000tmpfs\u0000/var/lib/kubelet/pods/f1399dee-05c9-409f-bbe9-ec39daee5e27/volumes/kubernetes.io~projected/kube-api-access-zjtqt",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=3221225472\u0000tmpfs\u0000/var/lib/kubelet/pods/26a16dff-be09-46a2-ab8c-a149dc764412/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=3221225472\u0000tmpfs\u0000/var/lib/kubelet/pods/df66ebde-972b-419f-8b86-3ed6530dd871/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=32304742400\u0000tmpfs\u0000/var/lib/kubelet/pods/b9c3b869-a680-475e-95b1-3288037d303a/volumes/kubernetes.io~projected/kube-api-access-5k29t",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=3262836736\u0000tmpfs\u0000/var/lib/kubelet/pods/41a615f3-f97f-459c-b746-a862f275e9c4/volumes/kubernetes.io~projected/kube-api-access-mt8j4",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=3262836736\u0000tmpfs\u0000/var/lib/kubelet/pods/486c678b-7ca5-43d6-8f33-3633249f2a4b/volumes/kubernetes.io~projected/kube-api-access-bjg79",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=3262836736\u0000tmpfs\u0000/var/lib/kubelet/pods/5607b44a-a85d-46ef-945e-7c756278cc87/volumes/kubernetes.io~projected/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=3262836736\u0000tmpfs\u0000/var/lib/kubelet/pods/5607b44a-a85d-46ef-945e-7c756278cc87/volumes/kubernetes.io~projected/kube-api-access-wprtw",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=3262836736\u0000tmpfs\u0000/var/lib/kubelet/pods/f9609d52-5e62-4ef1-b042-d14e1de107ae/volumes/kubernetes.io~projected/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=3262836736\u0000tmpfs\u0000/var/lib/kubelet/pods/f9609d52-5e62-4ef1-b042-d14e1de107ae/volumes/kubernetes.io~projected/kube-api-access-krcdx",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=5242880\u0000tmpfs\u0000/var/lib/kubelet/pods/04d607ff-813b-4aac-8c29-c9a0716d54e2/volumes/kubernetes.io~empty-dir/strimzi-tmp",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=5242880\u0000tmpfs\u0000/var/lib/kubelet/pods/c2370d91-6e9d-4b5b-b423-32f019cb3b00/volumes/kubernetes.io~empty-dir/strimzi-tmp",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=52428800\u0000tmpfs\u0000/var/lib/kubelet/pods/38c6fe1b-7fe5-4188-b23d-c2f4ba8da2d1/volumes/kubernetes.io~projected/kube-api-access-pvt9z",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=52428800\u0000tmpfs\u0000/var/lib/kubelet/pods/38c6fe1b-7fe5-4188-b23d-c2f4ba8da2d1/volumes/kubernetes.io~secret/tls-secret",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=52428800\u0000tmpfs\u0000/var/lib/kubelet/pods/74fb5845-f2cc-4237-a1dd-730cd199d4d8/volumes/kubernetes.io~projected/kube-api-access-l2xz7",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=52428800\u0000tmpfs\u0000/var/lib/kubelet/pods/7d4acb2b-fa5b-475c-b3ef-61337f030428/volumes/kubernetes.io~projected/kube-api-access-j6mdf",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=52428800\u0000tmpfs\u0000/var/lib/kubelet/pods/a830340d-827f-496c-931d-aaa79dd71287/volumes/kubernetes.io~projected/kube-api-access-lbdg6",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=52428800\u0000tmpfs\u0000/var/lib/kubelet/pods/d654e25c-9537-4f49-ab61-688a9fbd51ba/volumes/kubernetes.io~projected/kube-api-access-tvblg",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=524288000\u0000tmpfs\u0000/var/lib/kubelet/pods/6d13d3d9-586d-4ded-99db-b8f96061e003/volumes/kubernetes.io~projected/kube-api-access-c2vjc",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=536870912\u0000tmpfs\u0000/var/lib/kubelet/pods/2aac05c1-814b-4fa6-b001-5370a7b6ad1f/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=536870912\u0000tmpfs\u0000/var/lib/kubelet/pods/2aac05c1-814b-4fa6-b001-5370a7b6ad1f/volumes/kubernetes.io~projected/kube-api-access-jdz5j",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=536870912\u0000tmpfs\u0000/var/lib/kubelet/pods/50b25a9a-297e-42c8-891f-4176ae438aba/volumes/kubernetes.io~projected/kube-api-access-6vfqk",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=536870912\u0000tmpfs\u0000/var/lib/kubelet/pods/f92c8e6c-0fb1-4640-8040-1446fca42902/volumes/kubernetes.io~projected/kube-api-access-9kf6p",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=6442450944\u0000tmpfs\u0000/var/lib/kubelet/pods/12ae21e9-404b-4858-90c2-ea69c953ffe0/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=6442450944\u0000tmpfs\u0000/var/lib/kubelet/pods/12ae21e9-404b-4858-90c2-ea69c953ffe0/volumes/kubernetes.io~projected/kube-api-access-tvlf9",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=67108864\u0000tmpfs\u0000/var/lib/kubelet/pods/1f8f9439-9064-45da-98d5-8da59ad73b2a/volumes/kubernetes.io~projected/kube-api-access-dw4kb",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=67108864\u0000tmpfs\u0000/var/lib/kubelet/pods/33c44667-a859-4555-9ffc-6efdacd2e1fb/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=67108864\u0000tmpfs\u0000/var/lib/kubelet/pods/33c44667-a859-4555-9ffc-6efdacd2e1fb/volumes/kubernetes.io~projected/kube-api-access-7r45p",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=67108864\u0000tmpfs\u0000/var/lib/kubelet/pods/354cd6bc-8f27-4a55-8d9c-4888ff0c9d35/volumes/kubernetes.io~projected/kube-api-access-tkzfc",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=67108864\u0000tmpfs\u0000/var/lib/kubelet/pods/365af811-831d-4a84-87ed-7a102f54ff8c/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=67108864\u0000tmpfs\u0000/var/lib/kubelet/pods/365af811-831d-4a84-87ed-7a102f54ff8c/volumes/kubernetes.io~projected/kube-api-access-wz6qr",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=67108864\u0000tmpfs\u0000/var/lib/kubelet/pods/8c7b21e4-830c-4eb0-b99b-698d26548d62/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=67108864\u0000tmpfs\u0000/var/lib/kubelet/pods/935a4592-5a12-43f1-aefe-7ca902063821/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=67108864\u0000tmpfs\u0000/var/lib/kubelet/pods/935a4592-5a12-43f1-aefe-7ca902063821/volumes/kubernetes.io~projected/kube-api-access-pgklc",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=67108864\u0000tmpfs\u0000/var/lib/kubelet/pods/a3b57925-12d7-4af3-884f-c3f641c18059/volumes/kubernetes.io~projected/kube-api-access-6bvgx",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=67108864\u0000tmpfs\u0000/var/lib/kubelet/pods/a3b57925-12d7-4af3-884f-c3f641c18059/volumes/kubernetes.io~secret/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=67108864\u0000tmpfs\u0000/var/lib/kubelet/pods/c5b31832-b39c-43ff-ae64-66c136d9ade1/volumes/kubernetes.io~projected/kube-api-access-xwwlj",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/04d607ff-813b-4aac-8c29-c9a0716d54e2/volumes/kubernetes.io~projected/kube-api-access-9jrqx",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/04d607ff-813b-4aac-8c29-c9a0716d54e2/volumes/kubernetes.io~secret/broker-certs",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/04d607ff-813b-4aac-8c29-c9a0716d54e2/volumes/kubernetes.io~secret/client-ca-cert",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/04d607ff-813b-4aac-8c29-c9a0716d54e2/volumes/kubernetes.io~secret/cluster-ca",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/08627de4-e51e-4e47-ad25-2c898d26d877/volumes/kubernetes.io~projected/kube-api-access-thrtn",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/0ae9989a-1895-478d-a82f-55e7c6b5c939/volumes/kubernetes.io~projected/kube-api-access-k8gp8",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/0ae9989a-1895-478d-a82f-55e7c6b5c939/volumes/kubernetes.io~secret/argocd-repo-server-tls",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/0c381f4e-6bb8-4546-9b1c-41c878a98b2f/volumes/kubernetes.io~projected/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/0c381f4e-6bb8-4546-9b1c-41c878a98b2f/volumes/kubernetes.io~projected/kube-api-access-gvmbx",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/118b61a2-6434-4270-81d6-2ebc616d6e05/volumes/kubernetes.io~projected/kube-api-access-wq9gt",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/118b61a2-6434-4270-81d6-2ebc616d6e05/volumes/kubernetes.io~secret/argocd-repo-server-tls",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/139b476a-4522-4b3e-915e-41fb88120e02/volumes/kubernetes.io~projected/kube-api-access-njjjc",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/1ace0411-0c62-418c-9203-79074145eae5/volumes/kubernetes.io~projected/kube-api-access-tzlhl",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/2b98edd8-ab18-437b-9ed7-6563a80858e2/volumes/kubernetes.io~projected/kube-api-access-dpd4c",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/3cc3835c-5bca-43da-8541-4a5a8d31e849/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/3cc3835c-5bca-43da-8541-4a5a8d31e849/volumes/kubernetes.io~projected/kube-api-access-c9lkw",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/66ba0a72-4cf0-42ab-9842-b4c84648d480/volumes/kubernetes.io~projected/kube-api-access-rxgw5",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/6ba71169-2934-47d0-8a11-3764facb66fd/volumes/kubernetes.io~projected/kube-api-access-v7bbr",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/9591e83b-04de-4535-8766-d262f904abf1/volumes/kubernetes.io~empty-dir/config-out",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/9591e83b-04de-4535-8766-d262f904abf1/volumes/kubernetes.io~projected/kube-api-access-wt8bd",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/9591e83b-04de-4535-8766-d262f904abf1/volumes/kubernetes.io~projected/tls-assets",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/9591e83b-04de-4535-8766-d262f904abf1/volumes/kubernetes.io~secret/config-volume",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/9591e83b-04de-4535-8766-d262f904abf1/volumes/kubernetes.io~secret/web-config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/a66c61ff-d89d-4cf2-950f-04a08da397cb/volumes/kubernetes.io~projected/kube-api-access-8pljd",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/aadc4b0c-b0c3-4390-9e21-1777a26e3cbb/volumes/kubernetes.io~projected/kube-api-access-trl8r",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/b555134d-82f4-4443-90cd-ca080f45970d/volumes/kubernetes.io~projected/kube-api-access-qq8q9",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/dc114bf4-cbee-4b20-8d69-b70138c2b55e/volumes/kubernetes.io~projected/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/dc114bf4-cbee-4b20-8d69-b70138c2b55e/volumes/kubernetes.io~projected/kube-api-access-vb886",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/eba79dc6-066b-4ffc-926a-db46e8683808/volumes/kubernetes.io~projected/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/eba79dc6-066b-4ffc-926a-db46e8683808/volumes/kubernetes.io~projected/kube-api-access-88srn",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/ee4dc63f-a7d3-4a90-b883-1a6bd405a7cd/volumes/kubernetes.io~projected/kube-api-access-b86zc",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/f2af4440-8959-41ec-b0d1-f190a7913180/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061331968\u0000tmpfs\u0000/var/lib/kubelet/pods/f2af4440-8959-41ec-b0d1-f190a7913180/volumes/kubernetes.io~projected/kube-api-access-8x8nk",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061340160\u0000tmpfs\u0000/var/lib/kubelet/pods/08ccc5a1-6d14-4161-8ec7-7389fd4a28f8/volumes/kubernetes.io~projected/kube-api-access-sqjl7",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061340160\u0000tmpfs\u0000/var/lib/kubelet/pods/4524304b-6432-4861-8166-1f64a5cc1a14/volumes/kubernetes.io~projected/kube-api-access-cxj4k",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061340160\u0000tmpfs\u0000/var/lib/kubelet/pods/c2370d91-6e9d-4b5b-b423-32f019cb3b00/volumes/kubernetes.io~projected/kube-api-access-7gbcg",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061340160\u0000tmpfs\u0000/var/lib/kubelet/pods/c2370d91-6e9d-4b5b-b423-32f019cb3b00/volumes/kubernetes.io~secret/broker-certs",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061340160\u0000tmpfs\u0000/var/lib/kubelet/pods/c2370d91-6e9d-4b5b-b423-32f019cb3b00/volumes/kubernetes.io~secret/client-ca-cert",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061340160\u0000tmpfs\u0000/var/lib/kubelet/pods/c2370d91-6e9d-4b5b-b423-32f019cb3b00/volumes/kubernetes.io~secret/cluster-ca",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061340160\u0000tmpfs\u0000/var/lib/kubelet/pods/e34ed263-6619-45ef-b311-656b9397864e/volumes/kubernetes.io~empty-dir/config-out",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061340160\u0000tmpfs\u0000/var/lib/kubelet/pods/e34ed263-6619-45ef-b311-656b9397864e/volumes/kubernetes.io~projected/kube-api-access-8grbp",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061340160\u0000tmpfs\u0000/var/lib/kubelet/pods/e34ed263-6619-45ef-b311-656b9397864e/volumes/kubernetes.io~projected/tls-assets",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061340160\u0000tmpfs\u0000/var/lib/kubelet/pods/e34ed263-6619-45ef-b311-656b9397864e/volumes/kubernetes.io~secret/config-volume",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7061340160\u0000tmpfs\u0000/var/lib/kubelet/pods/e34ed263-6619-45ef-b311-656b9397864e/volumes/kubernetes.io~secret/web-config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7396319232\u0000tmpfs\u0000/var/lib/kubelet/pods/2a9cc845-89aa-4589-a42d-71a5d6e00d98/volumes/kubernetes.io~projected/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7396319232\u0000tmpfs\u0000/var/lib/kubelet/pods/2a9cc845-89aa-4589-a42d-71a5d6e00d98/volumes/kubernetes.io~projected/kube-api-access-hdtgl",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7396319232\u0000tmpfs\u0000/var/lib/kubelet/pods/5e5ec66c-9d9c-4270-ade6-8b5616d7d5a2/volumes/kubernetes.io~empty-dir/config-out",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7396319232\u0000tmpfs\u0000/var/lib/kubelet/pods/5e5ec66c-9d9c-4270-ade6-8b5616d7d5a2/volumes/kubernetes.io~projected/kube-api-access-pcvxp",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7396319232\u0000tmpfs\u0000/var/lib/kubelet/pods/5e5ec66c-9d9c-4270-ade6-8b5616d7d5a2/volumes/kubernetes.io~projected/tls-assets",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7396319232\u0000tmpfs\u0000/var/lib/kubelet/pods/5e5ec66c-9d9c-4270-ade6-8b5616d7d5a2/volumes/kubernetes.io~secret/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7396319232\u0000tmpfs\u0000/var/lib/kubelet/pods/5e5ec66c-9d9c-4270-ade6-8b5616d7d5a2/volumes/kubernetes.io~secret/web-config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7396319232\u0000tmpfs\u0000/var/lib/kubelet/pods/5f4ab5df-1e06-4b24-8640-f4ba10bb3c29/volumes/kubernetes.io~empty-dir/config-out",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7396319232\u0000tmpfs\u0000/var/lib/kubelet/pods/5f4ab5df-1e06-4b24-8640-f4ba10bb3c29/volumes/kubernetes.io~projected/kube-api-access-mtrvx",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7396319232\u0000tmpfs\u0000/var/lib/kubelet/pods/5f4ab5df-1e06-4b24-8640-f4ba10bb3c29/volumes/kubernetes.io~projected/tls-assets",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7396319232\u0000tmpfs\u0000/var/lib/kubelet/pods/5f4ab5df-1e06-4b24-8640-f4ba10bb3c29/volumes/kubernetes.io~secret/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7396319232\u0000tmpfs\u0000/var/lib/kubelet/pods/5f4ab5df-1e06-4b24-8640-f4ba10bb3c29/volumes/kubernetes.io~secret/web-config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7396319232\u0000tmpfs\u0000/var/lib/kubelet/pods/e3ba4a35-9da5-4cdc-b8cf-f50c7890707c/volumes/kubernetes.io~projected/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t\u0000tmpfs\u0000-o\u0000size=7396319232\u0000tmpfs\u0000/var/lib/kubelet/pods/e3ba4a35-9da5-4cdc-b8cf-f50c7890707c/volumes/kubernetes.io~projected/kube-api-access-hh52p",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/host/opt/cni/bin/.cilium-cni.new\u0000/host/opt/cni/bin/cilium-cni",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/host/opt/cni/bin/.loopback.new\u0000/host/opt/cni/bin/loopback",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.0gsNSiuWU1\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.5LkxYPhWpk\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.A7UdddUeNj\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.B3hQQlvKmi\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.BGVbzMPUL1\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.CmpENTL0NF\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.FUAfFzKRir\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.HtdLVciCJK\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.PlGe1AUWpH\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.QXNSiA1RsF\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.RnwxYv63sr\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.U4VtxayePA\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.W4PSEBHfaB\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.WFbB9sgpfA\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.dFX7CB5YVC\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.dPTFnAL7oR\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.gQ69mWXyiR\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.l6igLL0Dr3\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.lttTh0XpMg\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.qmcRMQdmqP\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.uHoULVeGhb\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.v58apTE1LS\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments:
            "/var/lib/update-motd/tmp.vFkxXkUBQ7\u0000/var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/nsenter",
          arguments:
            "--cgroup=/hostproc/1/ns/cgroup\u0000--mount=/hostproc/1/ns/mnt\u0000/opt/cni/bin/cilium-mount\u0000/run/cilium/cgroupv2",
        },
        {
          name: "/usr/bin/nsenter",
          arguments:
            "--mount=/hostproc/1/ns/mnt\u0000/opt/cni/bin/cilium-sysctlfix",
        },
        {
          name: "/usr/bin/promtail",
          arguments:
            "-config.file=/etc/promtail/promtail.yaml\u0000-client.external-labels=cluster=df-tetragon-dev-ce-01\u0000-config.expand-env=true",
          connections: [
            {
              destination_name: "default/Service:kubernetes",
              destination_port: "443",
              bytes_sent: "3303",
              bytes_received: "51869",
            },
          ],
        },
        {
          name: "/usr/bin/ps",
          arguments: "-e\u0000-o\u0000pid,ppid,state,command",
        },
        {
          name: "/usr/bin/python3.9",
          arguments: "/usr/bin/dnf\u0000--debuglevel\u00002\u0000updateinfo",
          connections: [
            {
              destination_name:
                "al2023-repos-us-west-2-de612dc2.s3.dualstack.us-west-2.amazonaws.com",
              destination_port: "443",
              bytes_sent: "8446",
              bytes_received: "50466",
            },
          ],
        },
        {
          name: "/usr/bin/python3.9",
          arguments: "/usr/bin/dnf\u0000check-release-update",
          connections: [
            {
              destination_name:
                "al2023-repos-us-west-2-de612dc2.s3.dualstack.us-west-2.amazonaws.com",
              destination_port: "443",
              bytes_sent: "3163",
              bytes_received: "498318",
            },
          ],
        },
        {
          name: "/usr/bin/python3.9",
          arguments: "/usr/sbin/ebsnvme-id\u0000-u\u0000/dev/nvme1n1",
        },
        {
          name: "/usr/bin/python3.9",
          arguments: "/usr/sbin/ebsnvme-id\u0000-u\u0000/dev/nvme2n1",
        },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.part1Xw5b" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.part4m1JX" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.part6PdPy" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.part6VV3a" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.part9dtQ0" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partBDEMf" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partBbtvc" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partBepMz" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partJsy7f" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partK3o18" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partK6TuU" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partL3GyD" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partNvRMg" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partP5hmc" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partP7n9s" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partPqG3S" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partPwKwt" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partSX3II" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partSnk8m" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partSuwv0" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partSwYOU" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partTSQMr" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partUd1cU" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partX0Tld" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partXKR6a" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partYcs3b" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partYwc8V" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partZVCfT" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partZarqx" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partZeugm" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partaZQ9e" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partc5GFA" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.parteoUki" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partf4axd" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partfWeCb" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partjQ6m1" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partk5jtm" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partoLAaM" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partob2Uz" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partp2NXR" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partpiKKo" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partunACI" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partvS3y0" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partws0CF" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partwwNGb" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/tmp/motd.partyYDK1" },
        { name: "/usr/bin/rm", arguments: "-f\u0000/usr/sbin/ip6tables" },
        {
          name: "/usr/bin/rm",
          arguments: "-f\u0000/usr/sbin/ip6tables-restore",
        },
        {
          name: "/usr/bin/rm",
          arguments: "-f\u0000/usr/sbin/ip6tables-save",
        },
        { name: "/usr/bin/rm", arguments: "-f\u0000/usr/sbin/iptables" },
        {
          name: "/usr/bin/rm",
          arguments: "-f\u0000/usr/sbin/iptables-restore",
        },
        {
          name: "/usr/bin/rm",
          arguments: "-f\u0000/usr/sbin/iptables-save",
        },
        { name: "/usr/bin/rm", arguments: "/hostbin/cilium-mount" },
        { name: "/usr/bin/rm", arguments: "/hostbin/cilium-sysctlfix" },
        {
          name: "/usr/bin/rpm",
          arguments: "-q\u0000--quiet\u0000dnf-plugin-release-notification",
        },
        { name: "/usr/bin/rpm", arguments: "-qa" },
        {
          name: "/usr/bin/ssm-agent-worker",
          connections: [
            {
              destination_name: "169.254.169.254",
              destination_port: "80",
              bytes_sent: "9066",
              bytes_received: "10848",
            },
            {
              destination_name: "52.119.161.149",
              destination_port: "443",
              bytes_sent: "197",
              bytes_received: "153",
            },
            {
              destination_name: "52.119.171.223",
              destination_port: "443",
              bytes_sent: "3659",
              bytes_received: "2999",
            },
            { destination_name: "52.94.177.115", destination_port: "443" },
            {
              destination_name: "52.94.177.136",
              destination_port: "443",
              bytes_sent: "104",
              bytes_received: "449",
            },
            {
              destination_name: "52.94.181.105",
              destination_port: "443",
              bytes_sent: "80",
              bytes_received: "80",
            },
            {
              destination_name: "52.94.181.45",
              destination_port: "443",
              bytes_sent: "224",
              bytes_received: "224",
            },
            {
              destination_name: "52.94.182.119",
              destination_port: "443",
              bytes_sent: "104",
              bytes_received: "144",
            },
            { destination_name: "52.94.184.186", destination_port: "443" },
            {
              destination_name: "52.94.185.42",
              destination_port: "443",
              bytes_sent: "144",
              bytes_received: "449",
            },
            { destination_name: "52.94.186.139", destination_port: "443" },
            { destination_name: "52.94.209.3", destination_port: "443" },
            {
              destination_name: "ec2messages.us-west-2.amazonaws.com",
              destination_port: "443",
              bytes_sent: "3516",
              bytes_received: "6940",
            },
            {
              destination_name: "ssm.us-west-2.amazonaws.com",
              destination_port: "443",
              bytes_sent: "3762",
              bytes_received: "6983",
            },
            {
              destination_name: "ssmmessages.us-west-2.amazonaws.com",
              destination_port: "443",
              bytes_sent: "3235",
              bytes_received: "7264",
            },
          ],
        },
        { name: "/usr/bin/systemd-tmpfiles", arguments: "--clean" },
        {
          name: "/usr/bin/tetragon-oci-hook-setup",
          arguments:
            "install\u0000--interface=nri-hook\u0000--local-install-dir=/hostInstall\u0000--host-install-dir=/opt/tetragon\u0000--oci-hooks.local-dir=/hostHooks\u0000--daemonize\u0000hook-args\u0000--grpc-address=localhost:54321\u0000--fail-allow-namespaces\u0000tetragon",
        },
        {
          name: "/usr/bin/timeout",
          arguments: "30s\u0000/etc/update-motd.d/10-nvidia-eula",
        },
        {
          name: "/usr/bin/timeout",
          arguments: "30s\u0000/etc/update-motd.d/70-available-updates",
        },
        {
          name: "/usr/bin/timeout",
          arguments:
            "30s\u0000/usr/bin/dnf\u0000--debuglevel\u00002\u0000updateinfo",
        },
        {
          name: "/usr/bin/timeout",
          arguments: "30s\u0000/usr/bin/dnf\u0000check-release-update",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/05ac4801-0a14-4aca-b04e-a2c1515c26b1/volume-subpaths/config/grafana/0",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/05ac4801-0a14-4aca-b04e-a2c1515c26b1/volume-subpaths/config/grafana/8",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/05ac4801-0a14-4aca-b04e-a2c1515c26b1/volume-subpaths/config/grafana/9",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/05ac4801-0a14-4aca-b04e-a2c1515c26b1/volumes/kubernetes.io~projected/kube-api-access-zch5d",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/08ccc5a1-6d14-4161-8ec7-7389fd4a28f8/volumes/kubernetes.io~projected/kube-api-access-sqjl7",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/10d70cef-1905-48fb-9a50-2bcd8b1a198b/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/4524304b-6432-4861-8166-1f64a5cc1a14/volumes/kubernetes.io~projected/kube-api-access-cxj4k",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/4e35af66-b8c0-4ef1-a1f2-68e15a674e79/volumes/kubernetes.io~projected/kube-api-access-dhqf9",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/74fb5845-f2cc-4237-a1dd-730cd199d4d8/volumes/kubernetes.io~projected/kube-api-access-l2xz7",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/84cc34b9-3d9c-4312-8bdf-e4bf132ee449/volumes/kubernetes.io~projected/kube-api-access-8kj6s",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/92169e69-a62b-4065-a709-de028db31122/volume-subpaths/config-emptydir/opensearch/0",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/92169e69-a62b-4065-a709-de028db31122/volume-subpaths/config/configfile/1",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/c2370d91-6e9d-4b5b-b423-32f019cb3b00/volumes/kubernetes.io~empty-dir/ready-files",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/c2370d91-6e9d-4b5b-b423-32f019cb3b00/volumes/kubernetes.io~empty-dir/strimzi-tmp",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/c2370d91-6e9d-4b5b-b423-32f019cb3b00/volumes/kubernetes.io~projected/kube-api-access-7gbcg",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/c2370d91-6e9d-4b5b-b423-32f019cb3b00/volumes/kubernetes.io~secret/broker-certs",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/c2370d91-6e9d-4b5b-b423-32f019cb3b00/volumes/kubernetes.io~secret/client-ca-cert",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/c2370d91-6e9d-4b5b-b423-32f019cb3b00/volumes/kubernetes.io~secret/cluster-ca",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/df66ebde-972b-419f-8b86-3ed6530dd871/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/e34ed263-6619-45ef-b311-656b9397864e/volume-subpaths/web-config/alertmanager/4",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/e34ed263-6619-45ef-b311-656b9397864e/volumes/kubernetes.io~empty-dir/config-out",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/e34ed263-6619-45ef-b311-656b9397864e/volumes/kubernetes.io~projected/kube-api-access-8grbp",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/e34ed263-6619-45ef-b311-656b9397864e/volumes/kubernetes.io~projected/tls-assets",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/e34ed263-6619-45ef-b311-656b9397864e/volumes/kubernetes.io~secret/config-volume",
        },
        {
          name: "/usr/bin/umount",
          arguments:
            "/var/lib/kubelet/pods/e34ed263-6619-45ef-b311-656b9397864e/volumes/kubernetes.io~secret/web-config",
        },
        { name: "/usr/bin/uname", arguments: "-rs" },
        { name: "/usr/bin/unpigz", arguments: "-d\u0000-c" },
        {
          name: "/usr/bin/vector",
          arguments: "--config-dir\u0000/etc/vector/",
          connections: [
            {
              destination_name:
                "http-inputs.cisco-ngfwbu-valent.splunkcloud.com",
              destination_port: "443",
              bytes_sent: "6074342",
              bytes_received: "56674",
            },
          ],
        },
        { name: "/usr/bin/wc", arguments: "-l" },
        { name: "/usr/lib/systemd/systemd-sysctl" },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/cilium\u0000--prefix=/net/ipv4/neigh/cilium\u0000--prefix=/net/ipv6/conf/cilium\u0000--prefix=/net/ipv6/neigh/cilium",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/cilium_host\u0000--prefix=/net/ipv4/neigh/cilium_host\u0000--prefix=/net/ipv6/conf/cilium_host\u0000--prefix=/net/ipv6/neigh/cilium_host",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/cilium_net\u0000--prefix=/net/ipv4/neigh/cilium_net\u0000--prefix=/net/ipv6/conf/cilium_net\u0000--prefix=/net/ipv6/neigh/cilium_net",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/ens6\u0000--prefix=/net/ipv4/neigh/ens6\u0000--prefix=/net/ipv6/conf/ens6\u0000--prefix=/net/ipv6/neigh/ens6",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc01c6d73ac9af\u0000--prefix=/net/ipv4/neigh/lxc01c6d73ac9af\u0000--prefix=/net/ipv6/conf/lxc01c6d73ac9af\u0000--prefix=/net/ipv6/neigh/lxc01c6d73ac9af",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc01e4b82b12d5\u0000--prefix=/net/ipv4/neigh/lxc01e4b82b12d5\u0000--prefix=/net/ipv6/conf/lxc01e4b82b12d5\u0000--prefix=/net/ipv6/neigh/lxc01e4b82b12d5",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc0265a5de9550\u0000--prefix=/net/ipv4/neigh/lxc0265a5de9550\u0000--prefix=/net/ipv6/conf/lxc0265a5de9550\u0000--prefix=/net/ipv6/neigh/lxc0265a5de9550",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc0318f775136f\u0000--prefix=/net/ipv4/neigh/lxc0318f775136f\u0000--prefix=/net/ipv6/conf/lxc0318f775136f\u0000--prefix=/net/ipv6/neigh/lxc0318f775136f",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc06119829ae18\u0000--prefix=/net/ipv4/neigh/lxc06119829ae18\u0000--prefix=/net/ipv6/conf/lxc06119829ae18\u0000--prefix=/net/ipv6/neigh/lxc06119829ae18",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc06a4bea3a1c2\u0000--prefix=/net/ipv4/neigh/lxc06a4bea3a1c2\u0000--prefix=/net/ipv6/conf/lxc06a4bea3a1c2\u0000--prefix=/net/ipv6/neigh/lxc06a4bea3a1c2",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc087c8a160770\u0000--prefix=/net/ipv4/neigh/lxc087c8a160770\u0000--prefix=/net/ipv6/conf/lxc087c8a160770\u0000--prefix=/net/ipv6/neigh/lxc087c8a160770",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc0f4383076d8a\u0000--prefix=/net/ipv4/neigh/lxc0f4383076d8a\u0000--prefix=/net/ipv6/conf/lxc0f4383076d8a\u0000--prefix=/net/ipv6/neigh/lxc0f4383076d8a",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc13a1657ff277\u0000--prefix=/net/ipv4/neigh/lxc13a1657ff277\u0000--prefix=/net/ipv6/conf/lxc13a1657ff277\u0000--prefix=/net/ipv6/neigh/lxc13a1657ff277",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc14f6dd8a67a7\u0000--prefix=/net/ipv4/neigh/lxc14f6dd8a67a7\u0000--prefix=/net/ipv6/conf/lxc14f6dd8a67a7\u0000--prefix=/net/ipv6/neigh/lxc14f6dd8a67a7",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc18a6cfe801b1\u0000--prefix=/net/ipv4/neigh/lxc18a6cfe801b1\u0000--prefix=/net/ipv6/conf/lxc18a6cfe801b1\u0000--prefix=/net/ipv6/neigh/lxc18a6cfe801b1",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc1b086f7099bd\u0000--prefix=/net/ipv4/neigh/lxc1b086f7099bd\u0000--prefix=/net/ipv6/conf/lxc1b086f7099bd\u0000--prefix=/net/ipv6/neigh/lxc1b086f7099bd",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc1b19dc18f2f9\u0000--prefix=/net/ipv4/neigh/lxc1b19dc18f2f9\u0000--prefix=/net/ipv6/conf/lxc1b19dc18f2f9\u0000--prefix=/net/ipv6/neigh/lxc1b19dc18f2f9",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc1c44e0ae7531\u0000--prefix=/net/ipv4/neigh/lxc1c44e0ae7531\u0000--prefix=/net/ipv6/conf/lxc1c44e0ae7531\u0000--prefix=/net/ipv6/neigh/lxc1c44e0ae7531",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc23691794a6a7\u0000--prefix=/net/ipv4/neigh/lxc23691794a6a7\u0000--prefix=/net/ipv6/conf/lxc23691794a6a7\u0000--prefix=/net/ipv6/neigh/lxc23691794a6a7",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc2370145d71f3\u0000--prefix=/net/ipv4/neigh/lxc2370145d71f3\u0000--prefix=/net/ipv6/conf/lxc2370145d71f3\u0000--prefix=/net/ipv6/neigh/lxc2370145d71f3",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc2433c4d4273a\u0000--prefix=/net/ipv4/neigh/lxc2433c4d4273a\u0000--prefix=/net/ipv6/conf/lxc2433c4d4273a\u0000--prefix=/net/ipv6/neigh/lxc2433c4d4273a",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc2475dfc7e95e\u0000--prefix=/net/ipv4/neigh/lxc2475dfc7e95e\u0000--prefix=/net/ipv6/conf/lxc2475dfc7e95e\u0000--prefix=/net/ipv6/neigh/lxc2475dfc7e95e",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc24a5f80ed36a\u0000--prefix=/net/ipv4/neigh/lxc24a5f80ed36a\u0000--prefix=/net/ipv6/conf/lxc24a5f80ed36a\u0000--prefix=/net/ipv6/neigh/lxc24a5f80ed36a",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc265432f71017\u0000--prefix=/net/ipv4/neigh/lxc265432f71017\u0000--prefix=/net/ipv6/conf/lxc265432f71017\u0000--prefix=/net/ipv6/neigh/lxc265432f71017",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc2696a70c3247\u0000--prefix=/net/ipv4/neigh/lxc2696a70c3247\u0000--prefix=/net/ipv6/conf/lxc2696a70c3247\u0000--prefix=/net/ipv6/neigh/lxc2696a70c3247",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc26c89d8a13d7\u0000--prefix=/net/ipv4/neigh/lxc26c89d8a13d7\u0000--prefix=/net/ipv6/conf/lxc26c89d8a13d7\u0000--prefix=/net/ipv6/neigh/lxc26c89d8a13d7",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc277262bfb65d\u0000--prefix=/net/ipv4/neigh/lxc277262bfb65d\u0000--prefix=/net/ipv6/conf/lxc277262bfb65d\u0000--prefix=/net/ipv6/neigh/lxc277262bfb65d",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc2c69368de16c\u0000--prefix=/net/ipv4/neigh/lxc2c69368de16c\u0000--prefix=/net/ipv6/conf/lxc2c69368de16c\u0000--prefix=/net/ipv6/neigh/lxc2c69368de16c",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc2dfd4bce9718\u0000--prefix=/net/ipv4/neigh/lxc2dfd4bce9718\u0000--prefix=/net/ipv6/conf/lxc2dfd4bce9718\u0000--prefix=/net/ipv6/neigh/lxc2dfd4bce9718",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc2e6a5d3ba3a2\u0000--prefix=/net/ipv4/neigh/lxc2e6a5d3ba3a2\u0000--prefix=/net/ipv6/conf/lxc2e6a5d3ba3a2\u0000--prefix=/net/ipv6/neigh/lxc2e6a5d3ba3a2",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc2ed52e8710c7\u0000--prefix=/net/ipv4/neigh/lxc2ed52e8710c7\u0000--prefix=/net/ipv6/conf/lxc2ed52e8710c7\u0000--prefix=/net/ipv6/neigh/lxc2ed52e8710c7",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc377166184c17\u0000--prefix=/net/ipv4/neigh/lxc377166184c17\u0000--prefix=/net/ipv6/conf/lxc377166184c17\u0000--prefix=/net/ipv6/neigh/lxc377166184c17",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc3df7978e9672\u0000--prefix=/net/ipv4/neigh/lxc3df7978e9672\u0000--prefix=/net/ipv6/conf/lxc3df7978e9672\u0000--prefix=/net/ipv6/neigh/lxc3df7978e9672",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc3e7bb0251c04\u0000--prefix=/net/ipv4/neigh/lxc3e7bb0251c04\u0000--prefix=/net/ipv6/conf/lxc3e7bb0251c04\u0000--prefix=/net/ipv6/neigh/lxc3e7bb0251c04",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc406e51304901\u0000--prefix=/net/ipv4/neigh/lxc406e51304901\u0000--prefix=/net/ipv6/conf/lxc406e51304901\u0000--prefix=/net/ipv6/neigh/lxc406e51304901",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc41d14bc0d8e1\u0000--prefix=/net/ipv4/neigh/lxc41d14bc0d8e1\u0000--prefix=/net/ipv6/conf/lxc41d14bc0d8e1\u0000--prefix=/net/ipv6/neigh/lxc41d14bc0d8e1",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc43d99f87c8fd\u0000--prefix=/net/ipv4/neigh/lxc43d99f87c8fd\u0000--prefix=/net/ipv6/conf/lxc43d99f87c8fd\u0000--prefix=/net/ipv6/neigh/lxc43d99f87c8fd",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc4429d3917cb6\u0000--prefix=/net/ipv4/neigh/lxc4429d3917cb6\u0000--prefix=/net/ipv6/conf/lxc4429d3917cb6\u0000--prefix=/net/ipv6/neigh/lxc4429d3917cb6",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc45991e9d6d16\u0000--prefix=/net/ipv4/neigh/lxc45991e9d6d16\u0000--prefix=/net/ipv6/conf/lxc45991e9d6d16\u0000--prefix=/net/ipv6/neigh/lxc45991e9d6d16",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc479dd61fe3c5\u0000--prefix=/net/ipv4/neigh/lxc479dd61fe3c5\u0000--prefix=/net/ipv6/conf/lxc479dd61fe3c5\u0000--prefix=/net/ipv6/neigh/lxc479dd61fe3c5",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc48e86bee7f5c\u0000--prefix=/net/ipv4/neigh/lxc48e86bee7f5c\u0000--prefix=/net/ipv6/conf/lxc48e86bee7f5c\u0000--prefix=/net/ipv6/neigh/lxc48e86bee7f5c",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc4a868c0b3f0d\u0000--prefix=/net/ipv4/neigh/lxc4a868c0b3f0d\u0000--prefix=/net/ipv6/conf/lxc4a868c0b3f0d\u0000--prefix=/net/ipv6/neigh/lxc4a868c0b3f0d",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc4d0fbf2a6226\u0000--prefix=/net/ipv4/neigh/lxc4d0fbf2a6226\u0000--prefix=/net/ipv6/conf/lxc4d0fbf2a6226\u0000--prefix=/net/ipv6/neigh/lxc4d0fbf2a6226",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc558b3082861c\u0000--prefix=/net/ipv4/neigh/lxc558b3082861c\u0000--prefix=/net/ipv6/conf/lxc558b3082861c\u0000--prefix=/net/ipv6/neigh/lxc558b3082861c",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc595ec8153e7a\u0000--prefix=/net/ipv4/neigh/lxc595ec8153e7a\u0000--prefix=/net/ipv6/conf/lxc595ec8153e7a\u0000--prefix=/net/ipv6/neigh/lxc595ec8153e7a",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc596c87f3525a\u0000--prefix=/net/ipv4/neigh/lxc596c87f3525a\u0000--prefix=/net/ipv6/conf/lxc596c87f3525a\u0000--prefix=/net/ipv6/neigh/lxc596c87f3525a",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc5a3c188ded66\u0000--prefix=/net/ipv4/neigh/lxc5a3c188ded66\u0000--prefix=/net/ipv6/conf/lxc5a3c188ded66\u0000--prefix=/net/ipv6/neigh/lxc5a3c188ded66",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc5c5d19cbda99\u0000--prefix=/net/ipv4/neigh/lxc5c5d19cbda99\u0000--prefix=/net/ipv6/conf/lxc5c5d19cbda99\u0000--prefix=/net/ipv6/neigh/lxc5c5d19cbda99",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc5d21df548e59\u0000--prefix=/net/ipv4/neigh/lxc5d21df548e59\u0000--prefix=/net/ipv6/conf/lxc5d21df548e59\u0000--prefix=/net/ipv6/neigh/lxc5d21df548e59",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc5fc35ea0a4b4\u0000--prefix=/net/ipv4/neigh/lxc5fc35ea0a4b4\u0000--prefix=/net/ipv6/conf/lxc5fc35ea0a4b4\u0000--prefix=/net/ipv6/neigh/lxc5fc35ea0a4b4",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc61c87915292b\u0000--prefix=/net/ipv4/neigh/lxc61c87915292b\u0000--prefix=/net/ipv6/conf/lxc61c87915292b\u0000--prefix=/net/ipv6/neigh/lxc61c87915292b",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc62836b14c256\u0000--prefix=/net/ipv4/neigh/lxc62836b14c256\u0000--prefix=/net/ipv6/conf/lxc62836b14c256\u0000--prefix=/net/ipv6/neigh/lxc62836b14c256",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc62f91a144b54\u0000--prefix=/net/ipv4/neigh/lxc62f91a144b54\u0000--prefix=/net/ipv6/conf/lxc62f91a144b54\u0000--prefix=/net/ipv6/neigh/lxc62f91a144b54",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc6480fc0b392c\u0000--prefix=/net/ipv4/neigh/lxc6480fc0b392c\u0000--prefix=/net/ipv6/conf/lxc6480fc0b392c\u0000--prefix=/net/ipv6/neigh/lxc6480fc0b392c",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc66913120575c\u0000--prefix=/net/ipv4/neigh/lxc66913120575c\u0000--prefix=/net/ipv6/conf/lxc66913120575c\u0000--prefix=/net/ipv6/neigh/lxc66913120575c",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc66fe2c8083be\u0000--prefix=/net/ipv4/neigh/lxc66fe2c8083be\u0000--prefix=/net/ipv6/conf/lxc66fe2c8083be\u0000--prefix=/net/ipv6/neigh/lxc66fe2c8083be",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc6756b8213654\u0000--prefix=/net/ipv4/neigh/lxc6756b8213654\u0000--prefix=/net/ipv6/conf/lxc6756b8213654\u0000--prefix=/net/ipv6/neigh/lxc6756b8213654",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc67f67d3e16d7\u0000--prefix=/net/ipv4/neigh/lxc67f67d3e16d7\u0000--prefix=/net/ipv6/conf/lxc67f67d3e16d7\u0000--prefix=/net/ipv6/neigh/lxc67f67d3e16d7",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc6c08531a5b47\u0000--prefix=/net/ipv4/neigh/lxc6c08531a5b47\u0000--prefix=/net/ipv6/conf/lxc6c08531a5b47\u0000--prefix=/net/ipv6/neigh/lxc6c08531a5b47",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc702f33cd39e6\u0000--prefix=/net/ipv4/neigh/lxc702f33cd39e6\u0000--prefix=/net/ipv6/conf/lxc702f33cd39e6\u0000--prefix=/net/ipv6/neigh/lxc702f33cd39e6",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc752b55e33264\u0000--prefix=/net/ipv4/neigh/lxc752b55e33264\u0000--prefix=/net/ipv6/conf/lxc752b55e33264\u0000--prefix=/net/ipv6/neigh/lxc752b55e33264",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc7692aeafb0cf\u0000--prefix=/net/ipv4/neigh/lxc7692aeafb0cf\u0000--prefix=/net/ipv6/conf/lxc7692aeafb0cf\u0000--prefix=/net/ipv6/neigh/lxc7692aeafb0cf",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc77b4bf9aaff7\u0000--prefix=/net/ipv4/neigh/lxc77b4bf9aaff7\u0000--prefix=/net/ipv6/conf/lxc77b4bf9aaff7\u0000--prefix=/net/ipv6/neigh/lxc77b4bf9aaff7",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc7c08c8e96c44\u0000--prefix=/net/ipv4/neigh/lxc7c08c8e96c44\u0000--prefix=/net/ipv6/conf/lxc7c08c8e96c44\u0000--prefix=/net/ipv6/neigh/lxc7c08c8e96c44",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc803ecc20d441\u0000--prefix=/net/ipv4/neigh/lxc803ecc20d441\u0000--prefix=/net/ipv6/conf/lxc803ecc20d441\u0000--prefix=/net/ipv6/neigh/lxc803ecc20d441",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc809f89ad774e\u0000--prefix=/net/ipv4/neigh/lxc809f89ad774e\u0000--prefix=/net/ipv6/conf/lxc809f89ad774e\u0000--prefix=/net/ipv6/neigh/lxc809f89ad774e",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc80e2549ff1d3\u0000--prefix=/net/ipv4/neigh/lxc80e2549ff1d3\u0000--prefix=/net/ipv6/conf/lxc80e2549ff1d3\u0000--prefix=/net/ipv6/neigh/lxc80e2549ff1d3",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc818457350e90\u0000--prefix=/net/ipv4/neigh/lxc818457350e90\u0000--prefix=/net/ipv6/conf/lxc818457350e90\u0000--prefix=/net/ipv6/neigh/lxc818457350e90",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc824354ddd3c1\u0000--prefix=/net/ipv4/neigh/lxc824354ddd3c1\u0000--prefix=/net/ipv6/conf/lxc824354ddd3c1\u0000--prefix=/net/ipv6/neigh/lxc824354ddd3c1",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc84a219c93943\u0000--prefix=/net/ipv4/neigh/lxc84a219c93943\u0000--prefix=/net/ipv6/conf/lxc84a219c93943\u0000--prefix=/net/ipv6/neigh/lxc84a219c93943",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc8749664badba\u0000--prefix=/net/ipv4/neigh/lxc8749664badba\u0000--prefix=/net/ipv6/conf/lxc8749664badba\u0000--prefix=/net/ipv6/neigh/lxc8749664badba",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc8750fedde9c3\u0000--prefix=/net/ipv4/neigh/lxc8750fedde9c3\u0000--prefix=/net/ipv6/conf/lxc8750fedde9c3\u0000--prefix=/net/ipv6/neigh/lxc8750fedde9c3",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc877604582d0e\u0000--prefix=/net/ipv4/neigh/lxc877604582d0e\u0000--prefix=/net/ipv6/conf/lxc877604582d0e\u0000--prefix=/net/ipv6/neigh/lxc877604582d0e",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc882949c9e413\u0000--prefix=/net/ipv4/neigh/lxc882949c9e413\u0000--prefix=/net/ipv6/conf/lxc882949c9e413\u0000--prefix=/net/ipv6/neigh/lxc882949c9e413",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc88d7479e369c\u0000--prefix=/net/ipv4/neigh/lxc88d7479e369c\u0000--prefix=/net/ipv6/conf/lxc88d7479e369c\u0000--prefix=/net/ipv6/neigh/lxc88d7479e369c",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc8970d95cbec2\u0000--prefix=/net/ipv4/neigh/lxc8970d95cbec2\u0000--prefix=/net/ipv6/conf/lxc8970d95cbec2\u0000--prefix=/net/ipv6/neigh/lxc8970d95cbec2",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc8d7c0ddbfa0b\u0000--prefix=/net/ipv4/neigh/lxc8d7c0ddbfa0b\u0000--prefix=/net/ipv6/conf/lxc8d7c0ddbfa0b\u0000--prefix=/net/ipv6/neigh/lxc8d7c0ddbfa0b",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc8fb92725f80b\u0000--prefix=/net/ipv4/neigh/lxc8fb92725f80b\u0000--prefix=/net/ipv6/conf/lxc8fb92725f80b\u0000--prefix=/net/ipv6/neigh/lxc8fb92725f80b",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc913c9f96533e\u0000--prefix=/net/ipv4/neigh/lxc913c9f96533e\u0000--prefix=/net/ipv6/conf/lxc913c9f96533e\u0000--prefix=/net/ipv6/neigh/lxc913c9f96533e",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc9327e4554128\u0000--prefix=/net/ipv4/neigh/lxc9327e4554128\u0000--prefix=/net/ipv6/conf/lxc9327e4554128\u0000--prefix=/net/ipv6/neigh/lxc9327e4554128",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc97b57774cd45\u0000--prefix=/net/ipv4/neigh/lxc97b57774cd45\u0000--prefix=/net/ipv6/conf/lxc97b57774cd45\u0000--prefix=/net/ipv6/neigh/lxc97b57774cd45",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc97dc1c976a2c\u0000--prefix=/net/ipv4/neigh/lxc97dc1c976a2c\u0000--prefix=/net/ipv6/conf/lxc97dc1c976a2c\u0000--prefix=/net/ipv6/neigh/lxc97dc1c976a2c",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc9a995d1f824b\u0000--prefix=/net/ipv4/neigh/lxc9a995d1f824b\u0000--prefix=/net/ipv6/conf/lxc9a995d1f824b\u0000--prefix=/net/ipv6/neigh/lxc9a995d1f824b",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc9c3cc9f2045c\u0000--prefix=/net/ipv4/neigh/lxc9c3cc9f2045c\u0000--prefix=/net/ipv6/conf/lxc9c3cc9f2045c\u0000--prefix=/net/ipv6/neigh/lxc9c3cc9f2045c",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc9c89600540a7\u0000--prefix=/net/ipv4/neigh/lxc9c89600540a7\u0000--prefix=/net/ipv6/conf/lxc9c89600540a7\u0000--prefix=/net/ipv6/neigh/lxc9c89600540a7",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc9f31d65ddcf3\u0000--prefix=/net/ipv4/neigh/lxc9f31d65ddcf3\u0000--prefix=/net/ipv6/conf/lxc9f31d65ddcf3\u0000--prefix=/net/ipv6/neigh/lxc9f31d65ddcf3",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc_health\u0000--prefix=/net/ipv4/neigh/lxc_health\u0000--prefix=/net/ipv6/conf/lxc_health\u0000--prefix=/net/ipv6/neigh/lxc_health",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxca0e3db39c96d\u0000--prefix=/net/ipv4/neigh/lxca0e3db39c96d\u0000--prefix=/net/ipv6/conf/lxca0e3db39c96d\u0000--prefix=/net/ipv6/neigh/lxca0e3db39c96d",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxca146e4d261a6\u0000--prefix=/net/ipv4/neigh/lxca146e4d261a6\u0000--prefix=/net/ipv6/conf/lxca146e4d261a6\u0000--prefix=/net/ipv6/neigh/lxca146e4d261a6",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcac7cefe3bd6d\u0000--prefix=/net/ipv4/neigh/lxcac7cefe3bd6d\u0000--prefix=/net/ipv6/conf/lxcac7cefe3bd6d\u0000--prefix=/net/ipv6/neigh/lxcac7cefe3bd6d",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcb1b1ef197f49\u0000--prefix=/net/ipv4/neigh/lxcb1b1ef197f49\u0000--prefix=/net/ipv6/conf/lxcb1b1ef197f49\u0000--prefix=/net/ipv6/neigh/lxcb1b1ef197f49",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcb266fa195fbb\u0000--prefix=/net/ipv4/neigh/lxcb266fa195fbb\u0000--prefix=/net/ipv6/conf/lxcb266fa195fbb\u0000--prefix=/net/ipv6/neigh/lxcb266fa195fbb",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcb4b51921a701\u0000--prefix=/net/ipv4/neigh/lxcb4b51921a701\u0000--prefix=/net/ipv6/conf/lxcb4b51921a701\u0000--prefix=/net/ipv6/neigh/lxcb4b51921a701",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcb9fd12fb31fc\u0000--prefix=/net/ipv4/neigh/lxcb9fd12fb31fc\u0000--prefix=/net/ipv6/conf/lxcb9fd12fb31fc\u0000--prefix=/net/ipv6/neigh/lxcb9fd12fb31fc",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcbababa5b64bd\u0000--prefix=/net/ipv4/neigh/lxcbababa5b64bd\u0000--prefix=/net/ipv6/conf/lxcbababa5b64bd\u0000--prefix=/net/ipv6/neigh/lxcbababa5b64bd",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcbd2921478045\u0000--prefix=/net/ipv4/neigh/lxcbd2921478045\u0000--prefix=/net/ipv6/conf/lxcbd2921478045\u0000--prefix=/net/ipv6/neigh/lxcbd2921478045",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcc13a171cf57f\u0000--prefix=/net/ipv4/neigh/lxcc13a171cf57f\u0000--prefix=/net/ipv6/conf/lxcc13a171cf57f\u0000--prefix=/net/ipv6/neigh/lxcc13a171cf57f",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcc28df8f30c30\u0000--prefix=/net/ipv4/neigh/lxcc28df8f30c30\u0000--prefix=/net/ipv6/conf/lxcc28df8f30c30\u0000--prefix=/net/ipv6/neigh/lxcc28df8f30c30",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcc3bebce1df0e\u0000--prefix=/net/ipv4/neigh/lxcc3bebce1df0e\u0000--prefix=/net/ipv6/conf/lxcc3bebce1df0e\u0000--prefix=/net/ipv6/neigh/lxcc3bebce1df0e",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcc4bedf68dc5a\u0000--prefix=/net/ipv4/neigh/lxcc4bedf68dc5a\u0000--prefix=/net/ipv6/conf/lxcc4bedf68dc5a\u0000--prefix=/net/ipv6/neigh/lxcc4bedf68dc5a",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcc85a9ec430ce\u0000--prefix=/net/ipv4/neigh/lxcc85a9ec430ce\u0000--prefix=/net/ipv6/conf/lxcc85a9ec430ce\u0000--prefix=/net/ipv6/neigh/lxcc85a9ec430ce",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcc89d2c09e44a\u0000--prefix=/net/ipv4/neigh/lxcc89d2c09e44a\u0000--prefix=/net/ipv6/conf/lxcc89d2c09e44a\u0000--prefix=/net/ipv6/neigh/lxcc89d2c09e44a",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcca705ae705cf\u0000--prefix=/net/ipv4/neigh/lxcca705ae705cf\u0000--prefix=/net/ipv6/conf/lxcca705ae705cf\u0000--prefix=/net/ipv6/neigh/lxcca705ae705cf",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxccb7f492bd7f4\u0000--prefix=/net/ipv4/neigh/lxccb7f492bd7f4\u0000--prefix=/net/ipv6/conf/lxccb7f492bd7f4\u0000--prefix=/net/ipv6/neigh/lxccb7f492bd7f4",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcd35a4cdbeb2b\u0000--prefix=/net/ipv4/neigh/lxcd35a4cdbeb2b\u0000--prefix=/net/ipv6/conf/lxcd35a4cdbeb2b\u0000--prefix=/net/ipv6/neigh/lxcd35a4cdbeb2b",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcd667644e7fc1\u0000--prefix=/net/ipv4/neigh/lxcd667644e7fc1\u0000--prefix=/net/ipv6/conf/lxcd667644e7fc1\u0000--prefix=/net/ipv6/neigh/lxcd667644e7fc1",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcdad3a05a3d73\u0000--prefix=/net/ipv4/neigh/lxcdad3a05a3d73\u0000--prefix=/net/ipv6/conf/lxcdad3a05a3d73\u0000--prefix=/net/ipv6/neigh/lxcdad3a05a3d73",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcdd3ee509817a\u0000--prefix=/net/ipv4/neigh/lxcdd3ee509817a\u0000--prefix=/net/ipv6/conf/lxcdd3ee509817a\u0000--prefix=/net/ipv6/neigh/lxcdd3ee509817a",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcdf0c112053b9\u0000--prefix=/net/ipv4/neigh/lxcdf0c112053b9\u0000--prefix=/net/ipv6/conf/lxcdf0c112053b9\u0000--prefix=/net/ipv6/neigh/lxcdf0c112053b9",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxce04e6d8b6939\u0000--prefix=/net/ipv4/neigh/lxce04e6d8b6939\u0000--prefix=/net/ipv6/conf/lxce04e6d8b6939\u0000--prefix=/net/ipv6/neigh/lxce04e6d8b6939",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxce749d5478320\u0000--prefix=/net/ipv4/neigh/lxce749d5478320\u0000--prefix=/net/ipv6/conf/lxce749d5478320\u0000--prefix=/net/ipv6/neigh/lxce749d5478320",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxce762c7b7b80c\u0000--prefix=/net/ipv4/neigh/lxce762c7b7b80c\u0000--prefix=/net/ipv6/conf/lxce762c7b7b80c\u0000--prefix=/net/ipv6/neigh/lxce762c7b7b80c",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxce9b647775a5d\u0000--prefix=/net/ipv4/neigh/lxce9b647775a5d\u0000--prefix=/net/ipv6/conf/lxce9b647775a5d\u0000--prefix=/net/ipv6/neigh/lxce9b647775a5d",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxceec29a3b2f55\u0000--prefix=/net/ipv4/neigh/lxceec29a3b2f55\u0000--prefix=/net/ipv6/conf/lxceec29a3b2f55\u0000--prefix=/net/ipv6/neigh/lxceec29a3b2f55",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcf0a668d56324\u0000--prefix=/net/ipv4/neigh/lxcf0a668d56324\u0000--prefix=/net/ipv6/conf/lxcf0a668d56324\u0000--prefix=/net/ipv6/neigh/lxcf0a668d56324",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcf18d0e3d04ee\u0000--prefix=/net/ipv4/neigh/lxcf18d0e3d04ee\u0000--prefix=/net/ipv6/conf/lxcf18d0e3d04ee\u0000--prefix=/net/ipv6/neigh/lxcf18d0e3d04ee",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcf1dbd10fb4cc\u0000--prefix=/net/ipv4/neigh/lxcf1dbd10fb4cc\u0000--prefix=/net/ipv6/conf/lxcf1dbd10fb4cc\u0000--prefix=/net/ipv6/neigh/lxcf1dbd10fb4cc",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcf2de92dd889b\u0000--prefix=/net/ipv4/neigh/lxcf2de92dd889b\u0000--prefix=/net/ipv6/conf/lxcf2de92dd889b\u0000--prefix=/net/ipv6/neigh/lxcf2de92dd889b",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcf4b40826e96f\u0000--prefix=/net/ipv4/neigh/lxcf4b40826e96f\u0000--prefix=/net/ipv6/conf/lxcf4b40826e96f\u0000--prefix=/net/ipv6/neigh/lxcf4b40826e96f",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcf7381b4c4247\u0000--prefix=/net/ipv4/neigh/lxcf7381b4c4247\u0000--prefix=/net/ipv6/conf/lxcf7381b4c4247\u0000--prefix=/net/ipv6/neigh/lxcf7381b4c4247",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcf7a8b4efbda3\u0000--prefix=/net/ipv4/neigh/lxcf7a8b4efbda3\u0000--prefix=/net/ipv6/conf/lxcf7a8b4efbda3\u0000--prefix=/net/ipv6/neigh/lxcf7a8b4efbda3",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcf93ec0570717\u0000--prefix=/net/ipv4/neigh/lxcf93ec0570717\u0000--prefix=/net/ipv6/conf/lxcf93ec0570717\u0000--prefix=/net/ipv6/neigh/lxcf93ec0570717",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcf9f6cf6cc4b5\u0000--prefix=/net/ipv4/neigh/lxcf9f6cf6cc4b5\u0000--prefix=/net/ipv6/conf/lxcf9f6cf6cc4b5\u0000--prefix=/net/ipv6/neigh/lxcf9f6cf6cc4b5",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcfb4f8047e0f2\u0000--prefix=/net/ipv4/neigh/lxcfb4f8047e0f2\u0000--prefix=/net/ipv6/conf/lxcfb4f8047e0f2\u0000--prefix=/net/ipv6/neigh/lxcfb4f8047e0f2",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcfbe820b3e89b\u0000--prefix=/net/ipv4/neigh/lxcfbe820b3e89b\u0000--prefix=/net/ipv6/conf/lxcfbe820b3e89b\u0000--prefix=/net/ipv6/neigh/lxcfbe820b3e89b",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcffaf7bf130d6\u0000--prefix=/net/ipv4/neigh/lxcffaf7bf130d6\u0000--prefix=/net/ipv6/conf/lxcffaf7bf130d6\u0000--prefix=/net/ipv6/neigh/lxcffaf7bf130d6",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp04fb7\u0000--prefix=/net/ipv4/neigh/tmp04fb7\u0000--prefix=/net/ipv6/conf/tmp04fb7\u0000--prefix=/net/ipv6/neigh/tmp04fb7",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp09182\u0000--prefix=/net/ipv4/neigh/tmp09182\u0000--prefix=/net/ipv6/conf/tmp09182\u0000--prefix=/net/ipv6/neigh/tmp09182",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp098e3\u0000--prefix=/net/ipv4/neigh/tmp098e3\u0000--prefix=/net/ipv6/conf/tmp098e3\u0000--prefix=/net/ipv6/neigh/tmp098e3",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp0c096\u0000--prefix=/net/ipv4/neigh/tmp0c096\u0000--prefix=/net/ipv6/conf/tmp0c096\u0000--prefix=/net/ipv6/neigh/tmp0c096",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp13436\u0000--prefix=/net/ipv4/neigh/tmp13436\u0000--prefix=/net/ipv6/conf/tmp13436\u0000--prefix=/net/ipv6/neigh/tmp13436",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp139a6\u0000--prefix=/net/ipv4/neigh/tmp139a6\u0000--prefix=/net/ipv6/conf/tmp139a6\u0000--prefix=/net/ipv6/neigh/tmp139a6",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp13a11\u0000--prefix=/net/ipv4/neigh/tmp13a11\u0000--prefix=/net/ipv6/conf/tmp13a11\u0000--prefix=/net/ipv6/neigh/tmp13a11",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp1b849\u0000--prefix=/net/ipv4/neigh/tmp1b849\u0000--prefix=/net/ipv6/conf/tmp1b849\u0000--prefix=/net/ipv6/neigh/tmp1b849",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp1ca1e\u0000--prefix=/net/ipv4/neigh/tmp1ca1e\u0000--prefix=/net/ipv6/conf/tmp1ca1e\u0000--prefix=/net/ipv6/neigh/tmp1ca1e",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp1dba5\u0000--prefix=/net/ipv4/neigh/tmp1dba5\u0000--prefix=/net/ipv6/conf/tmp1dba5\u0000--prefix=/net/ipv6/neigh/tmp1dba5",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp1f968\u0000--prefix=/net/ipv4/neigh/tmp1f968\u0000--prefix=/net/ipv6/conf/tmp1f968\u0000--prefix=/net/ipv6/neigh/tmp1f968",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp1ff29\u0000--prefix=/net/ipv4/neigh/tmp1ff29\u0000--prefix=/net/ipv6/conf/tmp1ff29\u0000--prefix=/net/ipv6/neigh/tmp1ff29",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp20bb4\u0000--prefix=/net/ipv4/neigh/tmp20bb4\u0000--prefix=/net/ipv6/conf/tmp20bb4\u0000--prefix=/net/ipv6/neigh/tmp20bb4",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp21b5e\u0000--prefix=/net/ipv4/neigh/tmp21b5e\u0000--prefix=/net/ipv6/conf/tmp21b5e\u0000--prefix=/net/ipv6/neigh/tmp21b5e",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp2c16a\u0000--prefix=/net/ipv4/neigh/tmp2c16a\u0000--prefix=/net/ipv6/conf/tmp2c16a\u0000--prefix=/net/ipv6/neigh/tmp2c16a",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp2cea8\u0000--prefix=/net/ipv4/neigh/tmp2cea8\u0000--prefix=/net/ipv6/conf/tmp2cea8\u0000--prefix=/net/ipv6/neigh/tmp2cea8",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp2d26d\u0000--prefix=/net/ipv4/neigh/tmp2d26d\u0000--prefix=/net/ipv6/conf/tmp2d26d\u0000--prefix=/net/ipv6/neigh/tmp2d26d",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp30183\u0000--prefix=/net/ipv4/neigh/tmp30183\u0000--prefix=/net/ipv6/conf/tmp30183\u0000--prefix=/net/ipv6/neigh/tmp30183",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp302d9\u0000--prefix=/net/ipv4/neigh/tmp302d9\u0000--prefix=/net/ipv6/conf/tmp302d9\u0000--prefix=/net/ipv6/neigh/tmp302d9",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp305dc\u0000--prefix=/net/ipv4/neigh/tmp305dc\u0000--prefix=/net/ipv6/conf/tmp305dc\u0000--prefix=/net/ipv6/neigh/tmp305dc",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp32044\u0000--prefix=/net/ipv4/neigh/tmp32044\u0000--prefix=/net/ipv6/conf/tmp32044\u0000--prefix=/net/ipv6/neigh/tmp32044",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp332af\u0000--prefix=/net/ipv4/neigh/tmp332af\u0000--prefix=/net/ipv6/conf/tmp332af\u0000--prefix=/net/ipv6/neigh/tmp332af",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp34462\u0000--prefix=/net/ipv4/neigh/tmp34462\u0000--prefix=/net/ipv6/conf/tmp34462\u0000--prefix=/net/ipv6/neigh/tmp34462",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp34615\u0000--prefix=/net/ipv4/neigh/tmp34615\u0000--prefix=/net/ipv6/conf/tmp34615\u0000--prefix=/net/ipv6/neigh/tmp34615",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp36a8d\u0000--prefix=/net/ipv4/neigh/tmp36a8d\u0000--prefix=/net/ipv6/conf/tmp36a8d\u0000--prefix=/net/ipv6/neigh/tmp36a8d",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp37fd0\u0000--prefix=/net/ipv4/neigh/tmp37fd0\u0000--prefix=/net/ipv6/conf/tmp37fd0\u0000--prefix=/net/ipv6/neigh/tmp37fd0",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp3931c\u0000--prefix=/net/ipv4/neigh/tmp3931c\u0000--prefix=/net/ipv6/conf/tmp3931c\u0000--prefix=/net/ipv6/neigh/tmp3931c",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp39d4e\u0000--prefix=/net/ipv4/neigh/tmp39d4e\u0000--prefix=/net/ipv6/conf/tmp39d4e\u0000--prefix=/net/ipv6/neigh/tmp39d4e",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp3b405\u0000--prefix=/net/ipv4/neigh/tmp3b405\u0000--prefix=/net/ipv6/conf/tmp3b405\u0000--prefix=/net/ipv6/neigh/tmp3b405",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp3b884\u0000--prefix=/net/ipv4/neigh/tmp3b884\u0000--prefix=/net/ipv6/conf/tmp3b884\u0000--prefix=/net/ipv6/neigh/tmp3b884",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp3bd07\u0000--prefix=/net/ipv4/neigh/tmp3bd07\u0000--prefix=/net/ipv6/conf/tmp3bd07\u0000--prefix=/net/ipv6/neigh/tmp3bd07",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp3c6bf\u0000--prefix=/net/ipv4/neigh/tmp3c6bf\u0000--prefix=/net/ipv6/conf/tmp3c6bf\u0000--prefix=/net/ipv6/neigh/tmp3c6bf",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp3f742\u0000--prefix=/net/ipv4/neigh/tmp3f742\u0000--prefix=/net/ipv6/conf/tmp3f742\u0000--prefix=/net/ipv6/neigh/tmp3f742",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp3fb1d\u0000--prefix=/net/ipv4/neigh/tmp3fb1d\u0000--prefix=/net/ipv6/conf/tmp3fb1d\u0000--prefix=/net/ipv6/neigh/tmp3fb1d",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp43326\u0000--prefix=/net/ipv4/neigh/tmp43326\u0000--prefix=/net/ipv6/conf/tmp43326\u0000--prefix=/net/ipv6/neigh/tmp43326",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp45f2c\u0000--prefix=/net/ipv4/neigh/tmp45f2c\u0000--prefix=/net/ipv6/conf/tmp45f2c\u0000--prefix=/net/ipv6/neigh/tmp45f2c",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp4841c\u0000--prefix=/net/ipv4/neigh/tmp4841c\u0000--prefix=/net/ipv6/conf/tmp4841c\u0000--prefix=/net/ipv6/neigh/tmp4841c",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp487cd\u0000--prefix=/net/ipv4/neigh/tmp487cd\u0000--prefix=/net/ipv6/conf/tmp487cd\u0000--prefix=/net/ipv6/neigh/tmp487cd",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp48d36\u0000--prefix=/net/ipv4/neigh/tmp48d36\u0000--prefix=/net/ipv6/conf/tmp48d36\u0000--prefix=/net/ipv6/neigh/tmp48d36",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp4a363\u0000--prefix=/net/ipv4/neigh/tmp4a363\u0000--prefix=/net/ipv6/conf/tmp4a363\u0000--prefix=/net/ipv6/neigh/tmp4a363",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp4e226\u0000--prefix=/net/ipv4/neigh/tmp4e226\u0000--prefix=/net/ipv6/conf/tmp4e226\u0000--prefix=/net/ipv6/neigh/tmp4e226",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp524d6\u0000--prefix=/net/ipv4/neigh/tmp524d6\u0000--prefix=/net/ipv6/conf/tmp524d6\u0000--prefix=/net/ipv6/neigh/tmp524d6",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp53233\u0000--prefix=/net/ipv4/neigh/tmp53233\u0000--prefix=/net/ipv6/conf/tmp53233\u0000--prefix=/net/ipv6/neigh/tmp53233",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp53767\u0000--prefix=/net/ipv4/neigh/tmp53767\u0000--prefix=/net/ipv6/conf/tmp53767\u0000--prefix=/net/ipv6/neigh/tmp53767",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp570f1\u0000--prefix=/net/ipv4/neigh/tmp570f1\u0000--prefix=/net/ipv6/conf/tmp570f1\u0000--prefix=/net/ipv6/neigh/tmp570f1",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp5859b\u0000--prefix=/net/ipv4/neigh/tmp5859b\u0000--prefix=/net/ipv6/conf/tmp5859b\u0000--prefix=/net/ipv6/neigh/tmp5859b",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp58689\u0000--prefix=/net/ipv4/neigh/tmp58689\u0000--prefix=/net/ipv6/conf/tmp58689\u0000--prefix=/net/ipv6/neigh/tmp58689",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp59662\u0000--prefix=/net/ipv4/neigh/tmp59662\u0000--prefix=/net/ipv6/conf/tmp59662\u0000--prefix=/net/ipv6/neigh/tmp59662",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp59e46\u0000--prefix=/net/ipv4/neigh/tmp59e46\u0000--prefix=/net/ipv6/conf/tmp59e46\u0000--prefix=/net/ipv6/neigh/tmp59e46",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp5b643\u0000--prefix=/net/ipv4/neigh/tmp5b643\u0000--prefix=/net/ipv6/conf/tmp5b643\u0000--prefix=/net/ipv6/neigh/tmp5b643",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp5f970\u0000--prefix=/net/ipv4/neigh/tmp5f970\u0000--prefix=/net/ipv6/conf/tmp5f970\u0000--prefix=/net/ipv6/neigh/tmp5f970",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp60340\u0000--prefix=/net/ipv4/neigh/tmp60340\u0000--prefix=/net/ipv6/conf/tmp60340\u0000--prefix=/net/ipv6/neigh/tmp60340",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp64577\u0000--prefix=/net/ipv4/neigh/tmp64577\u0000--prefix=/net/ipv6/conf/tmp64577\u0000--prefix=/net/ipv6/neigh/tmp64577",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp695b5\u0000--prefix=/net/ipv4/neigh/tmp695b5\u0000--prefix=/net/ipv6/conf/tmp695b5\u0000--prefix=/net/ipv6/neigh/tmp695b5",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp6ba49\u0000--prefix=/net/ipv4/neigh/tmp6ba49\u0000--prefix=/net/ipv6/conf/tmp6ba49\u0000--prefix=/net/ipv6/neigh/tmp6ba49",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp6c53b\u0000--prefix=/net/ipv4/neigh/tmp6c53b\u0000--prefix=/net/ipv6/conf/tmp6c53b\u0000--prefix=/net/ipv6/neigh/tmp6c53b",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp6e8e9\u0000--prefix=/net/ipv4/neigh/tmp6e8e9\u0000--prefix=/net/ipv6/conf/tmp6e8e9\u0000--prefix=/net/ipv6/neigh/tmp6e8e9",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp756ac\u0000--prefix=/net/ipv4/neigh/tmp756ac\u0000--prefix=/net/ipv6/conf/tmp756ac\u0000--prefix=/net/ipv6/neigh/tmp756ac",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp7703a\u0000--prefix=/net/ipv4/neigh/tmp7703a\u0000--prefix=/net/ipv6/conf/tmp7703a\u0000--prefix=/net/ipv6/neigh/tmp7703a",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp7a023\u0000--prefix=/net/ipv4/neigh/tmp7a023\u0000--prefix=/net/ipv6/conf/tmp7a023\u0000--prefix=/net/ipv6/neigh/tmp7a023",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp8144d\u0000--prefix=/net/ipv4/neigh/tmp8144d\u0000--prefix=/net/ipv6/conf/tmp8144d\u0000--prefix=/net/ipv6/neigh/tmp8144d",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp838ec\u0000--prefix=/net/ipv4/neigh/tmp838ec\u0000--prefix=/net/ipv6/conf/tmp838ec\u0000--prefix=/net/ipv6/neigh/tmp838ec",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp87627\u0000--prefix=/net/ipv4/neigh/tmp87627\u0000--prefix=/net/ipv6/conf/tmp87627\u0000--prefix=/net/ipv6/neigh/tmp87627",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp88159\u0000--prefix=/net/ipv4/neigh/tmp88159\u0000--prefix=/net/ipv6/conf/tmp88159\u0000--prefix=/net/ipv6/neigh/tmp88159",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp8eb34\u0000--prefix=/net/ipv4/neigh/tmp8eb34\u0000--prefix=/net/ipv6/conf/tmp8eb34\u0000--prefix=/net/ipv6/neigh/tmp8eb34",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp8f1ce\u0000--prefix=/net/ipv4/neigh/tmp8f1ce\u0000--prefix=/net/ipv6/conf/tmp8f1ce\u0000--prefix=/net/ipv6/neigh/tmp8f1ce",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp900af\u0000--prefix=/net/ipv4/neigh/tmp900af\u0000--prefix=/net/ipv6/conf/tmp900af\u0000--prefix=/net/ipv6/neigh/tmp900af",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp90dbc\u0000--prefix=/net/ipv4/neigh/tmp90dbc\u0000--prefix=/net/ipv6/conf/tmp90dbc\u0000--prefix=/net/ipv6/neigh/tmp90dbc",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp920d2\u0000--prefix=/net/ipv4/neigh/tmp920d2\u0000--prefix=/net/ipv6/conf/tmp920d2\u0000--prefix=/net/ipv6/neigh/tmp920d2",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp92332\u0000--prefix=/net/ipv4/neigh/tmp92332\u0000--prefix=/net/ipv6/conf/tmp92332\u0000--prefix=/net/ipv6/neigh/tmp92332",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp9a4d9\u0000--prefix=/net/ipv4/neigh/tmp9a4d9\u0000--prefix=/net/ipv6/conf/tmp9a4d9\u0000--prefix=/net/ipv6/neigh/tmp9a4d9",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp9a508\u0000--prefix=/net/ipv4/neigh/tmp9a508\u0000--prefix=/net/ipv6/conf/tmp9a508\u0000--prefix=/net/ipv6/neigh/tmp9a508",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp9b5a9\u0000--prefix=/net/ipv4/neigh/tmp9b5a9\u0000--prefix=/net/ipv6/conf/tmp9b5a9\u0000--prefix=/net/ipv6/neigh/tmp9b5a9",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpa1d7e\u0000--prefix=/net/ipv4/neigh/tmpa1d7e\u0000--prefix=/net/ipv6/conf/tmpa1d7e\u0000--prefix=/net/ipv6/neigh/tmpa1d7e",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpa7719\u0000--prefix=/net/ipv4/neigh/tmpa7719\u0000--prefix=/net/ipv6/conf/tmpa7719\u0000--prefix=/net/ipv6/neigh/tmpa7719",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpa79aa\u0000--prefix=/net/ipv4/neigh/tmpa79aa\u0000--prefix=/net/ipv6/conf/tmpa79aa\u0000--prefix=/net/ipv6/neigh/tmpa79aa",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpa931e\u0000--prefix=/net/ipv4/neigh/tmpa931e\u0000--prefix=/net/ipv6/conf/tmpa931e\u0000--prefix=/net/ipv6/neigh/tmpa931e",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpa9bcb\u0000--prefix=/net/ipv4/neigh/tmpa9bcb\u0000--prefix=/net/ipv6/conf/tmpa9bcb\u0000--prefix=/net/ipv6/neigh/tmpa9bcb",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpaafdc\u0000--prefix=/net/ipv4/neigh/tmpaafdc\u0000--prefix=/net/ipv6/conf/tmpaafdc\u0000--prefix=/net/ipv6/neigh/tmpaafdc",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpae1bb\u0000--prefix=/net/ipv4/neigh/tmpae1bb\u0000--prefix=/net/ipv6/conf/tmpae1bb\u0000--prefix=/net/ipv6/neigh/tmpae1bb",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpb113b\u0000--prefix=/net/ipv4/neigh/tmpb113b\u0000--prefix=/net/ipv6/conf/tmpb113b\u0000--prefix=/net/ipv6/neigh/tmpb113b",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpb1304\u0000--prefix=/net/ipv4/neigh/tmpb1304\u0000--prefix=/net/ipv6/conf/tmpb1304\u0000--prefix=/net/ipv6/neigh/tmpb1304",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpb1336\u0000--prefix=/net/ipv4/neigh/tmpb1336\u0000--prefix=/net/ipv6/conf/tmpb1336\u0000--prefix=/net/ipv6/neigh/tmpb1336",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpb4ac3\u0000--prefix=/net/ipv4/neigh/tmpb4ac3\u0000--prefix=/net/ipv6/conf/tmpb4ac3\u0000--prefix=/net/ipv6/neigh/tmpb4ac3",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpb6a74\u0000--prefix=/net/ipv4/neigh/tmpb6a74\u0000--prefix=/net/ipv6/conf/tmpb6a74\u0000--prefix=/net/ipv6/neigh/tmpb6a74",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpb7419\u0000--prefix=/net/ipv4/neigh/tmpb7419\u0000--prefix=/net/ipv6/conf/tmpb7419\u0000--prefix=/net/ipv6/neigh/tmpb7419",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpb759d\u0000--prefix=/net/ipv4/neigh/tmpb759d\u0000--prefix=/net/ipv6/conf/tmpb759d\u0000--prefix=/net/ipv6/neigh/tmpb759d",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpb91a1\u0000--prefix=/net/ipv4/neigh/tmpb91a1\u0000--prefix=/net/ipv6/conf/tmpb91a1\u0000--prefix=/net/ipv6/neigh/tmpb91a1",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpbaf5b\u0000--prefix=/net/ipv4/neigh/tmpbaf5b\u0000--prefix=/net/ipv6/conf/tmpbaf5b\u0000--prefix=/net/ipv6/neigh/tmpbaf5b",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpc02ed\u0000--prefix=/net/ipv4/neigh/tmpc02ed\u0000--prefix=/net/ipv6/conf/tmpc02ed\u0000--prefix=/net/ipv6/neigh/tmpc02ed",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpc2bf8\u0000--prefix=/net/ipv4/neigh/tmpc2bf8\u0000--prefix=/net/ipv6/conf/tmpc2bf8\u0000--prefix=/net/ipv6/neigh/tmpc2bf8",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpc2e12\u0000--prefix=/net/ipv4/neigh/tmpc2e12\u0000--prefix=/net/ipv6/conf/tmpc2e12\u0000--prefix=/net/ipv6/neigh/tmpc2e12",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpc37ac\u0000--prefix=/net/ipv4/neigh/tmpc37ac\u0000--prefix=/net/ipv6/conf/tmpc37ac\u0000--prefix=/net/ipv6/neigh/tmpc37ac",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpc3ddd\u0000--prefix=/net/ipv4/neigh/tmpc3ddd\u0000--prefix=/net/ipv6/conf/tmpc3ddd\u0000--prefix=/net/ipv6/neigh/tmpc3ddd",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpc41a6\u0000--prefix=/net/ipv4/neigh/tmpc41a6\u0000--prefix=/net/ipv6/conf/tmpc41a6\u0000--prefix=/net/ipv6/neigh/tmpc41a6",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpc577e\u0000--prefix=/net/ipv4/neigh/tmpc577e\u0000--prefix=/net/ipv6/conf/tmpc577e\u0000--prefix=/net/ipv6/neigh/tmpc577e",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpc6bf4\u0000--prefix=/net/ipv4/neigh/tmpc6bf4\u0000--prefix=/net/ipv6/conf/tmpc6bf4\u0000--prefix=/net/ipv6/neigh/tmpc6bf4",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpc7d4f\u0000--prefix=/net/ipv4/neigh/tmpc7d4f\u0000--prefix=/net/ipv6/conf/tmpc7d4f\u0000--prefix=/net/ipv6/neigh/tmpc7d4f",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpc828d\u0000--prefix=/net/ipv4/neigh/tmpc828d\u0000--prefix=/net/ipv6/conf/tmpc828d\u0000--prefix=/net/ipv6/neigh/tmpc828d",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpca230\u0000--prefix=/net/ipv4/neigh/tmpca230\u0000--prefix=/net/ipv6/conf/tmpca230\u0000--prefix=/net/ipv6/neigh/tmpca230",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpcc4a3\u0000--prefix=/net/ipv4/neigh/tmpcc4a3\u0000--prefix=/net/ipv6/conf/tmpcc4a3\u0000--prefix=/net/ipv6/neigh/tmpcc4a3",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpccf77\u0000--prefix=/net/ipv4/neigh/tmpccf77\u0000--prefix=/net/ipv6/conf/tmpccf77\u0000--prefix=/net/ipv6/neigh/tmpccf77",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpce10f\u0000--prefix=/net/ipv4/neigh/tmpce10f\u0000--prefix=/net/ipv6/conf/tmpce10f\u0000--prefix=/net/ipv6/neigh/tmpce10f",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpce2e2\u0000--prefix=/net/ipv4/neigh/tmpce2e2\u0000--prefix=/net/ipv6/conf/tmpce2e2\u0000--prefix=/net/ipv6/neigh/tmpce2e2",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpd2c0f\u0000--prefix=/net/ipv4/neigh/tmpd2c0f\u0000--prefix=/net/ipv6/conf/tmpd2c0f\u0000--prefix=/net/ipv6/neigh/tmpd2c0f",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpd519d\u0000--prefix=/net/ipv4/neigh/tmpd519d\u0000--prefix=/net/ipv6/conf/tmpd519d\u0000--prefix=/net/ipv6/neigh/tmpd519d",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpd792d\u0000--prefix=/net/ipv4/neigh/tmpd792d\u0000--prefix=/net/ipv6/conf/tmpd792d\u0000--prefix=/net/ipv6/neigh/tmpd792d",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpd81e3\u0000--prefix=/net/ipv4/neigh/tmpd81e3\u0000--prefix=/net/ipv6/conf/tmpd81e3\u0000--prefix=/net/ipv6/neigh/tmpd81e3",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpdd094\u0000--prefix=/net/ipv4/neigh/tmpdd094\u0000--prefix=/net/ipv6/conf/tmpdd094\u0000--prefix=/net/ipv6/neigh/tmpdd094",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpdf771\u0000--prefix=/net/ipv4/neigh/tmpdf771\u0000--prefix=/net/ipv6/conf/tmpdf771\u0000--prefix=/net/ipv6/neigh/tmpdf771",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpe5235\u0000--prefix=/net/ipv4/neigh/tmpe5235\u0000--prefix=/net/ipv6/conf/tmpe5235\u0000--prefix=/net/ipv6/neigh/tmpe5235",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpe649d\u0000--prefix=/net/ipv4/neigh/tmpe649d\u0000--prefix=/net/ipv6/conf/tmpe649d\u0000--prefix=/net/ipv6/neigh/tmpe649d",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpe66e6\u0000--prefix=/net/ipv4/neigh/tmpe66e6\u0000--prefix=/net/ipv6/conf/tmpe66e6\u0000--prefix=/net/ipv6/neigh/tmpe66e6",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpe6a0a\u0000--prefix=/net/ipv4/neigh/tmpe6a0a\u0000--prefix=/net/ipv6/conf/tmpe6a0a\u0000--prefix=/net/ipv6/neigh/tmpe6a0a",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpea70f\u0000--prefix=/net/ipv4/neigh/tmpea70f\u0000--prefix=/net/ipv6/conf/tmpea70f\u0000--prefix=/net/ipv6/neigh/tmpea70f",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpebb43\u0000--prefix=/net/ipv4/neigh/tmpebb43\u0000--prefix=/net/ipv6/conf/tmpebb43\u0000--prefix=/net/ipv6/neigh/tmpebb43",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmped260\u0000--prefix=/net/ipv4/neigh/tmped260\u0000--prefix=/net/ipv6/conf/tmped260\u0000--prefix=/net/ipv6/neigh/tmped260",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpf6eb9\u0000--prefix=/net/ipv4/neigh/tmpf6eb9\u0000--prefix=/net/ipv6/conf/tmpf6eb9\u0000--prefix=/net/ipv6/neigh/tmpf6eb9",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpfa046\u0000--prefix=/net/ipv4/neigh/tmpfa046\u0000--prefix=/net/ipv6/conf/tmpfa046\u0000--prefix=/net/ipv6/neigh/tmpfa046",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpfaa9d\u0000--prefix=/net/ipv4/neigh/tmpfaa9d\u0000--prefix=/net/ipv6/conf/tmpfaa9d\u0000--prefix=/net/ipv6/neigh/tmpfaa9d",
        },
        {
          name: "/usr/lib/systemd/systemd-update-utmp",
          arguments: "runlevel",
        },
        { name: "/usr/lib/udev/rename_device" },
        {
          name: "/usr/local/aws-cli/v2/2.22.23/dist/aws",
          arguments:
            "eks\u0000get-token\u0000--cluster-name\u0000df-tetragon-dev-ce-01\u0000--region\u0000us-west-2",
          connections: [
            {
              destination_name: "169.254.169.254",
              destination_port: "80",
              bytes_sent: "1463",
              bytes_received: "3141",
            },
          ],
        },
        {
          name: "/usr/local/bin/ruby",
          arguments:
            "/usr/local/bundle/bin/fluentd\u0000--config\u0000/fluentd/etc/fluent.conf\u0000--plugin\u0000/fluentd/plugins",
        },
        {
          name: "/usr/local/bin/tini",
          arguments: "--\u0000/bin/entrypoint.sh\u0000fluentd",
        },
        { name: "/usr/local/bin/valkey-server" },
        {
          name: "/usr/sbin/fstrim",
          arguments:
            "--listed-in\u0000/etc/fstab:/proc/self/mountinfo\u0000--verbose\u0000--quiet-unsupported",
        },
        { name: "/usr/sbin/logrotate", arguments: "/etc/logrotate.conf" },
        { name: "/usr/sbin/runc", arguments: "-" },
        { name: "/usr/sbin/runc", arguments: "--" },
        { name: "/usr/sbin/runc", arguments: "--r" },
        { name: "/usr/sbin/runc", arguments: "--ro" },
        { name: "/usr/sbin/runc", arguments: "--roo" },
        { name: "/usr/sbin/runc", arguments: "--root" },
        { name: "/usr/sbin/runc", arguments: "--root\u0000/ru" },
        { name: "/usr/sbin/runc", arguments: "--root\u0000/run/contai" },
        { name: "/usr/sbin/runc", arguments: "--root\u0000/run/contain" },
        { name: "/usr/sbin/runc", arguments: "--root\u0000/run/containe" },
        {
          name: "/usr/sbin/runc",
          arguments: "--root\u0000/run/containerd/ru",
        },
        {
          name: "/usr/sbin/runc",
          arguments: "--root\u0000/run/containerd/runc/",
        },
        {
          name: "/usr/sbin/runc",
          arguments:
            "--root\u0000/run/containerd/runc/k8s.io\u0000--log\u0000/run/cont",
        },
        {
          name: "/usr/sbin/runc",
          arguments:
            "--root\u0000/run/containerd/runc/k8s.io\u0000--log\u0000/run/conta",
        },
        { name: "/usr/sbin/runc", arguments: "init" },
        { name: "/usr/sbin/sshd" },
        { name: "/usr/sbin/xtables-nft-multi" },
        {
          name: "/usr/sbin/xtables-nft-multi",
          arguments: "-t\u0000mangle",
        },
        {
          name: "/usr/sbin/xtables-nft-multi",
          arguments:
            "-w\u00005\u0000-W\u0000100000\u0000-S\u0000KUBE-KUBELET-CANARY\u0000-t\u0000mangle",
        },
        { arguments: "init" },
      ],
    },
  },
};
