export const model = {
  node_name: "temujin",
  time: "2025-04-07T14:28:55.108924132Z",
  application_model: {
    namespaces: [
      {
        name: "argocd",
        workloads: [
          {
            name: "argo-cd-argocd-repo-server",
            kind: "WORKLOAD_KIND_DEPLOYMENT",
            processes: [
              {
                name: "/usr/bin/basename",
                arguments: "-- /usr/lib/git-core/git-submodule",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/basename",
                arguments: "/usr/lib/git-core/git-submodule",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/bash",
                arguments:
                  '-exc "helm registry login quay.io --username $QUAY_USERNAME --password $QUAY_PASSWORD"',
                in_init_tree: true,
              },
              {
                name: "/usr/bin/cp",
                arguments: "-n /usr/local/bin/argocd /var/run/argocd/argocd-cmp-server",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/dash",
                arguments: '-c "ssh -i /dev/shm/1200889544 -o StrictHostKeyChec"',
                in_init_tree: true,
              },
              {
                name: "/usr/bin/dash",
                arguments: '-c "ssh -i /dev/shm/1602379499 -o StrictHostKeyChec"',
                in_init_tree: true,
              },
              {
                name: "/usr/bin/dash",
                arguments: '-c "ssh -i /dev/shm/1613368471 -o StrictHostKeyChec"',
                in_init_tree: true,
              },
              {
                name: "/usr/bin/dash",
                arguments: '-c "ssh -i /dev/shm/1702175237 -o StrictHostKeyChec"',
                in_init_tree: true,
              },
              {
                name: "/usr/bin/dash",
                arguments: '-c "ssh -i /dev/shm/2336569163 -o StrictHostKeyChecking=yes -o UserKn"',
                in_init_tree: true,
              },
              {
                name: "/usr/bin/dash",
                arguments: '-c "ssh -i /dev/shm/2505935786 -o StrictHostKeyChecking=yes -o UserKn"',
                in_init_tree: true,
              },
              {
                name: "/usr/bin/dash",
                arguments: '-c "ssh -i /dev/shm/3142269216 -o StrictHostKeyChec"',
                in_init_tree: true,
              },
              {
                name: "/usr/bin/dash",
                arguments: '-c "ssh -i /dev/shm/4151709562 -o StrictHostKeyChecking=yes -"',
                in_init_tree: true,
              },
              {
                name: "/usr/bin/dash",
                arguments: "/usr/lib/git-core/git-submodule sync --recursive",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/dash",
                arguments: "/usr/lib/git-core/git-submodule update --init --recursive",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/dash",
                arguments:
                  "/usr/local/bin/gpg-wrapper.sh --no-permission-warning --list-secret-keys 8B9A20389D231D7B",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/git",
                arguments: "cat-file -t 08bf97bf666ec1e59e1067c8f307c7cc415e264c",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/git",
                arguments: "cat-file -t 1220a4e16071e67a90364b36223de86fe60bf3e8",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/git",
                arguments: "cat-file -t 1ff0e181222dd9fdad736421f0448e5a749d1636",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/git",
                arguments: "cat-file -t 3d05ecb5a7625675ce24f7e1ff033b9c58b7a3e2",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/git",
                arguments: "cat-file -t 6ac6c263e87ebfdbced4e5ef770b358cd56f214c",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/git",
                arguments: "cat-file -t 6c18bb5ffc965cfea30c121d240bfe526771ccef",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/git",
                arguments: "cat-file -t 75c1048699782787f9398f2233a8d1c2dafdc685",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/git",
                arguments: "checkout --force 08bf97bf666ec1e59e1067c8f307c7cc415e264c",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/git",
                arguments: "checkout --force 1220a4e16071e67a90364b36223de86fe60bf3e8",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/git",
                arguments: "checkout --force 1ff0e181222dd9fdad736421f0448e5a749d1636",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/git",
                arguments: "checkout --force 3d05ecb5a7625675ce24f7e1ff033b9c58b7a3e2",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/git",
                arguments: "checkout --force 5f26dc30ee29e84a6ba285f32cbe6e7739857a78",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/git",
                arguments: "checkout --force 6ac6c263e87ebfdbced4e5ef770b358cd56f214c",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/git",
                arguments: "checkout --force 6c18bb5ffc965cfea30c121d240bfe526771ccef",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/git",
                arguments: "checkout --force 75c1048699782787f9398f2233a8d1c2dafdc685",
                in_init_tree: true,
              },
              { name: "/usr/bin/git", arguments: "clean -ffdx", in_init_tree: true },
              {
                name: "/usr/bin/git",
                arguments: "fetch origin --tags --force --prune",
                in_init_tree: true,
              },
              { name: "/usr/bin/git", arguments: "rev-parse HEAD", in_init_tree: true },
              { name: "/usr/bin/git", arguments: "submodule sync --recursive", in_init_tree: true },
              {
                name: "/usr/bin/git",
                arguments: "submodule update --init --recursive",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/gpg",
                arguments: "--no-permission-warning --list-public-keys",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/gpg",
                arguments: "--no-permission-warning --list-secret-keys 8B9A20389D231D7B",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/gpg",
                arguments:
                  "--no-permission-warning --logger-fd 1 --batch --gen-key /tmp/gpg-key-recipe4232316578",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/gpg-agent",
                arguments: "--homedir /app/config/gpg/keys --use-standard-socket --daemon",
                in_init_tree: true,
              },
              { name: "/usr/bin/sed", arguments: '-e "s/-/ /"', in_init_tree: true },
              { name: "/usr/bin/sed", arguments: "-e s/-/_/g", in_init_tree: true },
              {
                name: "/usr/bin/ssh",
                arguments:
                  "-i /dev/shm/1200889544 -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/app/config/ssh/ssh_known_hosts -o SendEnv=GIT_PROTOCOL git@github.com \"git-upload-pack 'isovalent/hubble-fgs'\"",
                connections: [
                  {
                    destination: { dns: { destination_names: ["github.com"] }, port: "22" },
                    stats: { tx_bytes: "843478", rx_bytes: "222291117" },
                  },
                ],
              },
              {
                name: "/usr/bin/ssh",
                arguments:
                  "-i /dev/shm/1602379499 -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/app/config/ssh/ssh_known_hosts -o SendEnv=GIT_PROTOCOL git@github.com \"git-upload-pack 'isovalent/hubble-fgs'\"",
                connections: [
                  {
                    destination: { dns: { destination_names: ["github.com"] }, port: "22" },
                    stats: { tx_bytes: "7470", rx_bytes: "95981" },
                  },
                ],
              },
              {
                name: "/usr/bin/ssh",
                arguments:
                  "-i /dev/shm/1613368471 -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/app/config/ssh/ssh_known_hosts -o SendEnv=GIT_PROTOCOL git@github.com \"git-upload-pack 'isovalent/hubble-fgs'\"",
                connections: [
                  {
                    destination: { dns: { destination_names: ["github.com"] }, port: "22" },
                    stats: { tx_bytes: "9878", rx_bytes: "91149" },
                  },
                ],
              },
              {
                name: "/usr/bin/ssh",
                arguments:
                  "-i /dev/shm/1702175237 -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/app/config/ssh/ssh_known_hosts -o SendEnv=GIT_PROTOCOL git@github.com \"git-upload-pack 'isovalent/hubble-fgs'\"",
                connections: [
                  {
                    destination: { dns: { destination_names: ["github.com"] }, port: "22" },
                    stats: { tx_bytes: "7366", rx_bytes: "99477" },
                  },
                ],
              },
              {
                name: "/usr/bin/ssh",
                arguments:
                  "-i /dev/shm/2336569163 -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/app/config/ssh/ssh_known_hosts -o SendEnv=GIT_PROTOCOL git@github.com \"git-upload-pack 'isovalent/cilium-enterprise-dogfooding'\"",
                connections: [
                  {
                    destination: { dns: { destination_names: ["github.com"] }, port: "22" },
                    stats: { tx_bytes: "45942", rx_bytes: "4925729" },
                  },
                ],
              },
              {
                name: "/usr/bin/ssh",
                arguments:
                  "-i /dev/shm/2505935786 -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/app/config/ssh/ssh_known_hosts -o SendEnv=GIT_PROTOCOL git@github.com \"git-upload-pack 'isovalent/cilium-enterprise-dogfooding'\"",
                connections: [
                  {
                    destination: { dns: { destination_names: ["github.com"] }, port: "22" },
                    stats: { tx_bytes: "6914", rx_bytes: "27869" },
                  },
                ],
              },
              {
                name: "/usr/bin/ssh",
                arguments:
                  "-i /dev/shm/3142269216 -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/app/config/ssh/ssh_known_hosts -o SendEnv=GIT_PROTOCOL git@github.com \"git-upload-pack 'isovalent/hubble-fgs'\"",
                connections: [
                  {
                    destination: { dns: { destination_names: ["github.com"] }, port: "22" },
                    stats: { tx_bytes: "7978", rx_bytes: "104449" },
                  },
                ],
              },
              {
                name: "/usr/bin/ssh",
                arguments:
                  "-i /dev/shm/4151709562 -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/app/config/ssh/ssh_known_hosts -o SendEnv=GIT_PROTOCOL git@github.com \"git-upload-pack 'isovalent/cilium-ee-dashboards'\"",
                connections: [
                  {
                    destination: { dns: { destination_names: ["github.com"] }, port: "22" },
                    stats: { tx_bytes: "8110", rx_bytes: "351653" },
                  },
                ],
              },
              {
                name: "/usr/bin/tini",
                arguments: "-- /usr/local/bin/argocd-repo-server --port=8081 --metrics-port=8084",
                in_init_tree: true,
              },
              { name: "/usr/bin/uname", arguments: "-s", in_init_tree: true },
              { name: "/usr/lib/git-core/git", arguments: "--exec-path", in_init_tree: true },
              {
                name: "/usr/lib/git-core/git",
                arguments:
                  'index-pack --stdin --fix-thin "--keep=fetch-pack 31 on argo-cd-argocd-repo-server-689d9cc768-hfhcs" --pack_header=2,39664',
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments:
                  'index-pack --stdin --fix-thin "--keep=fetch-pack 3255 on argo-cd-argocd-repo-server-689d9cc768-hfhcs" --pack_header=2,1008',
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments:
                  'index-pack --stdin --fix-thin "--keep=fetch-pack 393 on argo-cd-argocd-repo-server-689d9cc768-hfhcs" --pack_header=2,147178',
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments:
                  'index-pack --stdin --fix-thin "--keep=fetch-pack 459 on argo-cd-argocd-repo-server-689d9cc768-hfhcs" --check-self-contained-and-connected',
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments: "maintenance run --auto --no-quiet",
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments: "rev-list --objects --stdin --not --all --quiet --alternate-refs",
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments:
                  "rev-list --objects --stdin --not --exclude-hidden=fetch --all --quiet --alternate-refs",
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments: "rev-list -n 1 0ee448f60c11ca75ace0a9d086e44a3b9b41abbc --not --all",
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments: "rev-parse --git-dir",
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments: "rev-parse --git-path objects",
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments: "rev-parse --is-inside-work-tree",
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments: "rev-parse --show-prefix",
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments: "rev-parse --show-toplevel",
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments: 'sh-i18n--envsubst "usage: $dashless $USAGE"',
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments: 'sh-i18n--envsubst --variables "usage: $dashless $USAGE"',
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments: "submodule--helper sync --recursive --",
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments:
                  "submodule--helper sync --recursive --super-prefix modules/tetragon-oss/",
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments: "submodule--helper update --recursive --init --",
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments:
                  "submodule--helper update --recursive --super-prefix modules/tetragon-oss/ --jobs=1 --init",
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments: "unpack-objects -q --pack_header=2,13",
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments: "unpack-objects -q --pack_header=2,25",
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments: "unpack-objects -q --pack_header=2,26",
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments: "unpack-objects -q --pack_header=2,43",
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git",
                arguments: "unpack-objects -q --pack_header=2,91",
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git-remote-http",
                arguments: "origin https://github.com/cilium/tetragon",
                connections: [
                  {
                    destination: { dns: { destination_names: ["github.com"] }, port: "443" },
                    stats: { tx_bytes: "61106", rx_bytes: "79763093" },
                  },
                ],
              },
              {
                name: "/usr/lib/git-core/git-sh-i18n--envsubst",
                arguments: ' "usage: $dashless $USAGE"',
                in_init_tree: true,
              },
              {
                name: "/usr/lib/git-core/git-sh-i18n--envsubst",
                arguments: '--variables "usage: $dashless $USAGE"',
                in_init_tree: true,
              },
              {
                name: "/usr/local/bin/argocd",
                arguments: "--port=8081 --metrics-port=8084",
                connections: [
                  {
                    destination: { dns: { destination_names: ["::1"] }, port: "8081" },
                    stats: { tx_bytes: "43343299", rx_bytes: "43343299" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["argo-cd-argocd-redis.argocd.svc.cluster.local"] },
                      port: "6379",
                    },
                    stats: { tx_bytes: "45819", rx_bytes: "3229742" },
                  },
                  {
                    destination: { dns: { destination_names: ["github.com"] }, port: "22" },
                    stats: { tx_bytes: "38759949", rx_bytes: "304749149" },
                  },
                ],
              },
              { name: "/usr/local/bin/helm", in_init_tree: true },
              {
                name: "/usr/local/bin/helm",
                arguments: "dependency build",
                connections: [
                  {
                    destination: { dns: { destination_names: ["github.com"] }, port: "443" },
                    stats: { tx_bytes: "28784", rx_bytes: "236352" },
                  },
                  {
                    destination: { dns: { destination_names: ["grafana.github.io"] }, port: "443" },
                    stats: { tx_bytes: "80932", rx_bytes: "27158143" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["objects.githubusercontent.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "51073", rx_bytes: "978058" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["prometheus-community.github.io"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "198232", rx_bytes: "61109294" },
                  },
                ],
              },
              {
                name: "/usr/local/bin/helm",
                arguments: "p",
                connections: [
                  {
                    destination: { dns: { destination_names: ["github.com"] }, port: "443" },
                    stats: { tx_bytes: "22116", rx_bytes: "177780" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["objects.githubusercontent.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "68280", rx_bytes: "5269644" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["open-telemetry.github.io"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "37182", rx_bytes: "4125528" },
                  },
                ],
              },
              {
                name: "/usr/local/bin/helm",
                arguments: "pull -",
                connections: [
                  {
                    destination: { dns: { destination_names: ["github.com"] }, port: "443" },
                    stats: { tx_bytes: "34048", rx_bytes: "275359" },
                  },
                  {
                    destination: { dns: { destination_names: ["grafana.github.io"] }, port: "443" },
                    stats: { tx_bytes: "57225", rx_bytes: "21761292" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["helm.isovalent.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "30527", rx_bytes: "1315076" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["kubernetes-sigs.github.io"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "14322", rx_bytes: "346332" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["objects.githubusercontent.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "63140", rx_bytes: "5861548" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["open-telemetry.github.io"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "81354", rx_bytes: "9614808" },
                  },
                ],
              },
              {
                name: "/usr/local/bin/helm",
                arguments: "pull --unta",
                connections: [
                  {
                    destination: { dns: { destination_names: ["github.com"] }, port: "443" },
                    stats: { tx_bytes: "3654", rx_bytes: "29670" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["objects.githubusercontent.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "17106", rx_bytes: "1903323" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["prometheus-community.github.io"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "37287", rx_bytes: "12724743" },
                  },
                ],
              },
              {
                name: "/usr/local/bin/helm",
                arguments:
                  "pull --untar --untardir /tmp/_argocd-repo/d3300d8a-9288-4fe5-acdc-57de02a955f8/infra/df-tetragon-common/kube-prometheus-stack/charts/prometheus-adapter-4.2.0 --repo https://prometheus-community.github.io/helm-charts prometheus-adapter --version 4.2.0",
                connections: [
                  {
                    destination: { dns: { destination_names: ["github.com"] }, port: "443" },
                    stats: { tx_bytes: "12310", rx_bytes: "99126" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["helm.isovalent.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "16274", rx_bytes: "3131932" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["objects.githubusercontent.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "17620", rx_bytes: "189124" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["prometheus-community.github.io"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "84080", rx_bytes: "33915266" },
                  },
                ],
              },
              {
                name: "/usr/local/bin/helm",
                arguments:
                  "pull --untar --untardir /tmp/_argocd-repo/d3300d8a-9288-4fe5-acdc-57de02a955f8/infra/df-tetragon-dev-ce-01/apps/cert-manager/charts/cert-manager-1.12.2 --repo https://charts.jetstack.io cert-manager --version 1.12.2",
                connections: [
                  {
                    destination: {
                      dns: { destination_names: ["charts.jetstack.io"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "10656", rx_bytes: "834634" },
                  },
                  {
                    destination: { dns: { destination_names: ["github.com"] }, port: "443" },
                    stats: { tx_bytes: "2710", rx_bytes: "20138" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["helm.isovalent.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "11882", rx_bytes: "3128472" },
                  },
                ],
              },
              {
                name: "/usr/local/bin/helm",
                arguments:
                  "pull --untar --untardir /tmp/_argocd-repo/d3300d8a-9288-4fe5-acdc-57de02a955f8/infra/df-tetragon-dev-ce-01/apps/cilium/charts/cilium-1.16.6 --repo https://helm.isovalent.com cilium --version 1.16.6",
                connections: [
                  {
                    destination: {
                      dns: { destination_names: ["helm.isovalent.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "3280720", rx_bytes: "434206736" },
                  },
                ],
              },
              {
                name: "/usr/local/bin/helm",
                arguments:
                  "pull --untar --untardir /tmp/_argocd-repo/d3300d8a-9288-4fe5-acdc-57de02a955f8/infra/df-tetragon-dev-ce-01/apps/hubble-enterprise/charts/hubble-enterprise-1.12.17 --repo https://helm.isovalent.com hubble-enterprise --version 1.12.17",
                connections: [
                  {
                    destination: {
                      dns: { destination_names: ["helm.isovalent.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "44612", rx_bytes: "6487312" },
                  },
                ],
              },
              {
                name: "/usr/local/bin/helm",
                arguments:
                  "pull --untar --untardir /tmp/_argocd-repo/d3300d8a-9288-4fe5-acdc-57de02a955f8/infra/df-tetragon-dev-ce-01/apps/hubble-ui/charts/hubble-ui-1.3.0 --repo https://helm.isovalent.com hubble-ui --version 1.3.0",
                connections: [
                  {
                    destination: { dns: { destination_names: ["cdn01.quay.io"] }, port: "443" },
                    stats: { tx_bytes: "6628", rx_bytes: "310594" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["helm.isovalent.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "22678", rx_bytes: "3356986" },
                  },
                ],
              },
              {
                name: "/usr/local/bin/helm",
                arguments:
                  "pull --untar --untardir /tmp/_argocd-repo/d3300d8a-9288-4fe5-acdc-57de02a955f8/infra/df-tetragon-dev-ce-01/apps/ingress-nginx/charts/ingress-nginx-4.11.0 --repo https://kubernetes.github.io/ingress-nginx ingress-nginx --version 4.11.0",
                connections: [
                  {
                    destination: { dns: { destination_names: ["github.com"] }, port: "443" },
                    stats: { tx_bytes: "1199", rx_bytes: "9864" },
                  },
                  {
                    destination: { dns: { destination_names: ["grafana.github.io"] }, port: "443" },
                    stats: { tx_bytes: "8543", rx_bytes: "3112191" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["kubernetes.github.io"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "3166", rx_bytes: "172335" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["objects.githubusercontent.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "4309", rx_bytes: "88135" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["open-telemetry.github.io"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "8417", rx_bytes: "693586" },
                  },
                ],
              },
              {
                name: "/usr/local/bin/helm",
                arguments:
                  "pull --untar --untardir /tmp/_argocd-repo/d3300d8a-9288-4fe5-acdc-57de02a955f8/infra/df-tetragon-dev-ce-01/apps/jobs-app/charts/jobs-app-0.10.1 --repo https://helm.isovalent.com jobs-app --version 0.10.1",
                connections: [
                  {
                    destination: {
                      dns: { destination_names: ["charts.jetstack.io"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "10440", rx_bytes: "833814" },
                  },
                  {
                    destination: { dns: { destination_names: ["grafana.github.io"] }, port: "443" },
                    stats: { tx_bytes: "52922", rx_bytes: "18677812" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["helm.isovalent.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "64950", rx_bytes: "12845460" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["objects.githubusercontent.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "16656", rx_bytes: "1463786" },
                  },
                ],
              },
              {
                name: "/usr/local/bin/helm",
                arguments:
                  "pull --untar --untardir /tmp/_argocd-repo/d3300d8a-9288-4fe5-acdc-57de02a955f8/infra/df-tetragon-dev-ce-01/apps/loki/charts/loki-distributed-0.69.16 --repo https://grafana.github.io/helm-charts loki-distributed --version 0.69.16",
                connections: [
                  {
                    destination: { dns: { destination_names: ["github.com"] }, port: "443" },
                    stats: { tx_bytes: "9624", rx_bytes: "78762" },
                  },
                  {
                    destination: { dns: { destination_names: ["grafana.github.io"] }, port: "443" },
                    stats: { tx_bytes: "74056", rx_bytes: "24900970" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["objects.githubusercontent.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "19096", rx_bytes: "416298" },
                  },
                ],
              },
              {
                name: "/usr/local/bin/helm",
                arguments:
                  "pull --untar --untardir /tmp/_argocd-repo/d3300d8a-9288-4fe5-acdc-57de02a955f8/infra/df-tetragon-dev-ce-01/apps/promtail/charts/promtail-6.0.0 --repo https://grafana.github.io/helm-charts promtail --version 6.0.0",
                connections: [
                  {
                    destination: { dns: { destination_names: ["github.com"] }, port: "443" },
                    stats: { tx_bytes: "21894", rx_bytes: "177270" },
                  },
                  {
                    destination: { dns: { destination_names: ["grafana.github.io"] }, port: "443" },
                    stats: { tx_bytes: "110088", rx_bytes: "37339335" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["kubernetes.github.io"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "9030", rx_bytes: "516699" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["objects.githubusercontent.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "18231", rx_bytes: "280449" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["open-telemetry.github.io"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "17811", rx_bytes: "2062293" },
                  },
                ],
              },
              {
                name: "/usr/local/bin/helm",
                arguments:
                  "pull --untar --untardir /tmp/_argocd-repo/d3300d8a-9288-4fe5-acdc-57de02a955f8/infra/df-tetragon-dev-ce-01/apps/vector/charts/vector-0.36.1 --repo https://helm.vector.dev vector --version 0.36.1",
                connections: [
                  {
                    destination: { dns: { destination_names: ["github.com"] }, port: "443" },
                    stats: { tx_bytes: "9528", rx_bytes: "78364" },
                  },
                  {
                    destination: { dns: { destination_names: ["helm.vector.dev"] }, port: "443" },
                    stats: { tx_bytes: "43376", rx_bytes: "2016044" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["objects.githubusercontent.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "43620", rx_bytes: "842764" },
                  },
                ],
              },
              {
                name: "/usr/local/bin/helm",
                arguments:
                  "registry login quay.io --username isovalent-charts-dev+quay_chart_bot --password R0QC7BDRO14LQUK610HYEFYAI656922CLZ5CRMWDLWCY8KPP8GB52BNWUCICOBIW",
                connections: [
                  {
                    destination: { dns: { destination_names: ["quay.io"] }, port: "443" },
                    stats: { tx_bytes: "4319", rx_bytes: "21432" },
                  },
                ],
              },
              {
                name: "/usr/local/bin/helm",
                arguments:
                  "repo add https:--grafana.github.io-helm-charts https://grafana.github.io/helm-charts",
                connections: [
                  {
                    destination: { dns: { destination_names: ["grafana.github.io"] }, port: "443" },
                    stats: { tx_bytes: "141864", rx_bytes: "37389223" },
                  },
                ],
              },
              {
                name: "/usr/local/bin/helm",
                arguments:
                  "repo add https:--prometheus-community.github.io-helm-charts https://prometheus-community.github.io/helm-charts",
                connections: [
                  {
                    destination: {
                      dns: { destination_names: ["prometheus-community.github.io"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "281552", rx_bytes: "101754742" },
                  },
                ],
              },
              {
                name: "/usr/local/bin/helm",
                arguments: "template cilium-enterprise /tmp/_argocd-repo/d3300d8a-",
                in_init_tree: true,
              },
              {
                name: "/usr/local/bin/helm",
                arguments: "template cilium-enterprise /tmp/_argocd-repo/d3300d8a-9",
                in_init_tree: true,
              },
              {
                name: "/usr/local/bin/helm",
                arguments: "template cilium-enterprise /tmp/_argocd-repo/d3300d8a-92",
                in_init_tree: true,
              },
              {
                name: "/usr/local/bin/helm",
                arguments:
                  "template prometheus-adapter /tmp/_argocd-repo/d3300d8a-9288-4fe5-acdc-57de02a955f8/",
                in_init_tree: true,
              },
              {
                name: "/usr/local/bin/helm",
                arguments:
                  "template prometheus-adapter /tmp/_argocd-repo/d3300d8a-9288-4fe5-acdc-57de02a955f8/i",
                in_init_tree: true,
              },
              { name: "/usr/local/bin/helm", arguments: "version -c --short", in_init_tree: true },
              { name: "/usr/local/bin/kustomize", in_init_tree: true },
              {
                name: "/usr/local/bin/kustomize",
                arguments:
                  "build /tmp/_argocd-repo/d3300d8a-9288-4fe5-acdc-57de02a955f8/infra/common-apps/kubernetes-event-exporter -enable-helm --load-restrictor=LoadRestrictionsNone",
                in_init_tree: true,
              },
              {
                name: "/usr/local/bin/kustomize",
                arguments:
                  "build /tmp/_argocd-repo/d3300d8a-9288-4fe5-acdc-57de02a955f8/infra/common-apps/storageclasses -enable-helm --load-restrictor=LoadRestrictionsNone",
                in_init_tree: true,
              },
              {
                name: "/usr/local/bin/kustomize",
                arguments:
                  "build /tmp/_argocd-repo/d3300d8a-9288-4fe5-acdc-57de02a955f8/infra/df-tetragon-dev-ce-01/apps/argo-cd -enable-helm --load-restrictor=LoadRestrictionsNone",
                in_init_tree: true,
              },
              {
                name: "/usr/local/bin/kustomize",
                arguments:
                  "build /tmp/_argocd-repo/d3300d8a-9288-4fe5-acdc-57de02a955f8/infra/df-tetragon-dev-ce-01/apps/karpenter -enable-helm --load-restrictor=LoadRestrictionsNone",
                in_init_tree: true,
              },
              {
                name: "/usr/local/bin/kustomize",
                arguments: "version --short",
                in_init_tree: true,
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
            kind: "WORKLOAD_KIND_DAEMONSET",
            processes: [
              { name: "/usr/bin/hostname", in_init_tree: true },
              {
                name: "/usr/local/bin/ruby",
                arguments: "-Eascii-8bit:ascii-8bit -h",
                in_init_tree: true,
              },
              {
                name: "/usr/local/bin/ruby",
                arguments:
                  "-Eascii-8bit:ascii-8bit /usr/local/bundle/bin/fluentd --config /fluentd/etc/fluent.conf --plugin /fluentd/plugins --under-supervisor",
                connections: [
                  {
                    destination: { dns: { destination_names: ["54.240.250.235"] }, port: "443" },
                    stats: {},
                  },
                  {
                    destination: {
                      dns: {
                        destination_names: [
                          "df-tetragon-dev-ce-01-logs.s3.us-west-2.amazonaws.com",
                        ],
                      },
                      port: "443",
                    },
                    stats: { tx_bytes: "1231723608", rx_bytes: "1298800901" },
                  },
                  {
                    destination: {
                      dns: {
                        destination_names: [
                          "hubble-timescape-ingester.hubble-timescape.svc.cluster.local",
                        ],
                      },
                      port: "4260",
                    },
                    stats: { tx_bytes: "58103", rx_bytes: "844085" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["sts.us-west-2.amazonaws.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "304566", rx_bytes: "1092233" },
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
            kind: "WORKLOAD_KIND_STATEFULSET",
            processes: [
              { name: "/bin/bash", arguments: "/entrypoint.sh", in_init_tree: true },
              {
                name: "/bin/busybox",
                arguments: "-R 101:101 /var/log/clickhouse-server",
                in_init_tree: true,
              },
              { name: "/bin/busybox", arguments: "-c %u /var/lib/clickhouse/", in_init_tree: true },
              {
                name: "/bin/busybox",
                arguments: "-c %u /var/lib/clickhouse/tmp/",
                in_init_tree: true,
              },
              { name: "/bin/busybox", arguments: "-p /var/lib/clickhouse/", in_init_tree: true },
              {
                name: "/bin/busybox",
                arguments: "-p /var/log/clickhouse-server",
                in_init_tree: true,
              },
              { name: "/bin/busybox", arguments: "-u clickhouse", in_init_tree: true },
              {
                name: "/bin/busybox",
                arguments: "/var/log/clickhouse-server/clickhouse-server.err.log",
                in_init_tree: true,
              },
              {
                name: "/bin/busybox",
                arguments: "/var/log/clickhouse-server/clickhouse-server.log",
                in_init_tree: true,
              },
              { name: "/bin/busybox", arguments: "30", in_init_tree: true },
              {
                name: "/usr/bin/clickhouse",
                arguments: "--config-file=/etc/clickhouse-server/config.xml",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/clickhouse",
                arguments:
                  "extract-from-config --config-file /etc/clickhouse-server/config.xml --key=format_schema_path",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/clickhouse",
                arguments:
                  "extract-from-config --config-file /etc/clickhouse-server/config.xml --key=logger.errorlog",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/clickhouse",
                arguments:
                  "extract-from-config --config-file /etc/clickhouse-server/config.xml --key=path",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/clickhouse",
                arguments:
                  "su 101:101 /usr/bin/clickhouse-server --config-file=/etc/clickhouse-server/config.xml",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/grpc_health_probe",
                arguments: "-addr=localhost:4244",
                connections: [
                  {
                    destination: { dns: { destination_names: ["::1"] }, port: "4244" },
                    stats: { tx_bytes: "322326198", rx_bytes: "322326198" },
                  },
                ],
              },
              {
                name: "/usr/bin/grpc_health_probe",
                arguments: "-addr=localhost:4244 -connect-timeout=5m -rpc-timeout=1m",
                connections: [
                  {
                    destination: { dns: { destination_names: ["127.0.0.1"] }, port: "4244" },
                    stats: { tx_bytes: "540", rx_bytes: "900" },
                  },
                  {
                    destination: { dns: { destination_names: ["::1"] }, port: "4244" },
                    stats: { tx_bytes: "1779", rx_bytes: "1779" },
                  },
                ],
              },
              {
                name: "/usr/bin/hubble-timescape",
                arguments: "run",
                connections: [
                  {
                    destination: { dns: { destination_names: ["127.0.0.1"] }, port: "9000" },
                    stats: { tx_bytes: "48008", rx_bytes: "66789" },
                  },
                  {
                    destination: { dns: { destination_names: ["::1"] }, port: "9000" },
                    stats: { tx_bytes: "98028708914", rx_bytes: "98047280202" },
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
            kind: "WORKLOAD_KIND_DAEMONSET",
            processes: [
              {
                name: "/usr/bin/cilium-agent",
                arguments: "--config-dir=/tmp/cilium/config-map",
                connections: [
                  {
                    destination: { dns: { destination_names: ["10.3.5.136"] }, port: "4240" },
                    stats: {},
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.5.174"] }, port: "4240" },
                    stats: {},
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.5.184"] }, port: "4240" },
                    stats: { tx_bytes: "3050", rx_bytes: "5580" },
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.5.236"] }, port: "4240" },
                    stats: { tx_bytes: "295984", rx_bytes: "536068" },
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.5.40"] }, port: "4240" },
                    stats: {},
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.5.70"] }, port: "443" },
                    stats: { tx_bytes: "1555776", rx_bytes: "9985163" },
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.6.14"] }, port: "4240" },
                    stats: {},
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.6.160"] }, port: "4240" },
                    stats: { tx_bytes: "300", rx_bytes: "300" },
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.6.177"] }, port: "4240" },
                    stats: { tx_bytes: "960709", rx_bytes: "1740016" },
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.6.240"] }, port: "4240" },
                    stats: { tx_bytes: "48893", rx_bytes: "88608" },
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.6.68"] }, port: "4240" },
                    stats: {},
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.6.74"] }, port: "4240" },
                    stats: { tx_bytes: "957148", rx_bytes: "1735450" },
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.6.85"] }, port: "4240" },
                    stats: {},
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.6.99"] }, port: "4240" },
                    stats: { tx_bytes: "874409", rx_bytes: "1558020" },
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.7.127"] }, port: "4240" },
                    stats: { tx_bytes: "1800827", rx_bytes: "3261496" },
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.7.189"] }, port: "4240" },
                    stats: {},
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.7.229"] }, port: "4240" },
                    stats: {},
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.7.57"] }, port: "4240" },
                    stats: {},
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.7.84"] }, port: "4240" },
                    stats: { tx_bytes: "1793657", rx_bytes: "3249882" },
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.7.99"] }, port: "4240" },
                    stats: { tx_bytes: "111628", rx_bytes: "201864" },
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.8.149"] }, port: "4240" },
                    stats: {},
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.8.160"] }, port: "4240" },
                    stats: {},
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.8.164"] }, port: "4240" },
                    stats: { tx_bytes: "732531", rx_bytes: "1324246" },
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.8.194"] }, port: "4240" },
                    stats: { tx_bytes: "959098", rx_bytes: "1737080" },
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.8.206"] }, port: "4240" },
                    stats: {},
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.8.6"] }, port: "4240" },
                    stats: { tx_bytes: "112533", rx_bytes: "204806" },
                  },
                  {
                    destination: { dns: { destination_names: ["169.254.169.254"] }, port: "80" },
                    stats: { tx_bytes: "4113", rx_bytes: "7801" },
                  },
                  {
                    destination: {
                      dns: {
                        destination_names: [
                          "3BE81FD965B44E29EE37641B4D0F95CD.gr7.us-west-2.eks.amazonaws.com",
                        ],
                      },
                      port: "443",
                    },
                    stats: { tx_bytes: "9063023", rx_bytes: "48927261" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["ip-10-3-6-68.us-west-2.compute.internal"] },
                      port: "4240",
                    },
                    stats: {},
                  },
                  {
                    destination: {
                      workload: {
                        name: "cilium",
                        namespace: "kube-system",
                        kind: "WORKLOAD_KIND_DAEMONSET",
                      },
                      port: "4240",
                    },
                    stats: { tx_bytes: "60", rx_bytes: "100" },
                  },
                  {
                    destination: {
                      workload: {
                        name: "kube-prometheus-stack-prometheus-node-exporter",
                        namespace: "monitoring",
                        kind: "WORKLOAD_KIND_DAEMONSET",
                      },
                      port: "4240",
                    },
                    stats: { tx_bytes: "7202743", rx_bytes: "13054647" },
                  },
                  {
                    destination: {
                      workload: {
                        name: "otel-demo-recommendationservice",
                        namespace: "otel-demo",
                        kind: "WORKLOAD_KIND_DEPLOYMENT",
                      },
                      port: "443",
                    },
                    stats: {},
                  },
                  {
                    destination: {
                      workload: {
                        name: "tetragon",
                        namespace: "tetragon",
                        kind: "WORKLOAD_KIND_DAEMONSET",
                      },
                      port: "4240",
                    },
                    stats: { tx_bytes: "8189042", rx_bytes: "14816976" },
                  },
                  {
                    destination: {
                      workload: {
                        name: "tls-weak-version",
                        namespace: "tetragon-tracing-demo",
                        kind: "WORKLOAD_KIND_POD",
                      },
                      port: "4240",
                    },
                    stats: { tx_bytes: "958176", rx_bytes: "1737275" },
                  },
                ],
              },
              { name: "/usr/bin/cilium-envoy", arguments: "--version", in_init_tree: true },
              {
                name: "/usr/bin/cilium-envoy",
                arguments:
                  "-l info -c /var/run/cilium/envoy/bootstrap.pb --base-id 0 --log-format %t|%l|%n|%v",
                connections: [
                  {
                    destination: {
                      workload: {
                        name: "kube-prometheus-stack-grafana",
                        namespace: "monitoring",
                        kind: "WORKLOAD_KIND_DEPLOYMENT",
                      },
                      port: "3000",
                    },
                    stats: { tx_bytes: "53802", rx_bytes: "349384" },
                  },
                  {
                    destination: {
                      workload: {
                        name: "otel-demo-frontendproxy",
                        namespace: "otel-demo",
                        kind: "WORKLOAD_KIND_DEPLOYMENT",
                      },
                      port: "8080",
                    },
                    stats: { tx_bytes: "33458", rx_bytes: "1945248" },
                  },
                  {
                    destination: {
                      workload: {
                        name: "tetragon-grafana",
                        namespace: "tetragon",
                        kind: "WORKLOAD_KIND_DEPLOYMENT",
                      },
                      port: "3000",
                    },
                    stats: { tx_bytes: "52030", rx_bytes: "187938" },
                  },
                ],
              },
              {
                name: "/usr/bin/cilium-envoy-starter",
                arguments:
                  "-l info -c /var/run/cilium/envoy/bootstrap.pb --base-id 0 --log-format %t|%l|%n|%v",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/cilium-health-responder",
                arguments: "--listen 4240 --pidfile /var/run/cilium/state/health-endpoint.pid",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/ip",
                arguments: "route add 0.0.0.0/0 via 10.3.6.226 mtu 9001 dev cilium",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/ip",
                arguments: "route add 10.3.6.226/32 dev cilium",
                in_init_tree: true,
              },
              { name: "/usr/bin/kmod", arguments: "iptable_nat", in_init_tree: true },
              { name: "/usr/bin/kmod", arguments: "iptable_raw", in_init_tree: true },
              { name: "/usr/local/bin/bpftool", arguments: "-j feature probe", in_init_tree: true },
              { name: "/usr/local/bin/bpftool", arguments: "-j map show", in_init_tree: true },
              { name: "/usr/local/bin/bpftool", arguments: "-j prog show", in_init_tree: true },
              { name: "/usr/local/bin/clang", arguments: "--version", in_init_tree: true },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals -I/var/run/cilium/state -I/var/lib/cilium/bpf -I/var/lib/cilium/bpf/include -g -O2 --target=bpf -std=gnu89 -nostdinc -Wall -Wextra -Werr",
                in_init_tree: true,
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals -I/var/run/cilium/state/templates/06b1088a2d83bd98e2d25f41927b086b22396bb5b19b3d7dd969b3542da393f4 -I/var/lib/cilium/bpf -I/var/lib/cilium/bpf/include -g -O2 --target=bpf -std=gnu89 -nostdinc -Wall -Wex",
                in_init_tree: true,
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals -I/var/run/cilium/state/templates/229dea6d80c52b236d20a258d4e84a96fe6e996bbcdc2d149ea4b99b7a247af8 -I/var/lib/cilium/bpf -I/var/lib/cilium/bpf/include -g -O2 --target=bpf -std=gnu89 -nostdinc -Wall -Wext",
                in_init_tree: true,
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals -I/var/run/cilium/state/templates/2c0297a9360d6d522d9d710328d4f9a7084b81f96b2a01d88a8be16e2eb876e7 -I/var/lib/cilium/bpf -I/var/lib/cilium/bpf/include -g -O2 --target=bpf -std=gnu89 -nostdinc -Wall -Wext",
                in_init_tree: true,
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals -I/var/run/cilium/state/templates/494bb2068ff137213d5fb5ce852ae22960792eae37df1720f8f64737c760eeb7 -I/var/lib/cilium/bpf -I/var/lib/cilium/bpf/include -g -O2 --target=bpf -std=gnu89 -nostdinc -Wall -Wext",
                in_init_tree: true,
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals -I/var/run/cilium/state/templates/8f60786f44015bf7ca18b46cdb4f3e2996658fad8feebfa13b0aeb9d0dfcba4f -I/var/lib/cilium/bpf -I/var/lib/cilium/bpf/include -g -O2 --target=bpf -std=gnu89 -nostdinc -Wall -Wext",
                in_init_tree: true,
              },
              {
                name: "/usr/local/bin/clang",
                arguments:
                  "-I/var/run/cilium/state/globals -I/var/run/cilium/state/templates/c09ff35dcd7500bf9a81b9761d8d1dd38cdabd1db43787342c9623332a0a9635 -I/var/lib/cilium/bpf -I/var/lib/cilium/bpf/include -g -O2 --target=bpf -std=gnu89 -nostdinc -Wall -Wex",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/ipset",
                arguments: "create cilium_node_set_v4 iphash family inet -exist",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/ipset",
                arguments: "create cilium_node_set_v6 iphash family inet6 -exist",
                in_init_tree: true,
              },
              { name: "/usr/sbin/ipset", arguments: "list cilium_node_set_v4", in_init_tree: true },
              { name: "/usr/sbin/ipset", arguments: "list cilium_node_set_v6", in_init_tree: true },
              { name: "/usr/sbin/ipset", arguments: "restore", in_init_tree: true },
              { name: "/usr/sbin/xtables-nft-multi", in_init_tree: true },
              { name: "/usr/sbin/xtables-nft-multi", arguments: "--version", in_init_tree: true },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t filter -S",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t filter -S OLD_CILIUM_FORWARD",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t filter -S OLD_CILIUM_OUTPUT",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t mangle -S",
                in_init_tree: true,
              },
              { name: "/usr/sbin/xtables-nft-multi", arguments: "-t nat -S", in_init_tree: true },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t nat -S CILIUM_POST_nat",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t nat -S OLD_CILIUM_POST_nat",
                in_init_tree: true,
              },
              { name: "/usr/sbin/xtables-nft-multi", arguments: "-t raw -S", in_init_tree: true },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t raw -S CILIUM_OUTPUT_raw",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t raw -S OLD_CILIUM_OUTPUT_raw",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t raw -S OLD_CILIUM_PRE_raw",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -W 100000 -N KUBE-POSTROUTING -t nat",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -W 100000 -N KUBE-PROXY-FIREWALL -t filter",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -W 100000 -S KUBE-KUBELET-CANARY -t mangle",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  '-w 5 -t filter -A CILIUM_INPUT -m mark --mark 0x00000200/0x00000f00 -m comment --comment "cilium: ACCEPT for proxy traffic" -j ACCEPT',
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  "-w 5 -t filter -A CILIUM_OUTPUT -m mark ! --mark 0x00000e00/0x00000f00 -m mark ! --mark 0x00000d00/0x00000f00",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  '-w 5 -t filter -D FORWARD -m comment --comment "cilium-feeder: CILIUM_FORWARD" -j OLD_CILIUM_FORWARD',
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  '-w 5 -t filter -D OLD_CILIUM_FORWARD -i lxc+ -m comment --comment "cilium: cluster-\u003eany on lxc+ forward accept" -j ACCEPT',
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  '-w 5 -t filter -D OLD_CILIUM_FORWARD -o lxc+ -m comment --comment "cilium: any-\u003ecluster on lxc+ forward accept" -j ACCEPT',
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  '-w 5 -t filter -D OLD_CILIUM_INPUT -m mark --mark 0x200/0xf00 -m comment --comment "cilium: ACCEPT for proxy traffic" -j ACCEPT',
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -t filter -D OLD_CILIUM_OUTPUT -m mark",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -t filter -F OLD_CILIUM_FORWARD",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -t filter -N CILIUM_OUTPUT",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -t filter -S OLD_CILIUM_INPUT",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -t filter -X OLD_CILIUM_INPUT",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  '-w 5 -t mangle -A CILIUM_PRE_mangle -p udp -m mark --mark 0xb1930200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --tproxy-mark 0x200 --on-ip 127.0.0.1 --on-port 37809',
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  '-w 5 -t mangle -D OLD_CILIUM_PRE_mangle -i ens5 -m comment --comment "cilium: primary ENI" -m addrtype --dst-type LOCAL --limit-iface-in -j CONNMARK --set-xmark 0x80/0x80',
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  '-w 5 -t mangle -D OLD_CILIUM_PRE_mangle -i lxc+ -m comment --comment "cilium: primary ENI" -j CONNMARK --restore-mark --nfmask 0x80 --ctmask 0x80',
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  '-w 5 -t mangle -D OLD_CILIUM_PRE_mangle -p udp -m mark --mark 0xf8490200 -m comment --comment "cilium: TPROXY to host kube-system/cilium-ingress/listener proxy" -j TPROXY --on-port 18936 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff',
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  '-w 5 -t mangle -D POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j OLD_CILIUM_POST_mangle',
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -t mangle -F OLD_CILIUM_POST_mangle",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -t mangle -S",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -t mangle -S CILIUM_POST_mangle",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -t mangle -S OLD_CILIUM_POST_mangle",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  '-w 5 -t nat -A CILIUM_POST_nat ! -d 10.3.0.0/20 -o ens+ -m comment --comment "cilium masquerade non-cluster" -j MASQUERADE',
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  '-w 5 -t nat -A CILIUM_POST_nat -s 127.0.0.1 -o lxc+ -m comment --comment "cilium host-\u003ecluster from 127.0.0.1 masquerade" -j SNAT --to-source 10.3.6.226',
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  '-w 5 -t nat -D OLD_CILIUM_POST_nat -o ens+ -m set --match-set cilium_node_set_v4 dst -m comment --comment "exclude traffic to cluster nodes from masquerade" -j ACCEPT',
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  '-w 5 -t nat -D OLD_CILIUM_POST_nat -s 127.0.0.1/32 -o lxc+ -m comment --comment "cilium host-\u003ecluster from 127.0.0.1 masquerade" -j SNAT --to-source 10.3.6.226',
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  '-w 5 -t nat -D OUTPUT -m comment --comment "cilium-feeder: CILIUM_OUTPUT_nat" -j OLD_CILIUM_OUTPUT_nat',
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  '-w 5 -t nat -D POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_nat" -j OLD_CILIUM_POST_nat',
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  '-w 5 -t nat -D PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_nat" -j OLD_CILIUM_PRE_nat',
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -t nat -E CILIUM_PRE_nat OLD_CILIUM_PRE_nat",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -t nat -S",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -t nat -S CILIUM_PRE_nat",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -t nat -S OLD_CILIUM_OUTPUT_nat",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  '-w 5 -t raw -D OLD_CILIUM_OUTPUT_raw -o lxc+ -m mark --mark 0x800/0xe00 -m comment --comment "cilium: NOTRACK for L7 proxy upstream traffic" -j CT --notrack',
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  '-w 5 -t raw -I OUTPUT -m comment --comment "cilium-feeder: CILIUM_OUTPUT_raw" -j CILIUM_OUTPUT_raw',
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  '-w 5 -t raw -I PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_raw" -j CILIUM_PRE_raw',
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -t raw -N CILIUM_PRE_raw",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -t raw -S OLD_CILIUM_OUTPUT_raw",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -t raw -S OLD_CILIUM_PRE_raw",
                in_init_tree: true,
              },
            ],
          },
          {
            name: "cilium-node-init",
            kind: "WORKLOAD_KIND_DAEMONSET",
            processes: [
              { name: "/bin/busybox", arguments: "30" },
              {
                name: "/usr/bin/nsenter",
                arguments:
                  "-t 1 -m -u -i -n -p -- stat /tmp/startup-script.kubernetes.io_81dc8a581b97e85076f03766446d2136",
              },
              {
                name: "/usr/bin/stat",
                arguments: "/tmp/startup-script.kubernetes.io_81dc8a581b97e85076f03766446d2136",
              },
            ],
          },
          {
            name: "ebs-csi-node",
            kind: "WORKLOAD_KIND_DAEMONSET",
            processes: [
              {
                name: "/csi-node-driver-registrar",
                arguments:
                  "--csi-address=/csi/csi.sock --kubelet-registration-path=/var/lib/kubelet/plugins/ebs.csi.aws.com/csi.sock --v=2",
                in_init_tree: true,
              },
              {
                name: "/csi-node-driver-registrar",
                arguments:
                  "--kubelet-registration-path=/var/lib/kubelet/plugins/ebs.csi.aws.com/csi.sock --mode=kubelet-registration-probe",
                in_init_tree: false,
              },
              {
                name: "/livenessprobe",
                arguments: "--csi-address=/csi/csi.sock",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/aws-ebs-csi-driver",
                arguments: "node --endpoint=unix:/csi/csi.sock --logging-format=text --v=2",
                connections: [
                  {
                    destination: { dns: { destination_names: ["169.254.169.254"] }, port: "80" },
                    stats: { tx_bytes: "3014", rx_bytes: "6898" },
                  },
                  {
                    destination: {
                      workload: {
                        name: "kubernetes",
                        namespace: "default",
                        kind: "WORKLOAD_KIND_SERVICE",
                      },
                      port: "443",
                    },
                    stats: { tx_bytes: "2835", rx_bytes: "15116" },
                  },
                ],
              },
              {
                name: "/usr/bin/mount",
                arguments: "-t ext4 -o bind /var/lib/kub",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/mount",
                arguments:
                  "-t ext4 -o defaults /dev/nvme1n1 /var/lib/kubelet/plugins/kubernetes.io/csi/ebs.csi.aws.com/50f78e7f464b97750d8e9b71f0d7645caf7c547014c72fadb31a9457e33a4196/globalmount",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/mount",
                arguments:
                  "-t ext4 -o defaults /dev/nvme2n1 /var/lib/kubelet/plugins/kubernetes.io/csi/ebs.csi.aws.com/1257d04c46483a15a693b82ee546183da7dcd2282e4d0fac5a92c1d2d08280b0/globalmount",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/mount",
                arguments:
                  "-t ext4 -o defaults /dev/nvme3n1 /var/lib/kubelet/plugins/kubernetes.io/csi/ebs.csi.aws.com/9e4b9f20a11efe3406327438e39be592a809ba63231022adba7a1c2ac1c8209d/globalmount",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/blkid",
                arguments: "-p -s TYPE -s PTTYPE -o export /dev/nvme1n1",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/blkid",
                arguments: "-p -s TYPE -s PTTYPE -o export /dev/nvme2n1",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/blkid",
                arguments: "-p -s TYPE -s PTTYPE -o export /dev/nvme3n1",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/blkid",
                arguments: "-p -s TYPE -s PTTYPE -o export /dev/nvme4n1",
                in_init_tree: true,
              },
              { name: "/usr/sbin/blockdev", arguments: "--getro /dev/nvme1n1", in_init_tree: true },
              { name: "/usr/sbin/blockdev", arguments: "--getro /dev/nvme2n1", in_init_tree: true },
              { name: "/usr/sbin/blockdev", arguments: "--getro /dev/nvme3n1", in_init_tree: true },
              {
                name: "/usr/sbin/blockdev",
                arguments: "--getsize64 /dev/nvme1n1",
                in_init_tree: true,
              },
              { name: "/usr/sbin/dumpe2fs", arguments: "-h /dev/nvme1n1", in_init_tree: true },
              { name: "/usr/sbin/dumpe2fs", arguments: "-h /dev/nvme2n1", in_init_tree: true },
              { name: "/usr/sbin/dumpe2fs", arguments: "-h /dev/nvme3n1", in_init_tree: true },
              { name: "/usr/sbin/fsck", arguments: "-a /dev/nvme1n1", in_init_tree: true },
              { name: "/usr/sbin/fsck", arguments: "-a /dev/nvme2n1", in_init_tree: true },
              { name: "/usr/sbin/fsck", arguments: "-a /dev/nvme4n1", in_init_tree: true },
              { name: "/usr/sbin/fsck.ext4", arguments: "-a /dev/nvme2n1", in_init_tree: true },
              { name: "/usr/sbin/fsck.ext4", arguments: "-a /dev/nvme4n1", in_init_tree: true },
            ],
          },
          {
            name: "hubble-relay",
            kind: "WORKLOAD_KIND_DEPLOYMENT",
            processes: [
              {
                name: "/usr/bin/hubble-relay",
                arguments: "serve",
                connections: [
                  {
                    destination: {
                      dns: { destination_names: ["hubble-peer.kube-system.svc.cluster.local"] },
                      port: "443",
                    },
                    stats: {},
                  },
                  {
                    destination: {
                      dns: { destination_names: ["ip-10-3-6-68.us-west-2.compute.internal"] },
                      port: "4244",
                    },
                    stats: {},
                  },
                  {
                    destination: {
                      workload: {
                        name: "cilium",
                        namespace: "kube-system",
                        kind: "WORKLOAD_KIND_DAEMONSET",
                      },
                      port: "4244",
                    },
                    stats: { tx_bytes: "180", rx_bytes: "300" },
                  },
                  {
                    destination: {
                      workload: {
                        name: "kube-prometheus-stack-prometheus-node-exporter",
                        namespace: "monitoring",
                        kind: "WORKLOAD_KIND_DAEMONSET",
                      },
                      port: "4244",
                    },
                    stats: { tx_bytes: "50545", rx_bytes: "99587" },
                  },
                  {
                    destination: {
                      workload: {
                        name: "otel-collector",
                        namespace: "otel-collector",
                        kind: "WORKLOAD_KIND_DAEMONSET",
                      },
                      port: "4244",
                    },
                    stats: { tx_bytes: "60", rx_bytes: "100" },
                  },
                  {
                    destination: {
                      workload: {
                        name: "tetragon",
                        namespace: "tetragon",
                        kind: "WORKLOAD_KIND_DAEMONSET",
                      },
                      port: "4244",
                    },
                    stats: { tx_bytes: "54662", rx_bytes: "106080" },
                  },
                  {
                    destination: {
                      workload: {
                        name: "tls-weak-version",
                        namespace: "tetragon-tracing-demo",
                        kind: "WORKLOAD_KIND_POD",
                      },
                      port: "4244",
                    },
                    stats: { tx_bytes: "8443", rx_bytes: "16609" },
                  },
                ],
              },
            ],
          },
          {
            name: "kube-proxy",
            kind: "WORKLOAD_KIND_DAEMONSET",
            processes: [
              {
                name: "/usr/local/bin/kube-proxy",
                connections: [
                  {
                    destination: { dns: { destination_names: ["10.3.7.111"] }, port: "443" },
                    stats: {},
                  },
                  {
                    destination: {
                      dns: {
                        destination_names: [
                          "3be81fd965b44e29ee37641b4d0f95cd.gr7.us-west-2.eks.amazonaws.com",
                        ],
                      },
                      port: "443",
                    },
                    stats: { tx_bytes: "2437007", rx_bytes: "25148854" },
                  },
                ],
              },
              {
                name: "/usr/sbin/conntrack",
                arguments: "-D --orig-dst 172.20.0.10 --dst-nat 10.3.5.151 -p udp",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/conntrack",
                arguments: "-D --orig-dst 172.20.0.10 --dst-nat 10.3.8.222 -p udp",
                in_init_tree: true,
              },
              { name: "/usr/sbin/xtables-nft-multi", in_init_tree: true },
              { name: "/usr/sbin/xtables-nft-multi", arguments: "--version", in_init_tree: true },
              { name: "/usr/sbin/xtables-nft-multi", arguments: "-t nat", in_init_tree: true },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-t nat -S CILIUM_POST_nat",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -W 100000 --noflush --counters",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments:
                  '-w 5 -W 100000 -C INPUT -t filter -m conntrack --ctstate NEW -m comment --comment "kubernetes externally-visible service portals" -j KUBE-EXTERNAL-SERVICES',
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -W 100000 -C OUTPUT -t filter -j KUBE-FIREWALL",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -W 100000 -N KUBE-EXTERNAL-SERVICES -t filter",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -W 100000 -N KUBE-POSTROUTING -t nat",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -W 100000 -N KUBE-PROXY-FIREWALL -t filter",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -W 100000 -S KUBE-KUBELET-CANARY -t mangle",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -W 100000 -S KUBE-PROXY-CANARY -t mangle",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -t filter -N CILIUM_OUTPUT",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -t nat -E CILIUM_PRE_nat OLD_CILIUM_PRE_nat",
                in_init_tree: true,
              },
              {
                name: "/usr/sbin/xtables-nft-multi",
                arguments: "-w 5 -t raw -N CILIUM_PRE_raw",
                in_init_tree: true,
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
            kind: "WORKLOAD_KIND_DAEMONSET",
            processes: [
              {
                name: "/app/tracer",
                connections: [
                  {
                    destination: { dns: { destination_names: ["172.20.0.1"] }, port: "443" },
                    stats: {},
                  },
                  {
                    destination: { dns: { destination_names: ["172.20.189.207"] }, port: "80" },
                    stats: {},
                  },
                  {
                    destination: {
                      dns: { destination_names: ["kubeshark-hub.kubeshark.svc.cluster.local"] },
                      port: "80",
                    },
                    stats: {},
                  },
                  {
                    destination: {
                      workload: {
                        name: "kubernetes",
                        namespace: "default",
                        kind: "WORKLOAD_KIND_SERVICE",
                      },
                      port: "443",
                    },
                    stats: { tx_bytes: "3713819", rx_bytes: "174354819" },
                  },
                  {
                    destination: {
                      workload: {
                        name: "kubeshark-hub",
                        namespace: "kubeshark",
                        kind: "WORKLOAD_KIND_SERVICE",
                      },
                      port: "80",
                    },
                    stats: { tx_bytes: "17143", rx_bytes: "3225141" },
                  },
                ],
              },
              {
                name: "/app/worker",
                connections: [
                  {
                    destination: { dns: { destination_names: ["172.20.0.1"] }, port: "443" },
                    stats: {},
                  },
                  {
                    destination: { dns: { destination_names: ["172.20.189.207"] }, port: "80" },
                    stats: {},
                  },
                  {
                    destination: { dns: { destination_names: ["api.kubeshark.co"] }, port: "443" },
                    stats: { tx_bytes: "5943687", rx_bytes: "33795898", tx_drops: "100" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["kubeshark-hub.kubeshark.svc.cluster.local"] },
                      port: "80",
                    },
                    stats: {},
                  },
                  {
                    destination: {
                      workload: {
                        name: "kubernetes",
                        namespace: "default",
                        kind: "WORKLOAD_KIND_SERVICE",
                      },
                      port: "443",
                    },
                    stats: { tx_bytes: "246814", rx_bytes: "4554268" },
                  },
                  {
                    destination: {
                      workload: {
                        name: "kubeshark-hub",
                        namespace: "kubeshark",
                        kind: "WORKLOAD_KIND_SERVICE",
                      },
                      port: "80",
                    },
                    stats: { tx_bytes: "46669", rx_bytes: "193313339" },
                  },
                ],
                file_events: [
                  { file_path: "/etc/passwd", event: "FILE_EVENT_KIND_READ" },
                  { file_path: "/home/username/.bashrc", event: "FILE_EVENT_KIND_WRITE" },
                ],
              },
            ],
          },
        ],
      },
      {
        name: "logging",
        workloads: [
          {
            name: "loki-compactor",
            kind: "WORKLOAD_KIND_DEPLOYMENT",
            processes: [
              { name: "/bin/busybox", arguments: "-r", in_init_tree: true },
              { name: "/bin/busybox", arguments: "-s", in_init_tree: true },
              {
                name: "/usr/bin/loki",
                arguments:
                  "-config.file=/etc/loki/config/config.yaml -target=compactor -boltdb.shipper.compactor.working-directory=/var/loki/compactor",
                connections: [
                  {
                    destination: { dns: { destination_names: ["127.0.0.1"] }, port: "5778" },
                    stats: { tx_bytes: "155460", rx_bytes: "259100" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["loki-memberlist.logging.svc.cluster.local"] },
                      port: "7946",
                    },
                    stats: { tx_bytes: "9288475", rx_bytes: "26924631" },
                  },
                  {
                    destination: {
                      dns: {
                        destination_names: [
                          "loki-query-frontend-headless.logging.svc.cluster.local",
                        ],
                      },
                      port: "9095",
                    },
                    stats: {},
                  },
                  {
                    destination: {
                      dns: { destination_names: ["s3.us-west-2.amazonaws.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "2803", rx_bytes: "10347" },
                  },
                  {
                    destination: { dns: { destination_names: ["stats.grafana.org"] }, port: "443" },
                    stats: { tx_bytes: "42898", rx_bytes: "108786" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["sts.us-west-2.amazonaws.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "3064", rx_bytes: "12241" },
                  },
                  {
                    destination: {
                      workload: {
                        name: "loki-compactor",
                        namespace: "logging",
                        kind: "WORKLOAD_KIND_DEPLOYMENT",
                      },
                      port: "7946",
                    },
                    stats: { tx_bytes: "61674857", rx_bytes: "83620914" },
                  },
                  {
                    destination: {
                      workload: {
                        name: "loki-distributor",
                        namespace: "logging",
                        kind: "WORKLOAD_KIND_DEPLOYMENT",
                      },
                      port: "7946",
                    },
                    stats: { tx_bytes: "112545234", rx_bytes: "156249008" },
                  },
                  {
                    destination: {
                      workload: {
                        name: "loki-querier",
                        namespace: "logging",
                        kind: "WORKLOAD_KIND_STATEFULSET",
                      },
                      port: "7946",
                    },
                    stats: { tx_bytes: "169840419", rx_bytes: "239307469" },
                  },
                ],
              },
            ],
          },
          {
            name: "loki-querier",
            kind: "WORKLOAD_KIND_STATEFULSET",
            processes: [
              { name: "/bin/busybox", arguments: "-m", in_init_tree: true },
              { name: "/bin/busybox", arguments: "-s", in_init_tree: true },
              {
                name: "/usr/bin/loki",
                arguments: "-config.file=/etc/loki/config/config.yaml -target=querier",
                connections: [
                  {
                    destination: { dns: { destination_names: ["127.0.0.1"] }, port: "5778" },
                    stats: { tx_bytes: "106380", rx_bytes: "177300" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["loki-memberlist.logging.svc.cluster.local"] },
                      port: "7946",
                    },
                    stats: {},
                  },
                  {
                    destination: {
                      dns: {
                        destination_names: [
                          "loki-query-frontend-headless.logging.svc.cluster.local",
                        ],
                      },
                      port: "9095",
                    },
                    stats: { tx_bytes: "420", rx_bytes: "700" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["s3.us-west-2.amazonaws.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "18975105", rx_bytes: "2450147738" },
                  },
                  {
                    destination: { dns: { destination_names: ["stats.grafana.org"] }, port: "443" },
                    stats: { tx_bytes: "12168", rx_bytes: "31000" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["sts.us-west-2.amazonaws.com"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "192485", rx_bytes: "784300" },
                  },
                  {
                    destination: {
                      workload: {
                        name: "loki-compactor",
                        namespace: "logging",
                        kind: "WORKLOAD_KIND_DEPLOYMENT",
                      },
                      port: "7946",
                    },
                    stats: { tx_bytes: "69671243", rx_bytes: "98680873" },
                  },
                  {
                    destination: {
                      workload: {
                        name: "loki-distributor",
                        namespace: "logging",
                        kind: "WORKLOAD_KIND_DEPLOYMENT",
                      },
                      port: "7946",
                    },
                    stats: { tx_bytes: "47981487", rx_bytes: "68429979" },
                  },
                  {
                    destination: {
                      workload: {
                        name: "loki-querier",
                        namespace: "logging",
                        kind: "WORKLOAD_KIND_STATEFULSET",
                      },
                      port: "7946",
                    },
                    stats: { tx_bytes: "13781188", rx_bytes: "19768409" },
                  },
                ],
              },
            ],
          },
          {
            name: "promtail",
            kind: "WORKLOAD_KIND_DAEMONSET",
            processes: [
              {
                name: "/usr/bin/promtail",
                arguments:
                  "-config.file=/etc/promtail/promtail.yaml -client.external-labels=cluster=df-tetragon-dev-ce-01 -config.expand-env=true",
                connections: [
                  {
                    destination: {
                      dns: { destination_names: ["logs-prod3.grafana.net"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "4868857267", rx_bytes: "5064573457" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["loki-gateway.logging.svc.cluster.local"] },
                      port: "80",
                    },
                    stats: {},
                  },
                  {
                    destination: {
                      workload: {
                        name: "kubernetes",
                        namespace: "default",
                        kind: "WORKLOAD_KIND_SERVICE",
                      },
                      port: "443",
                    },
                    stats: { tx_bytes: "1504643", rx_bytes: "4060989" },
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
            name: "kube-prometheus-stack-prometheus-node-exporter",
            kind: "WORKLOAD_KIND_DAEMONSET",
            processes: [
              {
                name: "/bin/node_exporter",
                arguments:
                  "--path.procfs=/host/proc --path.sysfs=/host/sys --path.rootfs=/host/root --path.udev.data=/host/root/run/udev/data --web.listen-address=[0.0.0.0]:9100 --collector.filesystem.mount-points-exclude=^/(dev|proc|sys|var/lib/docker/.",
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
            kind: "WORKLOAD_KIND_DAEMONSET",
            processes: [
              {
                name: "/otelcol-contrib",
                connections: [
                  {
                    destination: { dns: { destination_names: ["10.3.6.68"] }, port: "2112" },
                    stats: {},
                  },
                  {
                    destination: { dns: { destination_names: ["172.20.170.76"] }, port: "80" },
                    stats: {},
                  },
                  {
                    destination: { dns: { destination_names: ["35.190.55.74"] }, port: "443" },
                    stats: { tx_bytes: "58168670", rx_bytes: "63946707" },
                  },
                  {
                    destination: {
                      dns: { destination_names: ["otlp-gateway-prod-us-central-0.grafana.net"] },
                      port: "443",
                    },
                    stats: { tx_bytes: "4761462075", rx_bytes: "5202746058" },
                  },
                  {
                    destination: {
                      workload: {
                        name: "kube-prometheus-stack-prometheus-node-exporter",
                        namespace: "monitoring",
                        kind: "WORKLOAD_KIND_DAEMONSET",
                      },
                      port: "2112",
                    },
                    stats: { tx_bytes: "22561972", rx_bytes: "1118109438" },
                  },
                  {
                    destination: {
                      workload: {
                        name: "kube-prometheus-stack-prometheus-node-exporter",
                        namespace: "monitoring",
                        kind: "WORKLOAD_KIND_DAEMONSET",
                      },
                      port: "10250",
                    },
                    stats: { tx_bytes: "24981947", rx_bytes: "914187991" },
                  },
                  {
                    destination: {
                      workload: {
                        name: "otel-targetallocator",
                        namespace: "otel-collector",
                        kind: "WORKLOAD_KIND_SERVICE",
                      },
                      port: "80",
                    },
                    stats: { tx_bytes: "19239350", rx_bytes: "207148100" },
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
            name: "otel-demo-opensearch",
            kind: "WORKLOAD_KIND_STATEFULSET",
            processes: [
              {
                name: "/usr/bin/bash",
                arguments: '-c "#!/usr/bin/env bash\ncp -r /tmp/configfolder/*  /tmp/config/\n"',
                in_init_tree: true,
              },
              {
                name: "/usr/bin/bash",
                arguments: "./opensearch-docker-entrypoint.sh opensearch",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/bash",
                arguments:
                  "/usr/share/opensearch/bin/opensearch -Ediscovery.seed_hosts=opensearch-",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/bash",
                arguments:
                  "/usr/share/opensearch/bin/opensearch-performance-analyzer/performance-analyzer-agent-cli",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/bash",
                arguments: "bin/opensearch-keystore has-passwd --silent",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=cp /usr/bin/cp -r /tmp/configfolder/opensearch.yml /tmp/config/",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=dirname /usr/bin/dirname /usr/share/opensearch/bin/opensearch",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments: "--coreutils-prog-shebang=dirname /usr/bin/dirname bin/opensearch-cli",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=dirname /usr/bin/dirname bin/opensearch-keystore",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments: "--coreutils-prog-shebang=env /usr/bin/env",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=env /usr/bin/env bash /usr/share/opensearch/bin/opensearch-cli",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=env /usr/bin/env bash bin/opensearch-cli has-passwd --silent",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=env /usr/bin/env bash bin/opensearch-keystore has-passwd --silent",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments: "--coreutils-prog-shebang=id /usr/bin/id -u",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments: "--coreutils-prog-shebang=uname /usr/bin/uname -s",
                in_init_tree: true,
              },
              { name: "/usr/sbin/ldconfig", arguments: "-p", in_init_tree: true },
              {
                name: "/usr/share/opensearch/jdk/bin/java",
                arguments: "-Xms1g -Xmx1g -XX:+UseG1GC -XX:G1ReservePercent=25 -",
                in_init_tree: true,
              },
              {
                name: "/usr/share/opensearch/jdk/bin/java",
                arguments: "-Xshare:auto -Xms4m -Xmx64m -X",
                in_init_tree: true,
              },
              {
                name: "/usr/share/opensearch/jdk/bin/java",
                arguments:
                  "-Xshare:auto -Xms4m -Xmx64m -XX:+UseSerialGC -Dopensearch.cgroups.hierarchy.override=/ -Xms300m -Xmx300m -Dopensearch.path.",
                in_init_tree: true,
              },
              {
                name: "/usr/share/opensearch/jdk/bin/java",
                arguments:
                  "-Xshare:auto -cp /usr/share/opensearch/lib/* org.opensearch.tools.java_version_checker.JavaVersionChecker",
                in_init_tree: true,
              },
              {
                name: "/usr/share/opensearch/jdk/bin/java",
                arguments: "-version",
                in_init_tree: true,
              },
              {
                name: "/usr/share/opensearch/jdk/lib/jspawnhelper",
                arguments: "21.0.5+11-LTS 47:48:50",
                in_init_tree: true,
              },
              {
                name: "/usr/share/opensearch/jdk/lib/jspawnhelper",
                arguments: "21.0.5+11-LTS 62:63:65",
                in_init_tree: true,
              },
            ],
          },
        ],
      },
      {
        name: "tenant-jobs",
        workloads: [
          {
            name: "jobposting",
            kind: "WORKLOAD_KIND_DEPLOYMENT",
            processes: [
              {
                name: "/bin/busybox",
                arguments:
                  '-c "until curl -s -o /dev/null http://coreapi:9080; do echo waiting for coreapi; sleep 5; done"',
                in_init_tree: true,
              },
              {
                name: "/bin/busybox",
                arguments:
                  '-c "until curl -s -o /dev/null http://elasticsearch-master.tenant-jobs.svc.cluster.local:9200; do echo waiting for elasticsearch; sleep 5; done"',
                in_init_tree: true,
              },
              {
                name: "/bin/busybox",
                arguments:
                  '/usr/local/bin/docker-entrypoint.sh /bin/sh -c "PORT=9080 node server.js"',
                in_init_tree: true,
              },
              { name: "/bin/busybox", arguments: "30", in_init_tree: true },
              {
                name: "/usr/bin/curl",
                arguments: "-s -o /dev/null http://coreapi:9080",
                connections: [
                  {
                    destination: {
                      dns: { destination_names: ["coreapi.tenant-jobs.svc.cluster.local"] },
                      port: "9080",
                    },
                    stats: {},
                  },
                ],
              },
              {
                name: "/usr/bin/curl",
                arguments:
                  "-s -o /dev/null http://elasticsearch-master.tenant-jobs.svc.cluster.local:9200",
                connections: [
                  {
                    destination: {
                      dns: {
                        destination_names: ["elasticsearch-master.tenant-jobs.svc.cluster.local"],
                      },
                      port: "9200",
                    },
                    stats: {},
                  },
                ],
              },
              { name: "/usr/local/bin/node", arguments: "server.js", in_init_tree: true },
            ],
          },
          {
            name: "jobs-app-zookeeper-0",
            kind: "WORKLOAD_KIND_POD",
            processes: [
              {
                name: "/usr/bin/bash",
                arguments: "./zookeeper_config_generator.sh",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/bash",
                arguments: "./zookeeper_tls_prepare_certificates.sh",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/bash",
                arguments: "/opt/kafka/bin/zookeeper-server-start.sh /tmp/zookeeper.properties",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/bash",
                arguments: "/opt/kafka/zookeeper_healthcheck.sh",
                in_init_tree: false,
              },
              {
                name: "/usr/bin/bash",
                arguments: "/opt/kafka/zookeeper_run.sh",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments: "--coreutils-prog-shebang=cat /usr/bin/cat",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=cat /usr/bin/cat /opt/kafka/custom-config/zookeeper.node-count",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments: "--coreutils-prog-shebang=cut /usr/bin/cut -d - -f2-",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments: "--coreutils-prog-shebang=cut /usr/bin/cut -d . -f2-4",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=dirname /usr/bin/dirname /opt/kafka/bin/kafka-run-class.sh",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=dirname /usr/bin/dirname /opt/kafka/bin/zookeeper-server-start.sh",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=env /usr/bin/env bash ./zookeeper_config_generator.sh",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=env /usr/bin/env bash /opt/kafka/zookeeper_healthcheck.sh",
                in_init_tree: false,
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=env /usr/bin/env bash /opt/kafka/zookeeper_run.sh",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments: "--coreutils-prog-shebang=head /usr/bin/head -c32",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments: "--coreutils-prog-shebang=mkdir /usr/bin/mkdir -p /tmp/zookeeper",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=mkdir /usr/bin/mkdir -p /var/lib/zookeeper/data",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=rm /usr/bin/rm -f /tmp/zookeeper/cluster.keystore.p12",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments:
                  "--coreutils-prog-shebang=rm /usr/bin/rm -f /tmp/zookeeper/cluster.truststore.p12",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/coreutils",
                arguments: "--coreutils-prog-shebang=tee /usr/bin/tee /tmp/zookeeper.properties",
                in_init_tree: true,
              },
              { name: "/usr/bin/gawk", arguments: '-F- "{print $NF+1}"', in_init_tree: true },
              {
                name: "/usr/bin/grep",
                arguments:
                  "-E (-(test|test-sources|src|scaladoc|javadoc)\\.jar|jar.asc|connect-file.*\\.jar)$",
                in_init_tree: true,
              },
              { name: "/usr/bin/hostname", in_init_tree: true },
              {
                name: "/usr/bin/ncat",
                arguments: "127.0.0.1 12181",
                connections: [
                  {
                    destination: { dns: { destination_names: ["127.0.0.1"] }, port: "12181" },
                    stats: { tx_bytes: "20394308", rx_bytes: "39440108" },
                  },
                ],
              },
              {
                name: "/usr/bin/openssl",
                arguments:
                  "pkcs12 -export -in /opt/kafka/zookeeper-node-certs/jobs-app-zookeeper-0.crt -inkey /opt/kafka/zookeeper-no",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/openssl",
                arguments:
                  "verify -CAfile /opt/kafka/cluster-ca-certs/ca.crt /opt/kafka/zookeeper-node-certs/jobs-app-zookeeper-0.crt",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/openssl",
                arguments:
                  "verify -CAfile /opt/kafka/cluster-ca-certs/ca.password /opt/kafka/zookeeper-node-certs/jobs-app-zookeeper-0.crt",
                in_init_tree: true,
              },
              { name: "/usr/bin/rev", in_init_tree: true },
              {
                name: "/usr/bin/sed",
                arguments: "-e s/password=.*/password=[hidden]/g",
                in_init_tree: true,
              },
              {
                name: "/usr/bin/tini",
                arguments:
                  "-w -e 143 -- /opt/kafka/bin/zookeeper-server-start.sh /tmp/zookeeper.properties",
                in_init_tree: true,
              },
              {
                name: "/usr/lib/jvm/java-17-openjdk-17.0.9.0.9-2.el8.x86_64/bin/java",
                in_init_tree: true,
              },
              {
                name: "/usr/lib/jvm/java-17-openjdk-17.0.9.0.9-2.el8.x86_64/bin/keytool",
                arguments:
                  "-keystore /tmp/zookeeper/cluster.truststore.p12 -storepass zCAVEXR3xelp9yPnXmfXldLUeTklewHK -noprompt -alias ca -import -file /opt/kafka/cluster-ca-certs/ca.crt -storetype PKCS12",
                in_init_tree: true,
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
            kind: "WORKLOAD_KIND_DAEMONSET",
            processes: [
              { name: "/bin/busybox", in_init_tree: true },
              {
                name: "/usr/bin/tetragon",
                connections: [
                  {
                    destination: { dns: { destination_names: ["10.3.6.212"] }, port: "57902" },
                    stats: {},
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.6.68"] }, port: "36322" },
                    stats: {},
                  },
                  {
                    destination: { dns: { destination_names: ["10.3.7.122"] }, port: "51130" },
                    stats: {},
                  },
                  {
                    destination: { dns: { destination_names: ["172.20.0.1"] }, port: "443" },
                    stats: {},
                  },
                  {
                    destination: {
                      workload: {
                        name: "kubernetes",
                        namespace: "default",
                        kind: "WORKLOAD_KIND_SERVICE",
                      },
                      port: "443",
                    },
                    stats: { tx_bytes: "560254", rx_bytes: "2618755" },
                  },
                ],
              },
              {
                name: "/var/lib/tetragon/tetragon-fs-scanner",
                arguments:
                  "-hostMntNs 4026531841 -scannerFifoPath /var/run/cilium/hubble/fs_scanner.sock -maxSizeFileDigest 1073741824 -maxTimeoutFileDigest 30 -logLevel info -logFormat text",
                in_init_tree: true,
              },
              {
                name: "/var/lib/tetragon/tetragon-runner",
                arguments:
                  "/procRoot/1/ns/mnt /var/lib/tetragon/tetragon-fs-scanner -hostMntNs 4026531841 -scannerFifoPath /var/run/cilium/hubble/fs_scanner.sock -maxSizeFileDigest 1073741824 -maxTimeoutFileDigest 30 -logLevel info -logFormat text",
                in_init_tree: true,
              },
            ],
          },
        ],
      },
      {
        name: "vector",
        workloads: [
          {
            name: "vector",
            kind: "WORKLOAD_KIND_DAEMONSET",
            processes: [
              {
                name: "/usr/bin/vector",
                arguments: "--config-dir /etc/vector/",
                connections: [
                  {
                    destination: {
                      dns: {
                        destination_names: ["http-inputs.cisco-ngfwbu-valent.splunkcloud.com"],
                      },
                      port: "443",
                    },
                    stats: { tx_bytes: "3437455053", rx_bytes: "3461776941" },
                  },
                  {
                    destination: {
                      dns: {
                        destination_names: ["tetragon-aggregator.tetragon.svc.cluster.local"],
                      },
                      port: "8080",
                    },
                    stats: {},
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
        {
          name: "/bin/node_exporter",
          arguments:
            "--path.procfs=/host/proc --path.sysfs=/host/sys --path.rootfs=/host/root --path.udev.data=/host/root/run/udev/data --web.listen-address=[0.0.0.0]:9100 --collector.filesystem.mount-points-exclude=^/(dev|proc|sys|var/lib/docker/.",
        },
        { name: "/opt/cni/bin/cilium-cni" },
        {
          name: "/opt/cni/bin/cilium-mount",
          arguments: "/run/cilium/cgroupv2",
          in_init_tree: true,
        },
        { name: "/opt/cni/bin/cilium-sysctlfix", in_init_tree: true },
        { name: "/opt/cni/bin/loopback" },
        {
          name: "/opt/tetragon/tetragon-oci-hook",
          arguments:
            "createRuntime --log-fname /opt/tetragon/tetragon-oci-hook.log --grpc-address=localhost:54321 --fail-allow-namespaces tetragon",
          connections: [
            {
              destination: { dns: { destination_names: ["127.0.0.1"] }, port: "54321" },
              stats: { tx_bytes: "19274964", rx_bytes: "54629964" },
            },
          ],
        },
        { name: "/pause", in_init_tree: true },
        { name: "/runc", arguments: "init" },
        { name: "/usr/bin/basename", arguments: "/cni/loopback", in_init_tree: true },
        { name: "/usr/bin/basename", arguments: "/opt/cni/bin/cilium-cni", in_init_tree: true },
        {
          name: "/usr/bin/bash",
          arguments:
            '-c "\n        /usr/bin/chronyc cyclelogs \u003e /dev/null 2\u003e\u00261 || true\n" logrotate_script "/var/log/chrony/*.log "',
        },
        {
          name: "/usr/bin/bash",
          arguments: '-c "set -o errexit\nset -o pipefail\nset -o nounset\n\n# When running"',
          in_init_tree: false,
        },
        {
          name: "/usr/bin/bash",
          arguments: '-c -- "mount | grep "/sys/fs/bpf type bpf" || mount -t bpf bpf /sys/fs/bpf"',
          in_init_tree: true,
        },
        { name: "/usr/bin/bash", arguments: "/etc/update-motd.d/10-nvidia-eula" },
        { name: "/usr/bin/bash", arguments: "/etc/update-motd.d/70-available-updates" },
        { name: "/usr/bin/bash", arguments: "/install-plugin.sh", in_init_tree: true },
        { name: "/usr/bin/bash", arguments: "/usr/sbin/raid-check" },
        { name: "/usr/bin/bash", arguments: "/usr/sbin/update-motd" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partFZbp4" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partG9jiP" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partbyOmi" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partozF3t" },
        { name: "/usr/bin/cat", arguments: "/tmp/motd.partpYGw1" },
        { name: "/usr/bin/chmod", arguments: "go+r /var/lib/update-motd/tmp.87vyRaN2Ax" },
        { name: "/usr/bin/chmod", arguments: "go+r /var/lib/update-motd/tmp.Pd9ruT5n8i" },
        { name: "/usr/bin/chmod", arguments: "go+r /var/lib/update-motd/tmp.ajQhVZFttH" },
        { name: "/usr/bin/chmod", arguments: "go+r /var/lib/update-motd/tmp.fXu3rKDIG1" },
        { name: "/usr/bin/chmod", arguments: "go+r /var/lib/update-motd/tmp.nVNZ7uCJs4" },
        { name: "/usr/bin/chronyc", arguments: "cyclelogs" },
        {
          name: "/usr/bin/cilium-agent",
          arguments: "--config-dir=/tmp/cilium/config-map",
          connections: [
            {
              destination: { dns: { destination_names: ["10.3.5.136"] }, port: "4240" },
              stats: {},
            },
            {
              destination: { dns: { destination_names: ["10.3.5.174"] }, port: "4240" },
              stats: {},
            },
            {
              destination: { dns: { destination_names: ["10.3.5.184"] }, port: "4240" },
              stats: { tx_bytes: "3050", rx_bytes: "5580" },
            },
            {
              destination: { dns: { destination_names: ["10.3.5.236"] }, port: "4240" },
              stats: { tx_bytes: "295984", rx_bytes: "536068" },
            },
            { destination: { dns: { destination_names: ["10.3.5.40"] }, port: "4240" }, stats: {} },
            {
              destination: { dns: { destination_names: ["10.3.5.70"] }, port: "443" },
              stats: { tx_bytes: "1555776", rx_bytes: "9985163" },
            },
            { destination: { dns: { destination_names: ["10.3.6.14"] }, port: "4240" }, stats: {} },
            {
              destination: { dns: { destination_names: ["10.3.6.160"] }, port: "4240" },
              stats: { tx_bytes: "300", rx_bytes: "300" },
            },
            {
              destination: { dns: { destination_names: ["10.3.6.177"] }, port: "4240" },
              stats: { tx_bytes: "960709", rx_bytes: "1740016" },
            },
            {
              destination: { dns: { destination_names: ["10.3.6.240"] }, port: "4240" },
              stats: { tx_bytes: "48893", rx_bytes: "88608" },
            },
            { destination: { dns: { destination_names: ["10.3.6.68"] }, port: "4240" }, stats: {} },
            {
              destination: { dns: { destination_names: ["10.3.6.74"] }, port: "4240" },
              stats: { tx_bytes: "957148", rx_bytes: "1735450" },
            },
            { destination: { dns: { destination_names: ["10.3.6.85"] }, port: "4240" }, stats: {} },
            {
              destination: { dns: { destination_names: ["10.3.6.99"] }, port: "4240" },
              stats: { tx_bytes: "874409", rx_bytes: "1558020" },
            },
            {
              destination: { dns: { destination_names: ["10.3.7.127"] }, port: "4240" },
              stats: { tx_bytes: "1800827", rx_bytes: "3261496" },
            },
            {
              destination: { dns: { destination_names: ["10.3.7.189"] }, port: "4240" },
              stats: {},
            },
            {
              destination: { dns: { destination_names: ["10.3.7.229"] }, port: "4240" },
              stats: {},
            },
            { destination: { dns: { destination_names: ["10.3.7.57"] }, port: "4240" }, stats: {} },
            {
              destination: { dns: { destination_names: ["10.3.7.84"] }, port: "4240" },
              stats: { tx_bytes: "1793657", rx_bytes: "3249882" },
            },
            {
              destination: { dns: { destination_names: ["10.3.7.99"] }, port: "4240" },
              stats: { tx_bytes: "111628", rx_bytes: "201864" },
            },
            {
              destination: { dns: { destination_names: ["10.3.8.149"] }, port: "4240" },
              stats: {},
            },
            {
              destination: { dns: { destination_names: ["10.3.8.160"] }, port: "4240" },
              stats: {},
            },
            {
              destination: { dns: { destination_names: ["10.3.8.164"] }, port: "4240" },
              stats: { tx_bytes: "732531", rx_bytes: "1324246" },
            },
            {
              destination: { dns: { destination_names: ["10.3.8.194"] }, port: "4240" },
              stats: { tx_bytes: "959098", rx_bytes: "1737080" },
            },
            {
              destination: { dns: { destination_names: ["10.3.8.206"] }, port: "4240" },
              stats: {},
            },
            {
              destination: { dns: { destination_names: ["10.3.8.6"] }, port: "4240" },
              stats: { tx_bytes: "112533", rx_bytes: "204806" },
            },
            {
              destination: { dns: { destination_names: ["169.254.169.254"] }, port: "80" },
              stats: { tx_bytes: "4113", rx_bytes: "7801" },
            },
            {
              destination: {
                dns: {
                  destination_names: [
                    "3BE81FD965B44E29EE37641B4D0F95CD.gr7.us-west-2.eks.amazonaws.com",
                  ],
                },
                port: "443",
              },
              stats: { tx_bytes: "9063023", rx_bytes: "48927261" },
            },
            {
              destination: {
                dns: { destination_names: ["ip-10-3-6-68.us-west-2.compute.internal"] },
                port: "4240",
              },
              stats: {},
            },
            {
              destination: {
                workload: {
                  name: "cilium",
                  namespace: "kube-system",
                  kind: "WORKLOAD_KIND_DAEMONSET",
                },
                port: "4240",
              },
              stats: { tx_bytes: "60", rx_bytes: "100" },
            },
            {
              destination: {
                workload: {
                  name: "kube-prometheus-stack-prometheus-node-exporter",
                  namespace: "monitoring",
                  kind: "WORKLOAD_KIND_DAEMONSET",
                },
                port: "4240",
              },
              stats: { tx_bytes: "7202743", rx_bytes: "13054647" },
            },
            {
              destination: {
                workload: {
                  name: "otel-demo-recommendationservice",
                  namespace: "otel-demo",
                  kind: "WORKLOAD_KIND_DEPLOYMENT",
                },
                port: "443",
              },
              stats: {},
            },
            {
              destination: {
                workload: {
                  name: "tetragon",
                  namespace: "tetragon",
                  kind: "WORKLOAD_KIND_DAEMONSET",
                },
                port: "4240",
              },
              stats: { tx_bytes: "8189042", rx_bytes: "14816976" },
            },
            {
              destination: {
                workload: {
                  name: "tls-weak-version",
                  namespace: "tetragon-tracing-demo",
                  kind: "WORKLOAD_KIND_POD",
                },
                port: "4240",
              },
              stats: { tx_bytes: "958176", rx_bytes: "1737275" },
            },
          ],
        },
        {
          name: "/usr/bin/containerd",
          connections: [
            {
              destination: { dns: { destination_names: ["104.98.118.153"] }, port: "443" },
              stats: { tx_bytes: "308", rx_bytes: "656" },
            },
            {
              destination: { dns: { destination_names: ["104.98.118.171"] }, port: "443" },
              stats: {},
            },
            {
              destination: { dns: { destination_names: ["104.98.118.178"] }, port: "443" },
              stats: { tx_bytes: "128", rx_bytes: "204" },
            },
            {
              destination: { dns: { destination_names: ["127.0.0.1"] }, port: "54321" },
              stats: { tx_bytes: "15579", rx_bytes: "1122313" },
            },
            {
              destination: { dns: { destination_names: ["3.94.224.37"] }, port: "443" },
              stats: { tx_bytes: "44261", rx_bytes: "58583" },
            },
            {
              destination: { dns: { destination_names: ["34.201.96.33"] }, port: "443" },
              stats: {},
            },
            {
              destination: { dns: { destination_names: ["35.160.57.100"] }, port: "443" },
              stats: {},
            },
            {
              destination: { dns: { destination_names: ["35.167.171.26"] }, port: "443" },
              stats: {},
            },
            {
              destination: { dns: { destination_names: ["35.170.31.10"] }, port: "443" },
              stats: {},
            },
            {
              destination: { dns: { destination_names: ["35.175.162.128"] }, port: "443" },
              stats: {},
            },
            {
              destination: { dns: { destination_names: ["44.206.145.36"] }, port: "443" },
              stats: { tx_bytes: "180", rx_bytes: "284" },
            },
            {
              destination: { dns: { destination_names: ["44.209.92.154"] }, port: "443" },
              stats: {},
            },
            {
              destination: { dns: { destination_names: ["52.218.229.1"] }, port: "443" },
              stats: {},
            },
            {
              destination: { dns: { destination_names: ["52.92.132.194"] }, port: "443" },
              stats: {},
            },
            {
              destination: {
                dns: { destination_names: ["602401143452.dkr.ecr.us-west-2.amazonaws.com"] },
                port: "443",
              },
              stats: { tx_bytes: "82997", rx_bytes: "176525" },
            },
            {
              destination: { dns: { destination_names: ["98.85.153.80"] }, port: "443" },
              stats: { tx_bytes: "13085", rx_bytes: "18155" },
            },
            {
              destination: { dns: { destination_names: ["auth.docker.io"] }, port: "443" },
              stats: { tx_bytes: "13019", rx_bytes: "122004" },
            },
            {
              destination: { dns: { destination_names: ["cdn01.quay.io"] }, port: "443" },
              stats: { tx_bytes: "673764", rx_bytes: "658927348" },
            },
            {
              destination: {
                dns: {
                  destination_names: [
                    "prod-us-west-2-starport-layer-bucket.s3.us-west-2.amazonaws.com",
                  ],
                },
                port: "443",
              },
              stats: { tx_bytes: "35671", rx_bytes: "11250871" },
            },
            {
              destination: {
                dns: { destination_names: ["production.cloudflare.docker.com"] },
                port: "443",
              },
              stats: { tx_bytes: "1221745", rx_bytes: "1418605977" },
            },
            {
              destination: { dns: { destination_names: ["quay.io"] }, port: "443" },
              stats: { tx_bytes: "55421", rx_bytes: "386279" },
            },
            {
              destination: { dns: { destination_names: ["registry-1.docker.io"] }, port: "443" },
              stats: { tx_bytes: "211702", rx_bytes: "431997" },
            },
          ],
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments: "-namespace k8s.io -address /run/container",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 08883d865a89c742951f2115a87eb4ff59ad2015d73449dbfb04209b3a0e14d9 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 09548312220ec3e0de3896faefb927bcdad39234e0ddb9c6516f7a9095a3cc47 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 1183283b661044c81b34ed88b1a3dc0944c6380f8e0be84acfa517a02ff62d59 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 17e8e96b9964b98ef55105aa0196deb58ea163293b245681b1f2fe41f3fe0833 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 19c9e259bab74fe058158bbd1070d59fc98183886b76af62ea7cc412ded8e18e start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 201c89fc41d4e20b5bd9297e894df4434d29e65a2a3684661db6b841ca5cfe77 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 226fc452d76ad62ef4f32c6be9e5b268177553ccb4d60e0d519b04a4053d1789 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 32b60bb311a54bc068efb88101a6a9c01ee75ab8f173be6af6fb4159a152e128 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 36367f84980c65ef4176bda52c8adc435d55e6205d2522003ed3d97d6225e363 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 434a8e2f572801d81645bff5bf464795572b45a3507fb0f6e0ca0456458dfa53 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 435bb2d6ade8fd58fa50268b3f86634ba3cda59a05f6de1d65bdf67618e1e826 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 4474372cf1cffdadc2070b249b1e98522080020d82b718548eb2ca7fb2ee38f6 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 4db0fdb1f99549726ea057d2b222dd0ee4f33aa290a9bb5cc217ae53c510d3ba start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 5099bfddd9c276e123c6be27b0fc121a340afb84eacb79b2ce53bc1336a0b3b7 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 537d3ffc2c769e2087ab0033e515f027bab155b5865b82cad83f03f348633471 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 55b43dd8c1eda60df9af9a84f82fb602150433888bab40551758752325a2ab52 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 5a35a2d0be54ce6315737151d824c7a915654d38bf35cc75dd389b48c77b1978 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 5f7997e0be69cf1fbe8634d35825b6ac6011bd1937d19ce2c20cc2ae5a84cd3c start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 5fb3fb618366612756b3628997f06d5c8bd6a3db21afdc65850fd8a8a30d8ac0 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 6769dd958b19812d0defbf8d6197d09b85948d3edb34bd332939cf6457a73ea5 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 71ef2a30ffee4156da0fdc1e6b54e50d0a82a8944e82e1fb6ce7dd2ef761cc6e start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 7229931b39a9d70b9483fbeb030b1448add6abcb0e0ef62dbad08aa213eae7a7 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 81a787e06ebd8bf7d75838dbd1edf38b1edb4a92231aa2ed74cca91df36a9192 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 886f2b93925442ee3c1a6f1ef8270298d84a7ca0fed4f3b74baf36284dcfe2e7 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 897260ef87715a7a1b8bab5668711378c32e0a237fd9645f472c1d17de4addf7 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 95fa3c52c781b14a45a93c88878e74b0e85e29d9e752d68a97e3bb6219138e5e start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 9a7cbc9705fddd59d3eaa3253704a23a454e1c7bbb63c36af06514128e28161c start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 9d69c35ce63217030578f7b3e4102113e39920d1abf1b5ed104c87094d8b34c4 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id 9ea52f867f8fef8da54f2833769129396063516d90a9adc1cb343c494e8a92d1 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id a0c6069de594dcfd390c9a01126c65d3e9aee41754a60069057da4f4b038fda3 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id a4517a979f0789789dec84fda891e217767559c8167d734a105665078592f0bc start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id b49d74b47d8157d6bcf023ab32d582a634ee057c33a9e2cc03b39af5f13e8db8 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id c20fef855041e0a13d0c435bb549f29706098053d87d661edd8fef838241f876 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id c40d83eb146571af4fce932a9d25ac27f01a54ed5eb1b76e505b023772b1e1e1 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id c91aee3458ebf2e32b5ed8ecd9183dedda2a7f2b991396dc097eb5df4844a221 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id d8ac2979f8e57b9fb13b8a25e9e8f75c45c5786a3a51d5cdafefbb4e79c5cb70 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id dd50d9692d63eb50bb03cd87c9539d2d221110a269c8803bbf3eea1b8426bcf1 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id e39a53c3278842a72f0c5d7841ac73eb6a8d8d0fb18a8e5804c386ea01cdc219 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id f0b9b664827fa9000ea04029161839daafcd5d3303a5e8bf0d7847fecbf76ae1 start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -address /run/containerd/containerd.sock -publish-binary /usr/bin/containerd -id fca7fd7600f3429ccf1a5a7ffa304f71944c415de2fc706119fe3fb5abd92f3e start",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -id 32b60bb311a54bc068efb88101a6a9c01ee75ab8f173be6af6fb4159a152e128 -address /run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -id 36367f84980c65ef4176bda52c8adc435d55e6205d2522003ed3d97d6225e363 -address /run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -id 4db0fdb1f99549726ea057d2b222dd0ee4f33aa290a9bb5cc217ae53c510d3ba -address /run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -id 537d3ffc2c769e2087ab0033e515f027bab155b5865b82cad83f03f348633471 -address /run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -id 55b43dd8c1eda60df9af9a84f82fb602150433888bab40551758752325a2ab52 -address /run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -id 5a35a2d0be54ce6315737151d824c7a915654d38bf35cc75dd389b48c77b1978 -address /run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -id 842eb87090605a5c17e5fdc5fd6cf8f29c4ffcc5fcbce9dd5b3129c9ae918455 -address /run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -id a4517a979f0789789dec84fda891e217767559c8167d734a105665078592f0bc -address /run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/containerd-shim-runc-v2",
          arguments:
            "-namespace k8s.io -id c20fef855041e0a13d0c435bb549f29706098053d87d661edd8fef838241f876 -address /run/containerd/containerd.sock",
        },
        {
          name: "/usr/bin/cp",
          arguments: "/cni/loopback /host/opt/cni/bin/.loopback.new",
          in_init_tree: true,
        },
        {
          name: "/usr/bin/cp",
          arguments: "/opt/cni/bin/cilium-cni /host/opt/cni/bin/.cilium-cni.new",
          in_init_tree: true,
        },
        {
          name: "/usr/bin/cp",
          arguments: "/usr/bin/cilium-mount /hostbin/cilium-mount",
          in_init_tree: true,
        },
        {
          name: "/usr/bin/cp",
          arguments: "/usr/bin/cilium-sysctlfix /hostbin/cilium-sysctlfix",
          in_init_tree: true,
        },
        { name: "/usr/bin/cut", arguments: '-f 1 -d " "' },
        {
          name: "/usr/bin/dash",
          arguments:
            '-c "until test -s "/tmp/cilium-bootstrap.d/cilium-bootstrap-time"; do\n  echo "Waiting on node-init to run...";\n  sleep 1;\ndone\n"',
          in_init_tree: true,
        },
        {
          name: "/usr/bin/dash",
          arguments:
            '-ec "cp /usr/bin/cilium-mount /hostbin/cilium-mount;\nnsenter --cgroup=/hostproc/1/ns/cgroup --mount=/hostproc/1/ns/mnt "${BIN_PATH}/cilium-mount" $CGROUP_ROOT;\nrm /hostbin/cilium-mount\n"',
          in_init_tree: true,
        },
        {
          name: "/usr/bin/dash",
          arguments:
            '-ec "cp /usr/bin/cilium-sysctlfix /hostbin/cilium-sysctlfix;\nnsenter --mount=/hostproc/1/ns/mnt "${BIN_PATH}/cilium-sysctlfix";\nrm /hostbin/cilium-sysctlfix\n"',
          in_init_tree: true,
        },
        { name: "/usr/bin/dash", arguments: "/init-container.sh", in_init_tree: true },
        { name: "/usr/bin/dash", arguments: "/usr/sbin/iptables-save", in_init_tree: false },
        {
          name: "/usr/bin/gawk",
          arguments:
            '-v bdi=259:4 "BEGIN{ret=1} {if ($4 == bdi) {ret=0}} END{exit ret}" /proc/fs/nfsfs/volumes',
        },
        {
          name: "/usr/bin/gawk",
          arguments:
            '-v bdi=259:5 "BEGIN{ret=1} {if ($4 == bdi) {ret=0}} END{exit ret}" /proc/fs/nfsfs/volumes',
        },
        {
          name: "/usr/bin/gawk",
          arguments:
            '-v bdi=259:6 "BEGIN{ret=1} {if ($4 == bdi) {ret=0}} END{exit ret}" /proc/fs/nfsfs/volumes',
        },
        {
          name: "/usr/bin/gawk",
          arguments:
            '-v bdi=259:7 "BEGIN{ret=1} {if ($4 == bdi) {ret=0}} END{exit ret}" /proc/fs/nfsfs/volumes',
        },
        { name: "/usr/bin/grep", arguments: ' "/sys/fs/bpf type bpf"', in_init_tree: true },
        { name: "/usr/bin/grep", arguments: ' "^md.*: active" /proc/mdstat' },
        {
          name: "/usr/bin/grep",
          arguments: "-E -c AWS-SNAT-CHAIN|AWS-CONNMARK-CHAIN",
          in_init_tree: false,
        },
        {
          name: "/usr/bin/grep",
          arguments: "-E ^:(KUBE-IPTABLES-HINT|KUBE-PROXY-CANARY)",
          in_init_tree: false,
        },
        { name: "/usr/bin/grep", arguments: "-Pzo .*Updates(.*\\n)*" },
        { name: "/usr/bin/grep", arguments: "-q kmod-nvidia" },
        { name: "/usr/bin/gzip" },
        { name: "/usr/bin/hostname", arguments: "--fqdn" },
        { name: "/usr/bin/id", arguments: "-u" },
        { name: "/usr/bin/kmod", arguments: "-q -- cls_bpf" },
        { name: "/usr/bin/kmod", arguments: "-q -- fs-ext4" },
        { name: "/usr/bin/kmod", arguments: "-q -- ipt_CONNMARK" },
        { name: "/usr/bin/kmod", arguments: "-q -- ipt_CT" },
        { name: "/usr/bin/kmod", arguments: "-q -- ipt_TPROXY" },
        { name: "/usr/bin/kmod", arguments: "-q -- ipt_set" },
        { name: "/usr/bin/kmod", arguments: "-q -- net-pf-16-proto-6" },
        { name: "/usr/bin/kmod", arguments: "-q -- nfnetlink-subsys-6" },
        { name: "/usr/bin/kmod", arguments: "-q -- rtnl-link-veth" },
        { name: "/usr/bin/kmod", arguments: "-q -- sch_clsact" },
        {
          name: "/usr/bin/kubelet",
          connections: [
            {
              destination: { dns: { destination_names: ["10.3.5.70"] }, port: "443" },
              stats: { tx_bytes: "3966762", rx_bytes: "14371506" },
            },
            {
              destination: { dns: { destination_names: ["127.0.0.1"] }, port: "9879" },
              stats: { tx_bytes: "7394514", rx_bytes: "13346804" },
            },
            {
              destination: { dns: { destination_names: ["127.0.0.1"] }, port: "43683" },
              stats: { tx_bytes: "43205", rx_bytes: "1173211" },
            },
            {
              destination: {
                dns: {
                  destination_names: [
                    "3BE81FD965B44E29EE37641B4D0F95CD.gr7.us-west-2.eks.amazonaws.com",
                  ],
                },
                port: "443",
              },
              stats: { tx_bytes: "56986136", rx_bytes: "196698666" },
            },
            {
              destination: {
                dns: { destination_names: ["ip-10-3-6-68.us-west-2.compute.internal"] },
                port: "6789",
              },
              stats: { tx_bytes: "5082", rx_bytes: "15309" },
            },
            {
              destination: {
                dns: { destination_names: ["ip-10-3-6-68.us-west-2.compute.internal"] },
                port: "9100",
              },
              stats: { tx_bytes: "16012", rx_bytes: "50767" },
            },
            {
              destination: {
                dns: { destination_names: ["ip-10-3-6-68.us-west-2.compute.internal"] },
                port: "30001",
              },
              stats: { tx_bytes: "7003325", rx_bytes: "20948658" },
            },
            {
              destination: {
                workload: {
                  name: "argo-cd-argocd-repo-server",
                  namespace: "argocd",
                  kind: "WORKLOAD_KIND_DEPLOYMENT",
                },
                port: "8084",
              },
              stats: { tx_bytes: "21548622", rx_bytes: "41684136" },
            },
            {
              destination: {
                workload: {
                  name: "hubble-timescape-lite",
                  namespace: "hubble-timescape",
                  kind: "WORKLOAD_KIND_STATEFULSET",
                },
                port: "8123",
              },
              stats: { tx_bytes: "93852530", rx_bytes: "208493836" },
            },
            {
              destination: {
                workload: {
                  name: "ebs-csi-node",
                  namespace: "kube-system",
                  kind: "WORKLOAD_KIND_DAEMONSET",
                },
                port: "9808",
              },
              stats: { tx_bytes: "14671052", rx_bytes: "32319851" },
            },
            {
              destination: {
                workload: {
                  name: "hubble-relay",
                  namespace: "kube-system",
                  kind: "WORKLOAD_KIND_DEPLOYMENT",
                },
                port: "4222",
              },
              stats: { tx_bytes: "40155415", rx_bytes: "65902479" },
            },
            {
              destination: {
                workload: {
                  name: "loki-compactor",
                  namespace: "logging",
                  kind: "WORKLOAD_KIND_DEPLOYMENT",
                },
                port: "3100",
              },
              stats: { tx_bytes: "21099304", rx_bytes: "43180258" },
            },
            {
              destination: {
                workload: {
                  name: "loki-querier",
                  namespace: "logging",
                  kind: "WORKLOAD_KIND_STATEFULSET",
                },
                port: "3100",
              },
              stats: { tx_bytes: "23100859", rx_bytes: "51491699" },
            },
            {
              destination: {
                workload: {
                  name: "promtail",
                  namespace: "logging",
                  kind: "WORKLOAD_KIND_DAEMONSET",
                },
                port: "3101",
              },
              stats: { tx_bytes: "10788820", rx_bytes: "20885913" },
            },
            {
              destination: {
                workload: {
                  name: "kube-prometheus-stack-prometheus-node-exporter",
                  namespace: "monitoring",
                  kind: "WORKLOAD_KIND_DAEMONSET",
                },
                port: "6789",
              },
              stats: { tx_bytes: "22640287", rx_bytes: "37390240" },
            },
            {
              destination: {
                workload: {
                  name: "kube-prometheus-stack-prometheus-node-exporter",
                  namespace: "monitoring",
                  kind: "WORKLOAD_KIND_DAEMONSET",
                },
                port: "9100",
              },
              stats: { tx_bytes: "19935168", rx_bytes: "90986382" },
            },
            {
              destination: {
                workload: {
                  name: "kube-prometheus-stack-prometheus-node-exporter",
                  namespace: "monitoring",
                  kind: "WORKLOAD_KIND_DAEMONSET",
                },
                port: "30001",
              },
              stats: { tx_bytes: "116783688", rx_bytes: "184270430" },
            },
            {
              destination: {
                workload: {
                  name: "otel-demo-opensearch",
                  namespace: "otel-demo",
                  kind: "WORKLOAD_KIND_STATEFULSET",
                },
                port: "9200",
              },
              stats: { tx_bytes: "10424882", rx_bytes: "16001323" },
            },
            {
              destination: {
                workload: {
                  name: "otel-demo-recommendationservice",
                  namespace: "otel-demo",
                  kind: "WORKLOAD_KIND_DEPLOYMENT",
                },
                port: "443",
              },
              stats: {},
            },
          ],
        },
        {
          name: "/usr/bin/ln",
          arguments: "-s /usr/sbin/xtables-nft-multi /usr/sbin/ip6tables",
          in_init_tree: false,
        },
        {
          name: "/usr/bin/ln",
          arguments: "-s /usr/sbin/xtables-nft-multi /usr/sbin/ip6tables-restore",
          in_init_tree: false,
        },
        {
          name: "/usr/bin/ln",
          arguments: "-s /usr/sbin/xtables-nft-multi /usr/sbin/iptables",
          in_init_tree: false,
        },
        {
          name: "/usr/bin/ln",
          arguments: "-s /usr/sbin/xtables-nft-multi /usr/sbin/iptables-save",
          in_init_tree: false,
        },
        { name: "/usr/bin/mktemp", arguments: "--tmpdir motd.partXXXXX" },
        { name: "/usr/bin/mktemp", arguments: "--tmpdir=/var/lib/update-motd/" },
        { name: "/usr/bin/mount", in_init_tree: true },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize -o bind /proc/2415/fd/29 /var/lib/kubelet/pods/10798e62-b971-4133-9cd9-cf3f76ce4236/volume-subpaths/config/configfile/1",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize -o bind /proc/2415/fd/31 /var/lib/kubelet/pods/10798e62-b971-4133-9cd9-cf3f76ce4236/volume-subpaths/config-emptydir/opensearch/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "--no-canonicalize -o bind,remount /proc/2415/fd/31 /var/lib/kubelet/pods/10798e62-b971-4133-9cd9-cf3f76ce4236/volume-subpaths/config-emptydir/opensearch/0",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t tmpfs -o size=12884901888 tmpfs /var/lib/kubelet/pods/5bcf3d04-2b53-4e75-b256-53a46a82d942/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t tmpfs -o size=12884901888 tmpfs /var/lib/kubelet/pods/5bcf3d04-2b53-4e75-b256-53a46a82d942/volumes/kubernetes.io~projected/kube-api-access-2f9p9",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t tmpfs -o size=134217728 tmpfs /var/lib/kubelet/pods/58cc5c60-f395-4830-a974-eec94c3fd15d/volumes/kubernetes.io~projected/aws-iam-token",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t tmpfs -o size=134217728 tmpfs /var/lib/kubelet/pods/58cc5c60-f395-4830-a974-eec94c3fd15d/volumes/kubernetes.io~projected/kube-api-access-qdsd7",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t tmpfs -o size=15418474496 tmpfs /var/lib/kubelet/pods/1ace5824-3cae-498d-81ae-9876c2de3db5/volumes/kubernetes.io~projected/kube-api-access-m5ws5",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t tmpfs -o size=15418474496 tmpfs /var/lib/kubelet/pods/29fb2fc2-8d28-4ec7-96ab-20245ee56f31/volumes/kubernetes.io~projected/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t tmpfs -o size=15418474496 tmpfs /var/lib/kubelet/pods/31d18d90-b0c3-47e7-9aa4-3fadd0d209a1/volumes/kubernetes.io~secret/cluster-ca-certs",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t tmpfs -o size=15418474496 tmpfs /var/lib/kubelet/pods/31d18d90-b0c3-47e7-9aa4-3fadd0d209a1/volumes/kubernetes.io~secret/zookeeper-nodes",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t tmpfs -o size=15418474496 tmpfs /var/lib/kubelet/pods/7e7e48e2-e786-48de-bddc-15732c5c16de/volumes/kubernetes.io~projected/kube-api-access-bmnml",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t tmpfs -o size=15418474496 tmpfs /var/lib/kubelet/pods/82c3afc0-7841-4c2a-b82d-c89d6c75072a/volumes/kubernetes.io~projected/kube-api-access-xszvq",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t tmpfs -o size=15418474496 tmpfs /var/lib/kubelet/pods/82c3afc0-7841-4c2a-b82d-c89d6c75072a/volumes/kubernetes.io~secret/argocd-repo-server-tls",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t tmpfs -o size=268435456 tmpfs /var/lib/kubelet/pods/4205dbd7-a882-48f5-bf39-cde367b329f2/volumes/kubernetes.io~projected/kube-api-access-9h5qd",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t tmpfs -o size=268435456 tmpfs /var/lib/kubelet/pods/4205dbd7-a882-48f5-bf39-cde367b329f2/volumes/kubernetes.io~secret/config",
        },
        {
          name: "/usr/bin/mount",
          arguments:
            "-t tmpfs -o size=5242880 tmpfs /var/lib/kubelet/pods/31d18d90-b0c3-47e7-9aa4-3fadd0d209a1/volumes/kubernetes.io~empty-dir/strimzi-tmp",
        },
        {
          name: "/usr/bin/mv",
          arguments: "/host/opt/cni/bin/.cilium-cni.new /host/opt/cni/bin/cilium-cni",
          in_init_tree: true,
        },
        {
          name: "/usr/bin/mv",
          arguments: "/host/opt/cni/bin/.loopback.new /host/opt/cni/bin/loopback",
          in_init_tree: true,
        },
        {
          name: "/usr/bin/mv",
          arguments: "/var/lib/update-motd/tmp.87vyRaN2Ax /var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments: "/var/lib/update-motd/tmp.Pd9ruT5n8i /var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments: "/var/lib/update-motd/tmp.ajQhVZFttH /var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments: "/var/lib/update-motd/tmp.fXu3rKDIG1 /var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/mv",
          arguments: "/var/lib/update-motd/tmp.nVNZ7uCJs4 /var/lib/update-motd/motd",
        },
        {
          name: "/usr/bin/nsenter",
          arguments:
            "--cgroup=/hostproc/1/ns/cgroup --mount=/hostproc/1/ns/mnt /opt/cni/bin/cilium-mount /run/cilium/cgroupv2",
          in_init_tree: true,
        },
        {
          name: "/usr/bin/nsenter",
          arguments: "--mount=/hostproc/1/ns/mnt /opt/cni/bin/cilium-sysctlfix",
          in_init_tree: true,
        },
        { name: "/usr/bin/ps", arguments: "-e -o pid,ppid,state,command" },
        {
          name: "/usr/bin/python3.9",
          arguments: "/usr/bin/dnf --debuglevel 2 updateinfo",
          connections: [
            {
              destination: {
                dns: {
                  destination_names: [
                    "al2023-repos-us-west-2-de612dc2.s3.dualstack.us-west-2.amazonaws.com",
                  ],
                },
                port: "443",
              },
              stats: { tx_bytes: "6810", rx_bytes: "43818" },
            },
          ],
        },
        { name: "/usr/bin/python3.9", arguments: "/usr/sbin/ebsnvme-id -u /dev/nvme1n1" },
        { name: "/usr/bin/python3.9", arguments: "/usr/sbin/ebsnvme-id -u /dev/nvme2n1" },
        { name: "/usr/bin/python3.9", arguments: "/usr/sbin/ebsnvme-id -u /dev/nvme3n1" },
        { name: "/usr/bin/python3.9", arguments: "/usr/sbin/ebsnvme-id -u /dev/nvme4n1" },
        { name: "/usr/bin/rm", arguments: "-f /tmp/motd.part8wxU0" },
        { name: "/usr/bin/rm", arguments: "-f /tmp/motd.partFZbp4" },
        { name: "/usr/bin/rm", arguments: "-f /tmp/motd.partG9jiP" },
        { name: "/usr/bin/rm", arguments: "-f /tmp/motd.partQzQLB" },
        { name: "/usr/bin/rm", arguments: "-f /tmp/motd.partWk0rE" },
        { name: "/usr/bin/rm", arguments: "-f /tmp/motd.partbyOmi" },
        { name: "/usr/bin/rm", arguments: "-f /tmp/motd.parte1PJV" },
        { name: "/usr/bin/rm", arguments: "-f /tmp/motd.partjwPLf" },
        { name: "/usr/bin/rm", arguments: "-f /tmp/motd.partozF3t" },
        { name: "/usr/bin/rm", arguments: "-f /tmp/motd.partpYGw1" },
        { name: "/usr/bin/rm", arguments: "-f /usr/sbin/ip6tables", in_init_tree: false },
        { name: "/usr/bin/rm", arguments: "-f /usr/sbin/ip6tables-restore", in_init_tree: false },
        { name: "/usr/bin/rm", arguments: "-f /usr/sbin/ip6tables-save", in_init_tree: false },
        { name: "/usr/bin/rm", arguments: "-f /usr/sbin/iptables", in_init_tree: false },
        { name: "/usr/bin/rm", arguments: "-f /usr/sbin/iptables-save", in_init_tree: false },
        { name: "/usr/bin/rm", arguments: "/hostbin/cilium-mount", in_init_tree: true },
        { name: "/usr/bin/rm", arguments: "/hostbin/cilium-sysctlfix", in_init_tree: true },
        { name: "/usr/bin/rpm", arguments: "-qa" },
        {
          name: "/usr/bin/ssm-agent-worker",
          connections: [
            {
              destination: { dns: { destination_names: ["169.254.169.254"] }, port: "80" },
              stats: { tx_bytes: "2797220", rx_bytes: "6322492" },
            },
            {
              destination: { dns: { destination_names: ["52.94.178.57"] }, port: "443" },
              stats: {},
            },
            {
              destination: {
                dns: { destination_names: ["ssm.us-west-2.amazonaws.com"] },
                port: "443",
              },
              stats: { tx_bytes: "4732696", rx_bytes: "13923299" },
            },
            {
              destination: {
                dns: { destination_names: ["ssmmessages.us-west-2.amazonaws.com"] },
                port: "443",
              },
              stats: { tx_bytes: "1174400", rx_bytes: "2229885" },
            },
          ],
        },
        { name: "/usr/bin/systemd-tmpfiles", arguments: "--clean" },
        {
          name: "/usr/bin/tetragon-oci-hook-setup",
          arguments:
            "install --interface=nri-hook --local-install-dir=/hostInstall --host-install-dir=/opt/tetragon --oci-hooks.local-dir=/hostHooks --daemonize hook-args --grpc-address=localhost:54321 --fail-allow-namespaces tetragon",
          in_init_tree: true,
        },
        { name: "/usr/bin/timeout", arguments: "30s /etc/update-motd.d/10-nvidia-eula" },
        { name: "/usr/bin/timeout", arguments: "30s /etc/update-motd.d/70-available-updates" },
        { name: "/usr/bin/timeout", arguments: "30s /usr/bin/dnf --debuglevel 2 updateinfo" },
        { name: "/usr/bin/uname", arguments: "-rs" },
        { name: "/usr/bin/unpigz", arguments: "-d -c" },
        { name: "/usr/bin/wc", arguments: "-l", in_init_tree: false },
        { name: "/usr/lib/systemd/systemd-sysctl" },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/cilium --prefix=/net/ipv4/neigh/cilium --prefix=/net/ipv6/conf/cilium --prefix=/net/ipv6/neigh/cilium",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/cilium_host --prefix=/net/ipv4/neigh/cilium_host --prefix=/net/ipv6/conf/cilium_host --prefix=/net/ipv6/neigh/cilium_host",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/cilium_net --prefix=/net/ipv4/neigh/cilium_net --prefix=/net/ipv6/conf/cilium_net --prefix=/net/ipv6/neigh/cilium_net",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc280db0b0748a --prefix=/net/ipv4/neigh/lxc280db0b0748a --prefix=/net/ipv6/conf/lxc280db0b0748a --prefix=/net/ipv6/neigh/lxc280db0b0748a",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc6787102febf7 --prefix=/net/ipv4/neigh/lxc6787102febf7 --prefix=/net/ipv6/conf/lxc6787102febf7 --prefix=/net/ipv6/neigh/lxc6787102febf7",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc9b51b1fe4b3a --prefix=/net/ipv4/neigh/lxc9b51b1fe4b3a --prefix=/net/ipv6/conf/lxc9b51b1fe4b3a --prefix=/net/ipv6/neigh/lxc9b51b1fe4b3a",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxc_health --prefix=/net/ipv4/neigh/lxc_health --prefix=/net/ipv6/conf/lxc_health --prefix=/net/ipv6/neigh/lxc_health",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcaff1edc70588 --prefix=/net/ipv4/neigh/lxcaff1edc70588 --prefix=/net/ipv6/conf/lxcaff1edc70588 --prefix=/net/ipv6/neigh/lxcaff1edc70588",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcd75ed705f841 --prefix=/net/ipv4/neigh/lxcd75ed705f841 --prefix=/net/ipv6/conf/lxcd75ed705f841 --prefix=/net/ipv6/neigh/lxcd75ed705f841",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/lxcf88a45990832 --prefix=/net/ipv4/neigh/lxcf88a45990832 --prefix=/net/ipv6/conf/lxcf88a45990832 --prefix=/net/ipv6/neigh/lxcf88a45990832",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp32b60 --prefix=/net/ipv4/neigh/tmp32b60 --prefix=/net/ipv6/conf/tmp32b60 --prefix=/net/ipv6/neigh/tmp32b60",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp36367 --prefix=/net/ipv4/neigh/tmp36367 --prefix=/net/ipv6/conf/tmp36367 --prefix=/net/ipv6/neigh/tmp36367",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp537d3 --prefix=/net/ipv4/neigh/tmp537d3 --prefix=/net/ipv6/conf/tmp537d3 --prefix=/net/ipv6/neigh/tmp537d3",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmp842eb --prefix=/net/ipv4/neigh/tmp842eb --prefix=/net/ipv6/conf/tmp842eb --prefix=/net/ipv6/neigh/tmp842eb",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpa4517 --prefix=/net/ipv4/neigh/tmpa4517 --prefix=/net/ipv6/conf/tmpa4517 --prefix=/net/ipv6/neigh/tmpa4517",
        },
        {
          name: "/usr/lib/systemd/systemd-sysctl",
          arguments:
            "--prefix=/net/ipv4/conf/tmpc20fe --prefix=/net/ipv4/neigh/tmpc20fe --prefix=/net/ipv6/conf/tmpc20fe --prefix=/net/ipv6/neigh/tmpc20fe",
        },
        { name: "/usr/lib/udev/rename_device" },
        {
          name: "/usr/local/aws-cli/v2/2.24.25/dist/aws",
          arguments: "eks get-token --cluster-name df-tetragon-dev-ce-01 --region us-west-2",
          connections: [
            {
              destination: { dns: { destination_names: ["169.254.169.254"] }, port: "80" },
              stats: { tx_bytes: "452119", rx_bytes: "1426396" },
            },
          ],
        },
        {
          name: "/usr/sbin/fstrim",
          arguments: "--listed-in /etc/fstab:/proc/self/mountinfo --verbose --quiet-unsupported",
        },
        { name: "/usr/sbin/logrotate", arguments: "/etc/logrotate.conf" },
        { name: "/usr/sbin/runc", arguments: "-" },
        { name: "/usr/sbin/runc", arguments: "--" },
        { name: "/usr/sbin/runc", arguments: "--r" },
        { name: "/usr/sbin/runc", arguments: "--ro" },
        { name: "/usr/sbin/runc", arguments: "--roo" },
        { name: "/usr/sbin/runc", arguments: "--root" },
        { name: "/usr/sbin/runc", arguments: "--root /ru" },
        { name: "/usr/sbin/runc", arguments: "--root /run/contai" },
        { name: "/usr/sbin/runc", arguments: "--root /run/contain" },
        { name: "/usr/sbin/runc", arguments: "--root /run/containe" },
        { name: "/usr/sbin/runc", arguments: "--root /run/containerd/ru" },
        { name: "/usr/sbin/runc", arguments: "--root /run/containerd/runc/" },
        { name: "/usr/sbin/sshd" },
        { name: "/usr/sbin/xtables-nft-multi", in_init_tree: false },
        { name: "/usr/sbin/xtables-nft-multi", arguments: "-t mangle", in_init_tree: false },
        { name: "/usr/sbin/xtables-nft-multi", arguments: "-t nat" },
        { name: "/usr/sbin/xtables-nft-multi", arguments: "-w 5 -W 100000 --noflush --counters" },
        {
          name: "/usr/sbin/xtables-nft-multi",
          arguments: "-w 5 -W 100000 -S KUBE-KUBELET-CANARY -t mangle",
        },
      ],
    },
  },
};
