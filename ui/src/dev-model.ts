import { ApplicationModelEvent } from "./proto/appmodel";

const rnd = (min: number, max: number) => {
  return Math.floor(Math.random() * (max - min + 1)) + min;
};

export const model: ApplicationModelEvent = {
  clusterName: "production",
  nodeName: "node-a",
  time: new Date(),
  applicationModel: {
    host: {
      processes: [
        {
          name: "host-proc-1",
          arguments: "a",
          hash: "host-proc-1/a",
          connections: [],
          children: [
            {
              name: "host-proc-2",
              arguments: "b",
              hash: "host-proc-2/b",
              connections: [
                {
                  destinationName: "https://cisco.com",
                  destinationPort: 443,
                  bytesSent: rnd(1, 100500),
                  bytesReceived: 0,
                },
                {
                  destinationName: "https://cilium.io",
                  destinationPort: 443,
                  bytesSent: rnd(1, 100500),
                  bytesReceived: 0,
                },
                {
                  destinationName: "http://cilium.io",
                  destinationPort: 80,
                  bytesSent: rnd(1, 100500),
                  bytesReceived: 0,
                },
                {
                  destinationName: "http://cilium.io",
                  destinationPort: 8080,
                  bytesSent: rnd(1, 100500),
                  bytesReceived: 0,
                },
              ],
              children: [],
            },
          ],
        },
        {
          name: "host-proc-3",
          arguments: "c",
          hash: "host-proc-3/c",
          connections: [
            {
              destinationName: "https://api.github.com",
              destinationPort: 443,
              bytesSent: rnd(1, 100500),
              bytesReceived: 0,
            },
          ],
          children: [],
        },
      ],
    },
    namespaces: [
      {
        name: "kube-system",
        workloads: [
          {
            kind: "deployment",
            name: "kube-dns",
            processes: [
              {
                name: "kube-dns-proc-1",
                arguments: "a",
                hash: "kube-dns-proc-1/a",
                connections: [],
                children: [
                  {
                    name: "kube-dns-proc-2",
                    arguments: "a",
                    hash: "kube-dns-proc-2/a",
                    connections: [
                      {
                        destinationName: "http://api.dns.com",
                        destinationPort: 8080,
                        bytesSent: rnd(1, 100500),
                        bytesReceived: 0,
                      },
                    ],
                    children: [],
                  },
                  {
                    name: "kube-dns-proc-3",
                    arguments: "a",
                    hash: "kube-dns-proc-3/a",
                    connections: [],
                    children: [],
                  },
                ],
              },
              {
                name: "kube-dns-proc-4",
                arguments: "a",
                hash: "kube-dns-proc-4/a",
                connections: [],
                children: [],
              },
            ],
          },
          {
            kind: "deployment",
            name: "collector",
            processes: [
              {
                name: "collector-proc-1",
                arguments: "y",
                hash: "collector-proc-1/y",
                connections: [],
                children: [
                  {
                    name: "collector-proc-2",
                    arguments: "y",
                    hash: "collector-proc-2/y",
                    connections: [],
                    children: [],
                  },
                  {
                    name: "collector-proc-3",
                    arguments: "y",
                    hash: "collector-proc-3/y",
                    connections: [],
                    children: [],
                  },
                ],
              },
              {
                name: "collector-proc-4",
                arguments: "y",
                hash: "collector-proc-4/y",
                connections: [],
                children: [],
              },
            ],
          },
        ],
      },
      {
        name: "timescape",
        workloads: [
          {
            kind: "deployment",
            name: "timescape-server",
            processes: [
              {
                name: "timescape-server-proc-1",
                arguments: "a",
                hash: "timescape-server-proc-1/a",
                connections: [],
                children: [
                  {
                    name: "timescape-server-proc-2",
                    arguments: "a",
                    hash: "timescape-server-proc-2/a",
                    connections: [],
                    children: [],
                  },
                  {
                    name: "timescape-server-proc-3",
                    arguments: "a",
                    hash: "timescape-server-proc-3/a",
                    connections: [],
                    children: [],
                  },
                ],
              },
              {
                name: "timescape-server-proc-4",
                arguments: "a",
                hash: "timescape-server-proc-4/a",
                connections: [],
                children: [],
              },
            ],
          },
          {
            kind: "deployment",
            name: "timescape-ui",
            processes: [
              {
                name: "timescape-ui-proc-1",
                arguments: "y",
                hash: "timescape-ui-proc-1/y",
                connections: [],
                children: [
                  {
                    name: "timescape-ui-proc-2",
                    arguments: "y",
                    hash: "timescape-ui-proc-2/y",
                    connections: [],
                    children: [],
                  },
                  {
                    name: "timescape-ui-proc-3",
                    arguments: "y",
                    hash: "timescape-ui-proc-3/y",
                    connections: [
                      {
                        destinationName: "https://api.github.com",
                        destinationPort: 443,
                        bytesSent: rnd(1, 100500),
                        bytesReceived: 0,
                      },
                    ],
                    children: [],
                  },
                ],
              },
              {
                name: "timescape-ui-proc-4",
                arguments: "y",
                hash: "timescape-ui-proc-4/y",
                connections: [],
                children: [],
              },
            ],
          },
        ],
      },
    ],
  },
};
