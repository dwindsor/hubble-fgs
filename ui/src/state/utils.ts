import {
  ApplicationConnection,
  ApplicationModelEvent,
  ApplicationProcess,
} from "~/proto";
import { ConnectionsMap, EndpointsMap, ProcessesMap } from "~/types";
import { inferEndpointKind } from "~/utils/endpoints";

export type Stat = { totalBytesSent: number; totalBytesReceived: number };
export type TreeEntryStat = Stat & { endpointsMap: Map<string, Stat> };
export type Stats = ReturnType<typeof createEmptyStat>;

export function getEndpointHash(conn: ApplicationConnection) {
  return `${conn.destinationName}:${conn.destinationPort}`;
}

export type AppState = ReturnType<typeof createAppState>;

export function createAppState(model?: ApplicationModelEvent): {
  processesMap: ProcessesMap;
  endpointsMap: EndpointsMap;
  connectionsMap: ConnectionsMap;
  stat: Stats;
} {
  const processesMap: ProcessesMap = new WeakMap();
  const endpointsMap: EndpointsMap = new Map();
  const connectionsMap: ConnectionsMap = new Map();
  const stat = createEmptyStat();

  if (!model) {
    return {
      processesMap,
      endpointsMap,
      connectionsMap,
      stat,
    };
  }

  const rec = (processes?: ApplicationProcess[]) => {
    let totalBytesSent = 0;
    let totalBytesReceived = 0;
    const subEndpointsMap = new Map<string, Stat>();

    processes?.forEach((proc) => {
      let procTotalBytesSent = 0;
      let procTotalBytesReceived = 0;

      const procEndpointsMap = new Map<string, Stat>();

      proc.connections?.forEach((conn) => {
        const connBytesSent = Number(conn.bytesSent || 0);
        const connBytesReceived = Number(conn.bytesReceived || 0);

        const endpoint = getEndpointHash(conn);
        procEndpointsMap.set(endpoint, {
          totalBytesSent: connBytesSent,
          totalBytesReceived: connBytesReceived,
        });

        procTotalBytesSent += connBytesSent;
        procTotalBytesReceived += connBytesReceived;

        const endpointStat: Stat = stat.endpointsMap.get(endpoint) ?? {
          totalBytesSent: 0,
          totalBytesReceived: 0,
        };
        stat.endpointsMap.set(endpoint, {
          totalBytesSent: endpointStat.totalBytesSent + connBytesSent,
          totalBytesReceived:
            endpointStat.totalBytesReceived + connBytesReceived,
        });
      });

      totalBytesSent += procTotalBytesSent;
      totalBytesReceived += procTotalBytesReceived;

      procEndpointsMap.forEach((procEndpointStat, procEndpoint) => {
        const subEndpointStat = subEndpointsMap.get(procEndpoint) ?? {
          totalBytesSent: 0,
          totalBytesReceived: 0,
        };
        subEndpointStat.totalBytesSent += procEndpointStat.totalBytesSent;
        subEndpointStat.totalBytesReceived +=
          procEndpointStat.totalBytesReceived;
        subEndpointsMap.set(procEndpoint, subEndpointStat);

        const endpointKind = inferEndpointKind(procEndpoint);
        endpointsMap.set(procEndpoint, { kind: endpointKind });

        const endpointConnections =
          connectionsMap.get(procEndpoint) ?? new Set();

        endpointConnections.add(proc);
        connectionsMap.set(procEndpoint, endpointConnections);
      });

      processesMap.set(proc, {});

      const subResult = rec(proc.children);

      stat.processesMap.set(proc, {
        totalBytesSent: procTotalBytesSent,
        totalBytesReceived: procTotalBytesReceived,
        endpointsMap: procEndpointsMap,
      });

      totalBytesSent += subResult.totalBytesSent;
      totalBytesReceived += subResult.totalBytesReceived;

      subResult.endpointsMap.forEach((endpointStat, endpoint) => {
        const subEndpointStat = subEndpointsMap.get(endpoint) ?? {
          totalBytesSent: 0,
          totalBytesReceived: 0,
        };
        subEndpointStat.totalBytesSent += endpointStat.totalBytesSent;
        subEndpointStat.totalBytesReceived += endpointStat.totalBytesReceived;
        subEndpointsMap.set(endpoint, subEndpointStat);
      });
    });

    return {
      totalBytesSent,
      totalBytesReceived,
      endpointsMap: subEndpointsMap,
    };
  };

  const hostResult = rec(model.applicationModel?.host?.processes ?? []);

  let namespacesTotalBytesSent = 0;
  let namespacesTotalBytesReceived = 0;
  const namespacesEndpointsMap = new Map<string, Stat>();

  model.applicationModel?.namespaces?.forEach((namespace) => {
    if (!namespace.name) return;

    let namespaceTotalBytesSent = 0;
    let namespaceTotalBytesReceived = 0;
    const namespaceEndpointsMap = new Map<string, Stat>();

    namespace.workloads?.forEach((workload) => {
      if (!workload.name) return;
      const workloadResult = rec(workload.processes);
      stat.workloadsMap.set(namespace.name + "/" + workload.name, {
        totalBytesSent: workloadResult.totalBytesSent,
        totalBytesReceived: workloadResult.totalBytesReceived,
        endpointsMap: workloadResult.endpointsMap,
      });
      namespaceTotalBytesSent += workloadResult.totalBytesSent;
      namespaceTotalBytesReceived += workloadResult.totalBytesReceived;
      workloadResult.endpointsMap.forEach((endpointStat, endpoint) => {
        const namespaceEndpointStat = namespaceEndpointsMap.get(endpoint) ?? {
          totalBytesSent: 0,
          totalBytesReceived: 0,
        };
        namespaceEndpointStat.totalBytesSent += endpointStat.totalBytesSent;
        namespaceEndpointStat.totalBytesReceived +=
          endpointStat.totalBytesReceived;
        namespaceEndpointsMap.set(endpoint, namespaceEndpointStat);

        const namespacesEndpointStat = namespacesEndpointsMap.get(endpoint) ?? {
          totalBytesSent: 0,
          totalBytesReceived: 0,
        };
        namespacesEndpointStat.totalBytesSent += endpointStat.totalBytesSent;
        namespacesEndpointStat.totalBytesReceived +=
          endpointStat.totalBytesReceived;
        namespacesEndpointsMap.set(endpoint, namespacesEndpointStat);
      });
    });
    namespacesTotalBytesSent += namespaceTotalBytesSent;
    namespacesTotalBytesReceived += namespaceTotalBytesReceived;

    stat.namespacesMap.set(namespace.name, {
      totalBytesSent: namespaceTotalBytesSent,
      totalBytesReceived: namespaceTotalBytesReceived,
      endpointsMap: namespaceEndpointsMap,
    });
  });

  stat.node.totalBytesSent =
    hostResult.totalBytesSent + namespacesTotalBytesSent;
  stat.node.totalBytesReceived =
    hostResult.totalBytesReceived + namespacesTotalBytesReceived;

  stat.host.totalBytesSent = hostResult.totalBytesSent;
  stat.host.totalBytesReceived = hostResult.totalBytesSent;
  stat.host.endpointsMap = hostResult.endpointsMap;

  stat.namespaces.totalBytesSent = namespacesTotalBytesSent;
  stat.namespaces.totalBytesReceived = namespacesTotalBytesReceived;
  stat.namespaces.endpointsMap = namespacesEndpointsMap;

  return {
    processesMap,
    endpointsMap,
    connectionsMap,
    stat,
  };
}

export function createEmptyStat() {
  return {
    node: { totalBytesSent: 0, totalBytesReceived: 0 },
    host: {
      totalBytesSent: 0,
      totalBytesReceived: 0,
      endpointsMap: new Map(),
    } satisfies TreeEntryStat,
    namespaces: {
      totalBytesSent: 0,
      totalBytesReceived: 0,
      endpointsMap: new Map(),
    } satisfies TreeEntryStat,
    namespacesMap: new Map<string, TreeEntryStat>(),
    workloadsMap: new Map<string, TreeEntryStat>(),
    processesMap: new WeakMap<ApplicationProcess, TreeEntryStat>(),
    endpointsMap: new Map<string, Stat>(),
  };
}
