import { ConnectionsMap, EndpointsMap, ProcessesMap } from "~/types";
import {
  ApplicationConnection,
  ApplicationModelEvent,
  ApplicationProcess,
} from "~/proto";
import { inferEndpointKind } from "~/utils/endpoints";

export type Stat = { bytesSent: number };
export type Stats = ReturnType<typeof createEmptyStat>;

export function getEndpointHash(conn: ApplicationConnection) {
  return `${conn.destinationName}:${conn.destinationPort}`;
}

export type AppState = ReturnType<typeof createAppState>;

export function createAppState(model?: ApplicationModelEvent): {
  processesMap: ProcessesMap;
  endpointsMap: EndpointsMap;
  connectionsMap: ConnectionsMap;
  stats: Stats;
} {
  const processesMap: ProcessesMap = new WeakMap();
  const endpointsMap: EndpointsMap = new Map();
  const connectionsMap: ConnectionsMap = new Map();
  const stats = createEmptyStat();

  if (!model) {
    return {
      processesMap,
      endpointsMap,
      connectionsMap,
      stats,
    };
  }

  const rec = (processes?: ApplicationProcess[]) => {
    let bytesSent = 0;
    processes?.forEach((proc) => {
      let procBytesSent = 0;
      const endpoints = new Set<string>();
      proc.connections?.forEach((conn) => {
        endpoints.add(getEndpointHash(conn));
        procBytesSent += (conn.bytesSent || 0) as number;
      });
      bytesSent += procBytesSent;
      endpoints.forEach((endpoint) => {
        endpointsMap.set(endpoint, { kind: inferEndpointKind(endpoint) });

        const connectionEntry = connectionsMap.get(endpoint) ?? new Set();
        connectionEntry.add(proc);
        connectionsMap.set(endpoint, connectionEntry);
      });
      processesMap.set(proc, { endpoints });
      const subProcsBytesSent = rec(proc.children);
      stats.processesMap.set(proc, {
        bytesSent: procBytesSent,
        subProcsBytesSent: subProcsBytesSent,
      });
      bytesSent += subProcsBytesSent;
    });
    return bytesSent;
  };

  const hostBytesSent = rec(model.applicationModel?.host?.processes ?? []);

  let namespacesBytesSent = 0;
  model.applicationModel?.namespaces?.forEach((namespace) => {
    if (!namespace.name) return;
    let namespaceBytesSent = 0;
    namespace.workloads?.forEach((workload) => {
      if (!workload.name) return;
      const workloadBytesSent = rec(workload.processes);
      stats.workloadsMap[workload.name] = {
        bytesSent: workloadBytesSent,
      };
      namespaceBytesSent += workloadBytesSent;
    });
    namespacesBytesSent += namespaceBytesSent;
    stats.namespacesMap[namespace.name] = {
      bytesSent: namespaceBytesSent,
    };
  });

  stats.host.bytesSent = hostBytesSent;
  stats.namespaces.bytesSent = namespacesBytesSent;
  stats.node.bytesSent = hostBytesSent + namespacesBytesSent;
  stats.cluster.bytesSent = stats.node.bytesSent;

  return { processesMap, endpointsMap, connectionsMap: connectionsMap, stats };
}

export function createEmptyStat() {
  return {
    cluster: { bytesSent: 0 },
    node: { bytesSent: 0 },
    host: { bytesSent: 0 },
    namespaces: { bytesSent: 0 },
    namespacesMap: {} as { [key: string]: Stat },
    workloadsMap: {} as { [key: string]: Stat },
    processesMap: new WeakMap<
      ApplicationProcess,
      Stat & { subProcsBytesSent: number }
    >(),
  };
}
