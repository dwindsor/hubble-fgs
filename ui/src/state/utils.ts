import { Connection, EndpointsMap, ProcessesMap } from "~/types";
import {
  ApplicationConnection,
  ApplicationModelEvent,
  ApplicationProcess,
} from "~/proto/appmodel";

export type Stat = { bytesSent: number };
export type Stats = ReturnType<typeof createEmptyStat>;

export function getEndpointHash(conn: ApplicationConnection) {
  return `${conn.destinationName}:${conn.destinationPort}`;
}

export function createAppState(model?: ApplicationModelEvent): {
  processesMap: ProcessesMap;
  endpointsMap: EndpointsMap;
  connections: Connection[];
  stats: Stats;
} {
  const processesMap: ProcessesMap = new WeakMap();
  const endpointsMap: EndpointsMap = new Map();
  const connections: Connection[] = [];
  const stats = createEmptyStat();

  if (!model) {
    return { processesMap, endpointsMap, connections, stats };
  }

  const rec = (processes?: ApplicationProcess[]) => {
    let bytesSent = 0;
    processes?.forEach((proc) => {
      let procBytesSent = 0;
      const endpoints = new Set<string>();
      proc.connections?.forEach((conn) => {
        endpoints.add(getEndpointHash(conn));
        procBytesSent += conn.bytesSent;
      });
      bytesSent += procBytesSent;
      endpoints.forEach((endpoint) => {
        endpointsMap.set(endpoint, {});
        connections.push({ proc, endpoint });
      });
      processesMap.set(proc, { endpoints: Array.from(endpoints) });
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
  model.applicationModel?.namespaces.forEach((namespace) => {
    let namespaceBytesSent = 0;
    namespace.workloads.forEach((workload) => {
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

  return { processesMap, endpointsMap, connections, stats };
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
