import type { ApplicationConnection, ApplicationModelEvent, ApplicationProcess } from "~/proto";
import type {
  ConnectionsMap,
  EndpointsMap,
  ProcessesMap,
  TreeHostProcPath,
  TreeWorkloadProcPath,
} from "~/types";
import { inferEndpointKind } from "~/utils/endpoints";
import { isSuspiciousProc } from "~/utils/procs";

export type Stat = {
  totalBytesSent: number;
  totalBytesReceived: number;
  hasSuspiciousProcs: boolean;
};

export type EndpointStat = Stat;

export type TreeEntryStat = Stat & {
  endpointsMap: Map<string, EndpointStat>;
  hasSuspiciousProcs: boolean;
};

export type Stats = ReturnType<typeof createEmptyStat>;

export function getEndpointHash(conn: ApplicationConnection) {
  return `${conn.destinationName}:${conn.destinationPort}`;
}

export function getWorkloadHash(namespace: string, workload: string) {
  return `${namespace}/${workload}`;
}

export function getProcHash(proc: ApplicationProcess) {
  return `${proc.name}:[${proc.arguments}]`;
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

  const rec = (
    recProcPath: TreeHostProcPath | TreeWorkloadProcPath,
    recProcs?: ApplicationProcess[],
  ) => {
    let recTotalBytesSent = 0;
    let recTotalBytesReceived = 0;
    let recHasSuspiciousProcs = false;
    const recEndpointsMap = new Map<string, EndpointStat>();

    recProcs?.forEach((proc) => {
      const procHash = getProcHash(proc);
      const procPath: TreeHostProcPath | TreeWorkloadProcPath = {
        ...recProcPath,
        path: [...recProcPath.path, procHash],
      };
      processesMap.set(proc, { path: procPath });

      let procTotalBytesSent = 0;
      let procTotalBytesReceived = 0;
      const procHasSuspiciousProcs = isSuspiciousProc(proc);

      recHasSuspiciousProcs ||= procHasSuspiciousProcs;

      const procEndpointsMap = new Map<string, EndpointStat>();

      proc.connections?.forEach((conn) => {
        const connBytesSent = Number(conn.bytesSent || 0);
        const connBytesReceived = Number(conn.bytesReceived || 0);

        const endpoint = getEndpointHash(conn);
        procEndpointsMap.set(endpoint, {
          totalBytesSent: connBytesSent,
          totalBytesReceived: connBytesReceived,
          hasSuspiciousProcs: procHasSuspiciousProcs,
        });

        procTotalBytesSent += connBytesSent;
        procTotalBytesReceived += connBytesReceived;

        mergeEndpointStat(stat.endpointsMap, endpoint, {
          totalBytesSent: connBytesSent,
          totalBytesReceived: connBytesReceived,
          hasSuspiciousProcs: procHasSuspiciousProcs,
        });
      });

      stat.processesMap.set(proc, {
        totalBytesSent: procTotalBytesSent,
        totalBytesReceived: procTotalBytesReceived,
        hasSuspiciousProcs: procHasSuspiciousProcs,
        endpointsMap: procEndpointsMap,
      });

      recTotalBytesSent += procTotalBytesSent;
      recTotalBytesReceived += procTotalBytesReceived;

      procEndpointsMap.forEach((procEndpointStat, procEndpoint) => {
        mergeEndpointStat(recEndpointsMap, procEndpoint, procEndpointStat);

        const endpointKind = inferEndpointKind(procEndpoint);
        endpointsMap.set(procEndpoint, { kind: endpointKind });

        const endpointConnections = connectionsMap.get(procEndpoint) ?? new Set();

        endpointConnections.add(proc);
        connectionsMap.set(procEndpoint, endpointConnections);
      });

      const subResult = rec(procPath, proc.children);
      recTotalBytesSent += subResult.totalBytesSent;
      recTotalBytesReceived += subResult.totalBytesReceived;
      recHasSuspiciousProcs ||= subResult.hasSuspiciousProcs;

      mergeEndpointStatMaps(subResult.endpointsMap, recEndpointsMap);
    });

    return {
      totalBytesSent: recTotalBytesSent,
      totalBytesReceived: recTotalBytesReceived,
      hasSuspiciousProcs: recHasSuspiciousProcs,
      endpointsMap: recEndpointsMap,
    };
  };

  const hostResult = rec({ path: [] }, model.applicationModel?.host?.processes ?? []);

  let namespacesTotalBytesSent = 0;
  let namespacesTotalBytesReceived = 0;
  let namespacesHasSuspiciousProcs = false;
  const namespacesEndpointsMap = new Map<string, EndpointStat>();

  model.applicationModel?.namespaces?.forEach((namespace) => {
    if (!namespace.name) return;

    let namespaceTotalBytesSent = 0;
    let namespaceTotalBytesReceived = 0;
    const namespaceEndpointsMap = new Map<string, EndpointStat>();
    let namespaceHasSuspiciousProc = false;

    namespace.workloads?.forEach((workload) => {
      if (!workload.name) return;

      const workloadResult = rec(
        { namespace: namespace.name, workload: workload.name, path: [] },
        workload.processes,
      );

      stat.workloadsMap.set(getWorkloadHash(namespace.name, workload.name), {
        totalBytesSent: workloadResult.totalBytesSent,
        totalBytesReceived: workloadResult.totalBytesReceived,
        hasSuspiciousProcs: workloadResult.hasSuspiciousProcs,
        endpointsMap: workloadResult.endpointsMap,
      });

      namespaceTotalBytesSent += workloadResult.totalBytesSent;
      namespaceTotalBytesReceived += workloadResult.totalBytesReceived;
      namespaceHasSuspiciousProc ||= workloadResult.hasSuspiciousProcs;

      [namespaceEndpointsMap, namespacesEndpointsMap].forEach((endpointsMap) => {
        mergeEndpointStatMaps(workloadResult.endpointsMap, endpointsMap);
      });
    });

    namespacesTotalBytesSent += namespaceTotalBytesSent;
    namespacesTotalBytesReceived += namespaceTotalBytesReceived;
    namespacesHasSuspiciousProcs ||= namespaceHasSuspiciousProc;

    stat.namespacesMap.set(namespace.name, {
      totalBytesSent: namespaceTotalBytesSent,
      totalBytesReceived: namespaceTotalBytesReceived,
      hasSuspiciousProcs: namespaceHasSuspiciousProc,
      endpointsMap: namespaceEndpointsMap,
    });
  });

  stat.host.totalBytesSent = hostResult.totalBytesSent;
  stat.host.totalBytesReceived = hostResult.totalBytesSent;
  stat.host.endpointsMap = hostResult.endpointsMap;
  stat.host.hasSuspiciousProcs = hostResult.hasSuspiciousProcs;

  stat.namespaces.totalBytesSent = namespacesTotalBytesSent;
  stat.namespaces.totalBytesReceived = namespacesTotalBytesReceived;
  stat.namespaces.endpointsMap = namespacesEndpointsMap;
  stat.namespaces.hasSuspiciousProcs = namespacesHasSuspiciousProcs;

  stat.node.totalBytesSent = stat.host.totalBytesSent + stat.namespaces.totalBytesSent;
  stat.node.totalBytesReceived = stat.host.totalBytesReceived + stat.namespaces.totalBytesReceived;
  stat.node.endpointsMap = new Map();
  [stat.host.endpointsMap, stat.namespaces.endpointsMap].forEach((endpointsMap) => {
    mergeEndpointStatMaps(endpointsMap, stat.node.endpointsMap);
  });
  stat.node.hasSuspiciousProcs = stat.host.hasSuspiciousProcs || stat.namespaces.hasSuspiciousProcs;

  return {
    processesMap,
    endpointsMap,
    connectionsMap,
    stat,
  };
}

export function createEmptyStat() {
  return {
    node: {
      totalBytesSent: 0,
      totalBytesReceived: 0,
      endpointsMap: new Map(),
      hasSuspiciousProcs: false,
    } as TreeEntryStat,
    host: {
      totalBytesSent: 0,
      totalBytesReceived: 0,
      endpointsMap: new Map(),
      hasSuspiciousProcs: false,
    } as TreeEntryStat,
    namespaces: {
      totalBytesSent: 0,
      totalBytesReceived: 0,
      endpointsMap: new Map(),
      hasSuspiciousProcs: false,
    } as TreeEntryStat,
    namespacesMap: new Map<string, TreeEntryStat>(),
    workloadsMap: new Map<string, TreeEntryStat>(),
    processesMap: new WeakMap<ApplicationProcess, TreeEntryStat>(),
    endpointsMap: new Map<string, EndpointStat>(),
  };
}

function mergeEndpointStat(
  endpointsMap: Map<string, EndpointStat>,
  endpoint: string,
  endpointStat: EndpointStat,
) {
  const namespaceEndpointStat: EndpointStat = endpointsMap.get(endpoint) ?? {
    totalBytesSent: 0,
    totalBytesReceived: 0,
    hasSuspiciousProcs: false,
  };
  namespaceEndpointStat.totalBytesSent += endpointStat.totalBytesSent;
  namespaceEndpointStat.totalBytesReceived += endpointStat.totalBytesReceived;
  namespaceEndpointStat.hasSuspiciousProcs ||= endpointStat.hasSuspiciousProcs;
  endpointsMap.set(endpoint, namespaceEndpointStat);
}

function mergeEndpointStatMaps(
  withEndpointsMap: Map<string, EndpointStat>,
  targetEndpointsMap: Map<string, EndpointStat>,
) {
  withEndpointsMap.forEach((endpointStat, endpoint) => {
    mergeEndpointStat(targetEndpointsMap, endpoint, endpointStat);
  });
}
