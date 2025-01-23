import { ApplicationConnection, ApplicationModelEvent, ApplicationProcess } from '~/proto';
import { ConnectionsMap, EndpointsMap, ProcessesMap } from '~/types';
import { inferEndpointKind } from '~/utils/endpoints';

export type Stat = {
  totalBytesSent: number;
  totalBytesReceived: number;
  hasSuspiciousEvents: boolean;
};

export type EndpointStat = Stat;

export type TreeEntryStat = Stat & {
  endpointsMap: Map<string, EndpointStat>;
  hasSuspiciousEvents: boolean;
};
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
    let recTotalBytesSent = 0;
    let recTotalBytesReceived = 0;
    let recHasSuspiciousEvents = false;
    const recEndpointsMap = new Map<string, EndpointStat>();

    processes?.forEach((proc) => {
      processesMap.set(proc, {});

      let procTotalBytesSent = 0;
      let procTotalBytesReceived = 0;
      let procHasSuspiciousEvents = !!proc.inInitTree;

      recHasSuspiciousEvents ||= procHasSuspiciousEvents;

      const procEndpointsMap = new Map<string, EndpointStat>();

      proc.connections?.forEach((conn) => {
        const connBytesSent = Number(conn.bytesSent || 0);
        const connBytesReceived = Number(conn.bytesReceived || 0);

        const endpoint = getEndpointHash(conn);
        procEndpointsMap.set(endpoint, {
          totalBytesSent: connBytesSent,
          totalBytesReceived: connBytesReceived,
          hasSuspiciousEvents: procHasSuspiciousEvents,
        });

        procTotalBytesSent += connBytesSent;
        procTotalBytesReceived += connBytesReceived;

        const endpointStat: EndpointStat = stat.endpointsMap.get(endpoint) ?? {
          totalBytesSent: 0,
          totalBytesReceived: 0,
          hasSuspiciousEvents: false,
        };
        stat.endpointsMap.set(endpoint, {
          totalBytesSent: endpointStat.totalBytesSent + connBytesSent,
          totalBytesReceived: endpointStat.totalBytesReceived + connBytesReceived,
          hasSuspiciousEvents: endpointStat.hasSuspiciousEvents || procHasSuspiciousEvents,
        });
      });

      stat.processesMap.set(proc, {
        totalBytesSent: procTotalBytesSent,
        totalBytesReceived: procTotalBytesReceived,
        hasSuspiciousEvents: procHasSuspiciousEvents,
        endpointsMap: procEndpointsMap,
      });

      recTotalBytesSent += procTotalBytesSent;
      recTotalBytesReceived += procTotalBytesReceived;

      procEndpointsMap.forEach((procEndpointStat, procEndpoint) => {
        const subEndpointStat: EndpointStat = recEndpointsMap.get(procEndpoint) ?? {
          totalBytesSent: 0,
          totalBytesReceived: 0,
          hasSuspiciousEvents: false,
        };
        subEndpointStat.totalBytesSent += procEndpointStat.totalBytesSent;
        subEndpointStat.totalBytesReceived += procEndpointStat.totalBytesReceived;
        subEndpointStat.hasSuspiciousEvents ||= procEndpointStat.hasSuspiciousEvents;
        recEndpointsMap.set(procEndpoint, subEndpointStat);

        const endpointKind = inferEndpointKind(procEndpoint);
        endpointsMap.set(procEndpoint, { kind: endpointKind });

        const endpointConnections = connectionsMap.get(procEndpoint) ?? new Set();

        endpointConnections.add(proc);
        connectionsMap.set(procEndpoint, endpointConnections);
      });

      const subResult = rec(proc.children);
      recTotalBytesSent += subResult.totalBytesSent;
      recTotalBytesReceived += subResult.totalBytesReceived;
      recHasSuspiciousEvents ||= subResult.hasSuspiciousEvents;

      subResult.endpointsMap.forEach((endpointStat, endpoint) => {
        const subEndpointStat: EndpointStat = recEndpointsMap.get(endpoint) ?? {
          totalBytesSent: 0,
          totalBytesReceived: 0,
          hasSuspiciousEvents: false,
        };
        subEndpointStat.totalBytesSent += endpointStat.totalBytesSent;
        subEndpointStat.totalBytesReceived += endpointStat.totalBytesReceived;
        subEndpointStat.hasSuspiciousEvents ||= endpointStat.hasSuspiciousEvents;
        recEndpointsMap.set(endpoint, subEndpointStat);
      });
    });

    return {
      totalBytesSent: recTotalBytesSent,
      totalBytesReceived: recTotalBytesReceived,
      hasSuspiciousEvents: recHasSuspiciousEvents,
      endpointsMap: recEndpointsMap,
    };
  };

  const hostResult = rec(model.applicationModel?.host?.processes ?? []);

  let namespacesTotalBytesSent = 0;
  let namespacesTotalBytesReceived = 0;
  let namespacesHasSuspiciousEvents = false;
  const namespacesEndpointsMap = new Map<string, EndpointStat>();

  model.applicationModel?.namespaces?.forEach((namespace) => {
    if (!namespace.name) return;

    let namespaceTotalBytesSent = 0;
    let namespaceTotalBytesReceived = 0;
    const namespaceEndpointsMap = new Map<string, EndpointStat>();
    let namespaceHasSuspiciousEvent = false;

    namespace.workloads?.forEach((workload) => {
      if (!workload.name) return;

      const workloadResult = rec(workload.processes);

      stat.workloadsMap.set(namespace.name + '/' + workload.name, {
        totalBytesSent: workloadResult.totalBytesSent,
        totalBytesReceived: workloadResult.totalBytesReceived,
        hasSuspiciousEvents: workloadResult.hasSuspiciousEvents,
        endpointsMap: workloadResult.endpointsMap,
      });

      namespaceTotalBytesSent += workloadResult.totalBytesSent;
      namespaceTotalBytesReceived += workloadResult.totalBytesReceived;
      namespaceHasSuspiciousEvent ||= workloadResult.hasSuspiciousEvents;

      workloadResult.endpointsMap.forEach((endpointStat, endpoint) => {
        const namespaceEndpointStat: EndpointStat = namespaceEndpointsMap.get(endpoint) ?? {
          totalBytesSent: 0,
          totalBytesReceived: 0,
          hasSuspiciousEvents: false,
        };
        namespaceEndpointStat.totalBytesSent += endpointStat.totalBytesSent;
        namespaceEndpointStat.totalBytesReceived += endpointStat.totalBytesReceived;
        namespaceEndpointStat.hasSuspiciousEvents ||= endpointStat.hasSuspiciousEvents;
        namespaceEndpointsMap.set(endpoint, namespaceEndpointStat);

        const namespacesEndpointStat: EndpointStat = namespacesEndpointsMap.get(endpoint) ?? {
          totalBytesSent: 0,
          totalBytesReceived: 0,
          hasSuspiciousEvents: false,
        };
        namespacesEndpointStat.totalBytesSent += endpointStat.totalBytesSent;
        namespacesEndpointStat.totalBytesReceived += endpointStat.totalBytesReceived;
        namespacesEndpointStat.hasSuspiciousEvents ||= endpointStat.hasSuspiciousEvents;
        namespacesEndpointsMap.set(endpoint, namespacesEndpointStat);
      });
    });

    namespacesTotalBytesSent += namespaceTotalBytesSent;
    namespacesTotalBytesReceived += namespaceTotalBytesReceived;
    namespacesHasSuspiciousEvents ||= namespaceHasSuspiciousEvent;

    stat.namespacesMap.set(namespace.name, {
      totalBytesSent: namespaceTotalBytesSent,
      totalBytesReceived: namespaceTotalBytesReceived,
      hasSuspiciousEvents: namespaceHasSuspiciousEvent,
      endpointsMap: namespaceEndpointsMap,
    });
  });

  stat.node.totalBytesSent = hostResult.totalBytesSent + namespacesTotalBytesSent;
  stat.node.totalBytesReceived = hostResult.totalBytesReceived + namespacesTotalBytesReceived;
  stat.node.hasSuspiciousEvents = hostResult.hasSuspiciousEvents || namespacesHasSuspiciousEvents;

  stat.host.totalBytesSent = hostResult.totalBytesSent;
  stat.host.totalBytesReceived = hostResult.totalBytesSent;
  stat.host.endpointsMap = hostResult.endpointsMap;
  stat.host.hasSuspiciousEvents = hostResult.hasSuspiciousEvents;

  stat.namespaces.totalBytesSent = namespacesTotalBytesSent;
  stat.namespaces.totalBytesReceived = namespacesTotalBytesReceived;
  stat.namespaces.endpointsMap = namespacesEndpointsMap;
  stat.namespaces.hasSuspiciousEvents = namespacesHasSuspiciousEvents;

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
      hasSuspiciousEvents: false,
    } as Stat,
    host: {
      totalBytesSent: 0,
      totalBytesReceived: 0,
      endpointsMap: new Map(),
      hasSuspiciousEvents: false,
    } as TreeEntryStat,
    namespaces: {
      totalBytesSent: 0,
      totalBytesReceived: 0,
      endpointsMap: new Map(),
      hasSuspiciousEvents: false,
    } as TreeEntryStat,
    namespacesMap: new Map<string, TreeEntryStat>(),
    workloadsMap: new Map<string, TreeEntryStat>(),
    processesMap: new WeakMap<ApplicationProcess, TreeEntryStat>(),
    endpointsMap: new Map<string, EndpointStat>(),
  };
}
