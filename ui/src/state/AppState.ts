import type { ApplicationModelEvent, ApplicationProcessGroup } from "~/proto";
import type { ConnectionsMap } from "~/utils/connections";
import { type EndpointsMap, constructEndpoint, inferEndpointKind } from "~/utils/endpoints";
import { type ProcessesMap, getProcHash, isSuspiciousProc } from "~/utils/procs";
import {
  type StatState,
  type TreeEntryStat,
  advanceEndpointStat,
  advanceEndpointStatMap,
  advanceStat,
  createStat,
  createStatState,
  createTreeEntryStat,
} from "~/utils/stat";
import type { TreeHostProcPath, TreeWorkloadProcPath } from "~/utils/tree";
import { getWorkloadHash } from "~/utils/workloads";

export function createAppState(model?: ApplicationModelEvent): {
  processesMap: ProcessesMap;
  endpointsMap: EndpointsMap;
  connectionsMap: ConnectionsMap;
  stat: StatState;
} {
  const processesMap: ProcessesMap = new WeakMap();
  const endpointsMap: EndpointsMap = new Map();
  const connectionsMap: ConnectionsMap = new Map();
  const stat = createStatState();

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
    recProcs?: ApplicationProcessGroup[],
  ): TreeEntryStat => {
    const recStat = createTreeEntryStat();

    recProcs?.forEach((proc) => {
      const procHash = getProcHash(proc);
      const procPath: TreeHostProcPath | TreeWorkloadProcPath = {
        ...recProcPath,
        path: [...recProcPath.path, procHash],
      };
      processesMap.set(proc, { path: procPath });

      const procStat = createTreeEntryStat({
        hasSuspiciousProcs: isSuspiciousProc(proc),
      });
      stat.processesMap.set(proc, procStat);

      advanceStat(recStat, procStat);

      proc.connections?.forEach((conn) => {
        const endpoint = constructEndpoint(conn);
        endpointsMap.set(endpoint, { kind: inferEndpointKind(endpoint) });

        const endpointStat = createStat({
          bytesSent: Number(conn.bytesSent || 0),
          bytesReceived: Number(conn.bytesReceived || 0),
          hasSuspiciousProcs: procStat.hasSuspiciousProcs,
        });
        advanceEndpointStat(stat.endpointsMap, endpoint, endpointStat);

        procStat.endpointsMap.set(endpoint, endpointStat);

        advanceStat(recStat, endpointStat);
        advanceEndpointStat(recStat.endpointsMap, endpoint, endpointStat);

        const endpointConnections = connectionsMap.get(endpoint) ?? new Set();
        endpointConnections.add(proc);
        connectionsMap.set(endpoint, endpointConnections);
      });

      const subStat = rec(procPath, proc.children);
      advanceStat(recStat, subStat);
      advanceEndpointStatMap(recStat.endpointsMap, subStat.endpointsMap);
    });

    return recStat;
  };

  stat.host = rec({ path: [] }, model.applicationModel?.host?.processes ?? []);

  stat.namespaces = createTreeEntryStat();

  model.applicationModel?.namespaces?.forEach((namespace) => {
    if (!namespace.name) return;

    const namespaceStat = createTreeEntryStat();
    stat.namespacesMap.set(namespace.name, namespaceStat);

    namespace.workloads?.forEach((workload) => {
      if (!workload.name) return;

      const workloadStat = rec(
        { namespace: namespace.name, workload: workload.name, path: [] },
        workload.processes,
      );
      stat.workloadsMap.set(getWorkloadHash(namespace.name, workload.name), workloadStat);

      advanceStat(namespaceStat, workloadStat);
      advanceEndpointStatMap(namespaceStat.endpointsMap, workloadStat.endpointsMap);
      advanceEndpointStatMap(stat.namespaces.endpointsMap, workloadStat.endpointsMap);
    });

    advanceStat(stat.namespaces, namespaceStat);
  });

  advanceStat(stat.node, stat.host, stat.namespaces);
  advanceEndpointStatMap(
    stat.node.endpointsMap,
    stat.host.endpointsMap,
    stat.namespaces.endpointsMap,
  );

  return {
    processesMap,
    endpointsMap,
    connectionsMap,
    stat,
  };
}
