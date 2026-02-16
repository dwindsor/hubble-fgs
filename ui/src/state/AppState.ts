import type { ApplicationModelEvent, ApplicationProcessGroup, Destination } from "~/proto";
import type { ConnectionsMap } from "~/utils/connections";
import { getContainerHash } from "~/utils/containers";
import {
  EndpointKind,
  type EndpointsHashMap,
  type EndpointsMap,
  inferEndpointHash,
  inferEndpointSubKind,
} from "~/utils/endpoints";
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
import { ThrowableMap } from "~/utils/throwable-map";
import type { TreeContainerProcPath, TreeHostProcPath } from "~/utils/tree";
import { getWorkloadHash } from "~/utils/workloads";

export function createAppState(model?: ApplicationModelEvent): {
  processesMap: ProcessesMap;
  endpointsMap: EndpointsMap;
  endpointsHashMap: EndpointsHashMap;
  connectionsMap: ConnectionsMap;
  stat: StatState;
} {
  const processesMap: ProcessesMap = new ThrowableMap();
  const endpointsMap: EndpointsMap = new ThrowableMap();
  const endpointsHashMap: EndpointsHashMap = new ThrowableMap();
  const connectionsMap: ConnectionsMap = new Map();
  const stat = createStatState();

  if (!model) {
    return {
      processesMap,
      endpointsMap,
      endpointsHashMap,
      connectionsMap,
      stat,
    };
  }

  const rec = (
    recProcPath: TreeHostProcPath | TreeContainerProcPath,
    recProcs?: ApplicationProcessGroup[],
  ): TreeEntryStat => {
    const recStat = createTreeEntryStat();

    recProcs?.forEach((proc) => {
      const procHash = getProcHash(proc);
      const procPath: TreeHostProcPath | TreeContainerProcPath = {
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
        if (!conn.destination) {
          return;
        }

        const endpoint = conn.destination as unknown as Destination;
        const endpointKind = EndpointKind.Destination;
        const endpointHash = inferEndpointHash(endpoint, endpointKind);
        const endpointSubKind = inferEndpointSubKind(endpoint, endpointKind);
        endpointsMap.set(endpoint, {
          hash: endpointHash,
          kind: endpointKind,
          subKind: endpointSubKind,
        });
        endpointsHashMap.set(endpointHash, endpoint);

        const endpointStat = createStat({
          txBytes: Number(conn.stats?.tx_bytes || 0),
          rxBytes: Number(conn.stats?.rx_bytes || 0),
          txDrops: Number(conn.stats?.tx_drops || 0),
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

      proc.file_events?.forEach((fileEvent) => {
        if (!fileEvent.file_path) {
          return;
        }

        const endpoint = fileEvent;
        const endpointKind = EndpointKind.FileEvent;
        const endpointHash = inferEndpointHash(endpoint, endpointKind);
        const endpointSubKind = inferEndpointSubKind(endpoint, endpointKind);
        endpointsMap.set(endpoint, {
          hash: endpointHash,
          kind: endpointKind,
          subKind: endpointSubKind,
        });
        endpointsHashMap.set(endpointHash, endpoint);

        const endpointStat = createStat({
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

  stat.host = rec({ path: [] }, model.application_model?.host?.processes ?? []);

  stat.namespaces = createTreeEntryStat();

  model.application_model?.namespaces?.forEach((namespace) => {
    if (!namespace.name) return;

    const namespaceStat = createTreeEntryStat();
    stat.namespacesMap.set(namespace.name, namespaceStat);

    namespace.workloads?.forEach((workload) => {
      if (!workload.name) return;

      const workloadStat = createTreeEntryStat();
      stat.workloadsMap.set(getWorkloadHash(namespace.name, workload.name), workloadStat);

      workload.containers?.forEach((container) => {
        if (!container.name) return;

        const containerStat = rec(
          {
            namespace: namespace.name,
            workload: workload.name,
            container: container.name,
            path: [],
          },
          container.processes,
        );

        stat.containersMap.set(
          getContainerHash(namespace.name, workload.name, container.name),
          containerStat,
        );

        advanceStat(workloadStat, containerStat);
        advanceEndpointStatMap(workloadStat.endpointsMap, containerStat.endpointsMap);
      });

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
    endpointsHashMap,
    connectionsMap,
    stat,
  };
}
