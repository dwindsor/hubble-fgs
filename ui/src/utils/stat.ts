import type { ApplicationProcessGroup } from "~/proto";
import type { Endpoint } from "./endpoints";
import type { Namespace } from "./namespaces";
import type { Workload } from "./workloads";
import { Container } from "./containers";

export type Stat = {
  txBytes: number;
  rxBytes: number;
  txDrops: number;
  hasSuspiciousProcs: boolean;
};

export type TreeEntryStat = Stat & {
  endpointsMap: Map<Endpoint, Stat>;
  hasSuspiciousProcs: boolean;
};

export type StatState = ReturnType<typeof createStatState>;

export function createStat(initializer?: Partial<Stat>): Stat {
  return {
    txBytes: 0,
    rxBytes: 0,
    txDrops: 0,
    hasSuspiciousProcs: false,
    ...initializer,
  };
}

export function createTreeEntryStat(initializer?: Partial<TreeEntryStat>): TreeEntryStat {
  return {
    ...createStat(),
    endpointsMap: new Map(),
    ...initializer,
  };
}

export function advanceStat(target: Stat, ...extenders: Stat[]) {
  extenders.forEach((extender) => {
    target.txBytes += extender.txBytes;
    target.rxBytes += extender.rxBytes;
    target.txDrops += extender.txDrops;
    target.hasSuspiciousProcs ||= extender.hasSuspiciousProcs;
  });
}

export function advanceEndpointStat(
  target: Map<Endpoint, Stat>,
  endpoint: Endpoint,
  ...extenders: Stat[]
) {
  const endpointStat = target.get(endpoint) ?? createStat();
  advanceStat(endpointStat, ...extenders);
  target.set(endpoint, endpointStat);
}

export function advanceEndpointStatMap(
  target: Map<Endpoint, Stat>,
  ...extenders: Map<Endpoint, Stat>[]
) {
  extenders.forEach((extender) => {
    extender.forEach((endpointStat, endpoint) => {
      advanceEndpointStat(target, endpoint, endpointStat);
    });
  });
}

export function createStatState() {
  return {
    node: createTreeEntryStat(),
    host: createTreeEntryStat(),
    namespaces: createTreeEntryStat(),
    namespacesMap: new Map<Namespace, TreeEntryStat>(),
    workloadsMap: new Map<Workload, TreeEntryStat>(),
    containersMap: new Map<Container, TreeEntryStat>(),
    processesMap: new WeakMap<ApplicationProcessGroup, TreeEntryStat>(),
    endpointsMap: new Map<Endpoint, Stat>(),
  };
}
