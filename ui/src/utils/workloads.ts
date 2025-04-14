import { WORKLOAD_KIND_KEY_PREFIX, type WorkloadKind } from "~/proto";
import type { Namespace } from "./namespaces";

export type Workload = string;

export type WorkloadHash = `${Namespace}/${Workload}`;

export function getWorkloadHash(namespace: Namespace, workload: Workload): WorkloadHash {
  return `${namespace}/${workload}`;
}

export function workloadKindAsHumanString(kind: WorkloadKind): string {
  return kind.slice(WORKLOAD_KIND_KEY_PREFIX.length).toLocaleLowerCase();
}
