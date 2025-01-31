import type { Namespace } from "./namespaces";

export type Workload = string;

export type WorkloadHash = `${Namespace}/${Workload}`;

export function getWorkloadHash(namespace: Namespace, workload: Workload): WorkloadHash {
  return `${namespace}/${workload}`;
}
