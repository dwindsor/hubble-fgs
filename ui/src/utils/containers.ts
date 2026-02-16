import type { Namespace } from "./namespaces";
import type { Workload } from "./workloads";

export type Container = string;

export type ContainerHash = `${Namespace}/${Workload}/${Container}`;

export function getContainerHash(
  namespace: Namespace,
  workload: Workload,
  container: Container,
): ContainerHash {
  return `${namespace}/${workload}/${container}`;
}
