import hashsum from "hash-sum";
import type { Namespace } from "./namespaces";
import type { Workload } from "./workloads";

export type TreePathHash = string;
export type TreeClusterPath = { cluster: true };
export type TreeNodePath = { node: true };
export type TreeHostPath = { host: true };
export type TreeHostProcPath = { path: TreePathHash[] };
export type TreeNamespacesPath = { namespaces: true };
export type TreeNamespacePath = { namespace: Namespace };
export type TreeWorkloadPath = TreeNamespacePath & { workload: Workload };
export type TreeWorkloadProcPath = TreeWorkloadPath & { path: TreePathHash[] };
export type TreePath =
  | TreeClusterPath
  | TreeNodePath
  | TreeHostPath
  | TreeHostProcPath
  | TreeNamespacesPath
  | TreeNamespacePath
  | TreeWorkloadPath
  | TreeWorkloadProcPath;

export type TreePathStatus = {
  expanded?: boolean;
  visible?: boolean;
};

export const TREE_CLUSTER_PATH: TreeClusterPath = { cluster: true };
export const TREE_NODE_PATH: TreeNodePath = { node: true };
export const TREE_HOST_PATH: TreeHostPath = { host: true };
export const TREE_NAMESPACES_PATH: TreeNamespacesPath = { namespaces: true };

export function calcTreePathHash(path: TreePath): string {
  return hashsum(path);
}
