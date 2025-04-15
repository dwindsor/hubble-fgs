import type { ApplicationProcessGroup } from "~/proto";
import type { XY } from "./geometry";
import type { ThrowableMap } from "./throwable-map";
import type { TreePath } from "./tree";

export type ProcessInfo = {
  path: TreePath;
  visible?: boolean | undefined;
  xy?: XY | undefined;
};

export type ProcessesMap = ThrowableMap<ApplicationProcessGroup, ProcessInfo>;

export function getProcHash(proc: ApplicationProcessGroup) {
  return `${proc.name}:[${proc.arguments}]`;
}

export function isSuspiciousProc(proc: ApplicationProcessGroup): boolean {
  if (typeof proc.in_init_tree === "boolean") {
    return !proc.in_init_tree;
  }
  return false;
}
