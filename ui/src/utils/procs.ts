import type { ApplicationProcessGroup } from "~/proto";
import type { XY } from "./geometry";
import type { TreePath } from "./tree";

export type ProcessInfo = {
  path: TreePath;
  visible?: boolean | undefined;
  xy?: XY | undefined;
};

export type ProcessesMap = WeakMap<ApplicationProcessGroup, ProcessInfo>;

export function getProcHash(proc: ApplicationProcessGroup) {
  return `${proc.name}:[${proc.arguments}]`;
}

export function isSuspiciousProc(proc: ApplicationProcessGroup): boolean {
  if (typeof proc.inInitTree === "boolean") {
    return !proc.inInitTree;
  }
  return false;
}
