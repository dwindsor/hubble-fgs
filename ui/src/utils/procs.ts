import type { ApplicationProcess } from "~/proto";

export function isSuspiciousProc(proc: ApplicationProcess): boolean {
  if (typeof proc.inInitTree === "boolean") {
    return !proc.inInitTree;
  }
  return false;
}
