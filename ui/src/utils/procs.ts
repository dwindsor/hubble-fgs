import type { ApplicationProcessGroup } from "~/proto";

export function isSuspiciousProc(proc: ApplicationProcessGroup): boolean {
  if (typeof proc.inInitTree === "boolean") {
    return !proc.inInitTree;
  }
  return false;
}
