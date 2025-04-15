// biome-ignore lint/style/useNodejsImportProtocol: events it's the actual npm package
import Emitter from "events";
import type TypedEmitter from "typed-emitter";
import type { ApplicationProcessGroup } from "~/proto";
import type { Endpoint, EndpointModeKind } from "~/utils/endpoints";
import { Enum, type EnumType } from "~/utils/enum";
import type { TreePath, TreePathStatus } from "~/utils/tree";

export const EmitterEventKind = Enum({
  TreeChanged: "tree-changed",
  EndpointsListChanged: "endpoints-list-changed",
  RedrawConnectionsLines: "redraw-connections-lines",
  EndpointUpdated: "endpoint-updated",
  ProcUpdated: "proc-updated",
  HighlightEndpoint: "highlight-endpoint",
  HighlightProc: "highlight-proc",
  TreePathStatusChanged: "tree-path-status-changed",
  Scrolled: "scrolled",
});

export type EmitterEventKind = EnumType<typeof EmitterEventKind>;

export type EmitterHandlers = {
  [EmitterEventKind.TreeChanged]: () => void;
  [EmitterEventKind.EndpointsListChanged]: () => void;
  [EmitterEventKind.RedrawConnectionsLines]: () => void;
  [EmitterEventKind.ProcUpdated]: (proc: ApplicationProcessGroup) => void;
  [EmitterEventKind.EndpointUpdated]: (endpoint: Endpoint) => void;
  [EmitterEventKind.HighlightEndpoint]: (
    endpoint: Endpoint,
    state: boolean,
    mode: EndpointModeKind,
  ) => void;
  [EmitterEventKind.HighlightProc]: (proc: ApplicationProcessGroup, state: boolean) => void;
  [EmitterEventKind.TreePathStatusChanged]: (path: TreePath, status: TreePathStatus) => void;
  [EmitterEventKind.Scrolled]: () => void;
};

export class AppEmitter {
  public readonly emitter: TypedEmitter<EmitterHandlers>;

  constructor() {
    this.emitter = new Emitter().setMaxListeners(16384) as TypedEmitter<EmitterHandlers>;
  }

  createSubscriber = <K extends EmitterEventKind, H extends EmitterHandlers[K]>(kind: K) => {
    return (handler: H) => {
      this.emitter.on(kind, handler);
      return () => {
        this.emitter.off(kind, handler);
      };
    };
  };
}
