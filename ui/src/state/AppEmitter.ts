// biome-ignore lint/style/useNodejsImportProtocol: events it's the actual npm package
import Emitter from "events";
import type TypedEmitter from "typed-emitter";
import type { ApplicationProcessGroup } from "~/proto";
import type { Endpoint, EndpointMode } from "~/utils/endpoints";
import { Enum, type EnumType } from "~/utils/enum";

export const EmitterEventKind = Enum({
  TreeChanged: "tree-changed",
  EndpointsListChanged: "endpoints-list-changed",
  RedrawConnectionsLines: "redraw-connections-lines",
  EndpointUpdated: "endpoint-updated",
  ProcUpdated: "proc-updated",
  HighlightEndpoint: "highlight-endpoint",
  HighlightProc: "highlight-proc",
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
    mode: EndpointMode,
  ) => void;
  [EmitterEventKind.HighlightProc]: (proc: ApplicationProcessGroup, state: boolean) => void;
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
