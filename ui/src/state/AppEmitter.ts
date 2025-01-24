// biome-ignore lint/style/useNodejsImportProtocol: events it's an actual npm package
import Emitter from "events";
import type TypedEmitter from "typed-emitter";
import type { ApplicationProcess } from "~/proto";
import type { PropertyValues } from "~/types";
import type { EndpointModeType } from "~/utils/endpoints";

export const EmitterEventKind = {
  __proto__: null,
  TreeChanged: "tree-changed",
  EndpointsListChanged: "endpoints-list-changed",
  RedrawConnectionsLines: "redraw-connections-lines",
  EndpointUpdated: "endpoint-updated",
  ProcUpdated: "proc-updated",
  HighlightEndpoint: "highlight-endpoint",
  HighlightProc: "highlight-proc",
} as const;

export type EmitterEventKind = PropertyValues<typeof EmitterEventKind>;

export type EmitterHandlers = {
  [EmitterEventKind.TreeChanged]: () => void;
  [EmitterEventKind.EndpointsListChanged]: () => void;
  [EmitterEventKind.RedrawConnectionsLines]: () => void;
  [EmitterEventKind.ProcUpdated]: (proc: ApplicationProcess) => void;
  [EmitterEventKind.EndpointUpdated]: (endpoint: string) => void;
  [EmitterEventKind.HighlightEndpoint]: (
    endpoint: string,
    state: boolean,
    mode: EndpointModeType,
  ) => void;
  [EmitterEventKind.HighlightProc]: (proc: ApplicationProcess, state: boolean) => void;
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
