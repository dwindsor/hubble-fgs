import Emitter from "events";
import TypedEmitter from "typed-emitter";
import { ApplicationProcess } from "~/proto";
import { PropertyValues, WH } from "~/types";

export const EmitterEventKind = {
  __proto__: null,
  AppSizeChanged: "app-size-changed",
  TreeChanged: "tree-changed",
  RedrawConnectionsLines: "redraw-connections-lines",
  ToggleEndpointHighlight: "toggle-endpoint-highlight",
  ToggleProcHighlight: "toggle-process-highlight",
} as const;

export type EmitterEventKind = PropertyValues<typeof EmitterEventKind>;

export type EmitterHandlers = {
  [EmitterEventKind.AppSizeChanged]: (wh: WH) => void;
  [EmitterEventKind.TreeChanged]: () => void;
  [EmitterEventKind.RedrawConnectionsLines]: () => void;
  [EmitterEventKind.ToggleEndpointHighlight]: (
    endpoint: string,
    state: boolean
  ) => void;
  [EmitterEventKind.ToggleProcHighlight]: (
    proc: ApplicationProcess,
    state: boolean
  ) => void;
};

export class AppEmitter {
  public readonly emitter: TypedEmitter<EmitterHandlers>;

  constructor() {
    this.emitter = new Emitter().setMaxListeners(
      16384
    ) as TypedEmitter<EmitterHandlers>;
  }

  createSubscriber = <K extends EmitterEventKind, H extends EmitterHandlers[K]>(
    kind: K
  ) => {
    return (handler: H) => {
      this.emitter.on(kind, handler);
      return () => {
        this.emitter.off(kind, handler);
      };
    };
  };
}
