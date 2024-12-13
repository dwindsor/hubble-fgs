import Emitter from "events";
import { createContext, useContext } from "react";
import TypedEmitter from "typed-emitter";
import { ApplicationModelEvent, ApplicationProcess } from "~/proto/appmodel";
import { WH, XY } from "~/types";
import { createAppState } from "./utils";

export type AppState = ReturnType<typeof useAppState>;

export function createAppContext(
  model: ApplicationModelEvent,
  getTreeOffset: () => number
) {
  const state = createAppState(model);

  enum EmitterEventKind {
    AppSizeChanged = "app-size-changed",
    TreeChanged = "tree-changed",
    RedrawConnectionsLines = "redraw-connections-lines",
  }

  const emitter = new Emitter().setMaxListeners(4096) as TypedEmitter<{
    [EmitterEventKind.AppSizeChanged]: (wh: WH) => void;
    [EmitterEventKind.TreeChanged]: () => void;
    [EmitterEventKind.RedrawConnectionsLines]: () => void;
  }>;

  const createSubscriber = <Args extends any[]>(kind: EmitterEventKind) => {
    return (callback: (...args: Args) => void) => {
      emitter.on(kind, callback);
      return () => {
        emitter.off(kind, callback);
      };
    };
  };

  const uniqSortedEndpoints = Array.from(state.endpointsMap.keys()).sort(
    (a, b) => a.localeCompare(b)
  );

  const changeAppSize = (size: WH) => {
    emitter.emit(EmitterEventKind.AppSizeChanged, size);
  };

  const updateProcess = (
    proc: ApplicationProcess,
    visible: boolean | undefined,
    xy: XY | undefined
  ) => {
    const cur = state.processesMap.get(proc);
    if (!cur) {
      throw new Error(
        "All processes excpected to be available in processes map"
      );
    }
    state.processesMap.set(proc, { visible, xy, endpoints: cur.endpoints });
    emitter.emit(EmitterEventKind.RedrawConnectionsLines);
  };

  const updateEndpoint = (endpoint: string, xy: XY) => {
    state.endpointsMap.set(endpoint, { xy });
    emitter.emit(EmitterEventKind.RedrawConnectionsLines);
  };

  const changeTree = () => {
    emitter.emit(EmitterEventKind.TreeChanged);
  };

  const onAppSizeChanged = createSubscriber(EmitterEventKind.AppSizeChanged);

  const onTreeChanged = createSubscriber(EmitterEventKind.TreeChanged);

  const onRedrawConnectionsLines = createSubscriber(
    EmitterEventKind.RedrawConnectionsLines
  );

  return {
    model,
    endpoints: uniqSortedEndpoints,
    connections: state.connections,
    processesMap: state.processesMap,
    endpointsMap: state.endpointsMap,
    stat: state.stats,
    changeAppSize,
    updateProcess,
    updateEndpoint,
    changeTree,
    getTreeOffset,
    onTreeSizeChanged: onAppSizeChanged,
    onTreeChanged,
    onRedrawConnectionsLines,
  };
}

export const AppContext = createContext(
  createAppContext(
    {
      clusterName: "",
      nodeName: "",
      applicationModel: undefined,
      time: new Date(),
    },
    () => 0
  )
);

export const useAppState = () => useContext(AppContext);
