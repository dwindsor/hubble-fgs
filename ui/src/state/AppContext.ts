import Emitter from "events";
import { createContext, useContext } from "react";
import TypedEmitter from "typed-emitter";
import { ApplicationModelEvent, ApplicationProcess } from "~/proto";
import { WH, XY } from "~/types";
import { createAppState } from "./utils";
import {
  ApplicationModelEventSchema,
  file_application_model_v1alpha_application_model,
} from "@ipa/application_model/v1alpha/application_model_pb";
import { create } from "@bufbuild/protobuf";
import { timestampNow } from "@bufbuild/protobuf/wkt";

export type AppState = ReturnType<typeof useAppState>;

export function createAppContext({
  model,
  getTreeOffset,
}: {
  model: ApplicationModelEvent;
  getTreeOffset: () => number;
}) {
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

  const updateEndpoint = (
    endpoint: string,
    visible: boolean | undefined,
    xy: XY | undefined
  ) => {
    state.endpointsMap.set(endpoint, { visible, xy });
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
    connectionsMap: state.connectionsMap,
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
  createAppContext({
    model: create(ApplicationModelEventSchema, {
      clusterName: "",
      nodeName: "",
      time: timestampNow(),
    }),
    getTreeOffset: () => 0,
  })
);

export const useAppState = () => useContext(AppContext);
