import { create } from "@bufbuild/protobuf";
import { timestampNow } from "@bufbuild/protobuf/wkt";
import { ApplicationModelEventSchema } from "@ipa/application_model/v1alpha/application_model_pb";
import { createContext, useContext } from "react";
import { ApplicationModelEvent, ApplicationProcess } from "~/proto";
import { WH, XY } from "~/types";
import { assert } from "~/utils/assert";
import { AppEmitter, EmitterEventKind } from "./AppEmitter";
import { createAppState } from "./utils";

export type AppState = ReturnType<typeof useAppState>;

export function createAppContext({
  model,
  getTreeOffset,
}: {
  model: ApplicationModelEvent;
  getTreeOffset: () => { x?: number; y?: number };
}) {
  const state = createAppState(model);

  const inner = {
    highlightedEndpoint: null as string | null,
    highlightedProc: null as ApplicationProcess | null,
  };

  const emitter = new AppEmitter();

  const that = {
    model,

    getTreeOffset,

    get connectionsMap() {
      return state.connectionsMap;
    },

    get processesMap() {
      return state.processesMap;
    },

    get endpointsMap() {
      return state.endpointsMap;
    },

    get stat() {
      return state.stats;
    },

    changeAppSize(size: WH) {
      emitter.emitter.emit(EmitterEventKind.TreeSizeChanged, size);
    },

    onTreeSizeChanged: emitter.createSubscriber(
      EmitterEventKind.TreeSizeChanged
    ),

    changeTree() {
      emitter.emitter.emit(EmitterEventKind.TreeChanged);
    },

    onTreeChanged: emitter.createSubscriber(EmitterEventKind.TreeChanged),

    onRedrawConnectionsLines: emitter.createSubscriber(
      EmitterEventKind.RedrawConnectionsLines
    ),

    updateProcess(
      proc: ApplicationProcess,
      visible: boolean | undefined,
      xy: XY | undefined
    ) {
      const cur = state.processesMap.get(proc);
      assert(cur, "All processes expected to be available in processes map");
      state.processesMap.set(proc, { ...cur, visible, xy });
      emitter.emitter.emit(EmitterEventKind.RedrawConnectionsLines);
    },

    updateEndpoint(
      endpoint: string,
      visible: boolean | undefined,
      xy: XY | undefined
    ) {
      const cur = state.endpointsMap.get(endpoint);
      assert(cur, "All endpoints expected to be available in endpoints map");
      state.endpointsMap.set(endpoint, { ...cur, visible, xy });
      emitter.emitter.emit(EmitterEventKind.RedrawConnectionsLines);
    },

    get highlightedEndpoint() {
      return inner.highlightedEndpoint;
    },

    toggleEndpontHighlight(endpoint: string, state: boolean) {
      inner.highlightedEndpoint = state ? endpoint : null;
      emitter.emitter.emit(
        EmitterEventKind.ToggleEndpointHighlight,
        endpoint,
        state
      );
    },

    onToggleEndpointHighlight: emitter.createSubscriber(
      EmitterEventKind.ToggleEndpointHighlight
    ),

    get highlightedProc() {
      return inner.highlightedProc;
    },

    toggleProcHighlight(proc: ApplicationProcess, state: boolean) {
      inner.highlightedProc = state ? proc : null;
      emitter.emitter.emit(EmitterEventKind.ToggleProcHighlight, proc, state);
    },

    onToggleProcHighlight: emitter.createSubscriber(
      EmitterEventKind.ToggleProcHighlight
    ),
  };

  return that;
}

export const AppContext = createContext(
  createAppContext({
    model: create(ApplicationModelEventSchema, {
      clusterName: "",
      nodeName: "",
      time: timestampNow(),
    }),
    getTreeOffset: () => ({}),
  })
);

export const useAppState = () => useContext(AppContext);
