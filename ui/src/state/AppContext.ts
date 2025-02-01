import { create } from "@bufbuild/protobuf";
import { timestampNow } from "@bufbuild/protobuf/wkt";
import { ApplicationModelEventSchema } from "@ipa/application_model/v1alpha/application_model_pb";
import { createContext, useContext } from "react";
import type { ApplicationModelEvent, ApplicationProcessGroup } from "~/proto";
import type { TreePathStatus, XY } from "~/types";
import { assert } from "~/utils/assert";
import { EndpointMode, type EndpointModeType } from "~/utils/endpoints";
import { UrlParams, type UrlParamsType, setQueryParam } from "~/utils/url";
import { AppEmitter, EmitterEventKind } from "./AppEmitter";
import { createAppState } from "./utils";

export type AppState = ReturnType<typeof useAppState>;

export function createAppContext({
  model,
  getTreeOffset,
  persistInUrl,
}: {
  model: ApplicationModelEvent;
  getTreeOffset: () => { x?: number; y?: number };
  persistInUrl?: boolean | undefined;
}) {
  const state = createAppState(model);

  const inner = {
    treePathsMap: new Map<string, TreePathStatus>(),
    highlightedEndpointsMap: new Map<string, Set<EndpointModeType>>(),
    highlightedProc: null as ApplicationProcessGroup | null,
  };

  if (persistInUrl) {
    // Restore state from url params
    new URLSearchParams(window.location.search).forEach((value, param) => {
      if (param === "expanded") {
        value.split(",").forEach((hash) => {
          inner.treePathsMap.set(hash, { expanded: true });
        });
      } else if (param === "pinned") {
        value.split(",").forEach((endpoint) => {
          const modes = new Set<EndpointModeType>();
          modes.add(EndpointMode.Pinned);
          inner.highlightedEndpointsMap.set(endpoint, modes);
        });
      }
    });
  }

  const emitter = new AppEmitter();

  const that = {
    model,

    getTreeOffset,

    setQueryParam(key: UrlParamsType, value?: string | undefined | null) {
      if (!persistInUrl) {
        return;
      }
      setQueryParam(key, value);
    },

    getTreePathStatus(hash: string) {
      return inner.treePathsMap.get(hash);
    },

    setTreePathStatus(hash: string, status: TreePathStatus) {
      inner.treePathsMap.set(hash, Object.assign(inner.treePathsMap.get(hash) ?? {}, status));

      const expanded: string[] = [];
      inner.treePathsMap.forEach((value, hash) => {
        if (!value.expanded || !value.visible) return;
        expanded.push(hash);
      });
      if (expanded.length) {
        that.setQueryParam(UrlParams.Expanded, expanded.sort().join(","));
      } else {
        that.setQueryParam(UrlParams.Expanded, undefined);
      }
    },

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
      return state.stat;
    },

    changeTree() {
      emitter.emitter.emit(EmitterEventKind.TreeChanged);
    },

    onTreeChanged: emitter.createSubscriber(EmitterEventKind.TreeChanged),

    changeEndpointsList() {
      emitter.emitter.emit(EmitterEventKind.EndpointsListChanged);
    },

    onEndpointsListChanged: emitter.createSubscriber(EmitterEventKind.EndpointsListChanged),

    redrawConnectionLines() {
      emitter.emitter.emit(EmitterEventKind.RedrawConnectionsLines);
    },

    onRedrawConnectionsLines: emitter.createSubscriber(EmitterEventKind.RedrawConnectionsLines),

    updateProcess(proc: ApplicationProcessGroup, visible: boolean | undefined, xy: XY | undefined) {
      const cur = state.processesMap.get(proc);
      if (cur) {
        cur.visible = visible;
        cur.xy = xy;
      }
      assert(cur, "All processes expected to be available in processes map");
      state.processesMap.set(proc, cur);
      emitter.emitter.emit(EmitterEventKind.ProcUpdated, proc);
      that.redrawConnectionLines();
    },

    onProcUpdated: emitter.createSubscriber(EmitterEventKind.ProcUpdated),

    updateEndpoint(endpoint: string, visible: boolean | undefined, xy: XY | undefined) {
      const cur = state.endpointsMap.get(endpoint);
      if (cur) {
        cur.visible = visible;
        cur.xy = xy;
      }
      assert(cur, "All endpoints expected to be available in endpoints map");
      state.endpointsMap.set(endpoint, cur);
      emitter.emitter.emit(EmitterEventKind.EndpointUpdated, endpoint);
      that.redrawConnectionLines();
    },

    onEndpointUpdated: emitter.createSubscriber(EmitterEventKind.EndpointUpdated),

    get highlightedEndpointsMap() {
      return inner.highlightedEndpointsMap;
    },

    highlightEndpoint(endpoint: string, state: boolean, mode: EndpointModeType) {
      const modes = inner.highlightedEndpointsMap.get(endpoint) ?? new Set();
      if (!state) {
        modes.delete(mode);
        if (!modes.size) {
          inner.highlightedEndpointsMap.delete(endpoint);
        }
      } else {
        modes.add(mode);
        inner.highlightedEndpointsMap.set(endpoint, modes);
      }

      const pinned: string[] = [];
      inner.highlightedEndpointsMap.forEach((modes, endpoint) => {
        if (!modes.has(EndpointMode.Pinned)) return;
        pinned.push(endpoint);
      });
      if (pinned.length) {
        that.setQueryParam(UrlParams.Pinned, pinned.sort().join(","));
      } else {
        that.setQueryParam(UrlParams.Pinned, undefined);
      }

      emitter.emitter.emit(EmitterEventKind.HighlightEndpoint, endpoint, state, mode);
      that.redrawConnectionLines();
    },

    onEndpointHighlight: emitter.createSubscriber(EmitterEventKind.HighlightEndpoint),

    get highlightedProc() {
      return inner.highlightedProc;
    },

    highlightProc(proc: ApplicationProcessGroup, state: boolean) {
      inner.highlightedProc = state ? proc : null;
      emitter.emitter.emit(EmitterEventKind.HighlightProc, proc, state);
      that.redrawConnectionLines();
    },

    onProcHighlight: emitter.createSubscriber(EmitterEventKind.HighlightProc),
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
  }),
);

export const useAppState = () => useContext(AppContext);
