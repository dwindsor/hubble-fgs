import { create } from "@bufbuild/protobuf";
import { timestampNow } from "@bufbuild/protobuf/wkt";
import { ApplicationModelEventSchema } from "@ipa/application_model/v1alpha/application_model_pb";
import { createContext, useContext } from "react";
import type { ApplicationModelEvent, ApplicationProcessGroup } from "~/proto";
import { assert } from "~/utils/assert";
import { type Endpoint, EndpointModeKind } from "~/utils/endpoints";
import type { XY } from "~/utils/geometry";
import type { TreePathHash, TreePathStatus } from "~/utils/tree";
import { UrlParams, setQueryParam } from "~/utils/url";
import { AppEmitter, EmitterEventKind } from "./AppEmitter";
import { createAppState } from "./AppState";

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
    treePathsMap: new Map<TreePathHash, TreePathStatus>(),
    highlightedEndpointsMap: new Map<Endpoint, Set<EndpointModeKind>>(),
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
          const modes = new Set<EndpointModeKind>();
          modes.add(EndpointModeKind.Pinned);
          inner.highlightedEndpointsMap.set(endpoint, modes);
        });
      }
    });
  }

  const emitter = new AppEmitter();

  const that = {
    model,

    getTreeOffset,

    setQueryParam(key: UrlParams, value?: string | undefined | null) {
      if (!persistInUrl) {
        return;
      }
      setQueryParam(key, value);
    },

    getTreePathStatus(hash: TreePathHash) {
      return inner.treePathsMap.get(hash);
    },

    setTreePathStatus(hash: TreePathHash, status: TreePathStatus) {
      inner.treePathsMap.set(hash, Object.assign(inner.treePathsMap.get(hash) ?? {}, status));

      const expanded: TreePathHash[] = [];
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

    scroll() {
      emitter.emitter.emit(EmitterEventKind.Scrolled);
    },

    onScrolled: emitter.createSubscriber(EmitterEventKind.Scrolled),

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

    updateEndpoint(endpoint: Endpoint, visible: boolean | undefined, xy: XY | undefined) {
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

    highlightEndpoint(endpoint: Endpoint, state: boolean, mode: EndpointModeKind) {
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

      const pinned: Endpoint[] = [];
      inner.highlightedEndpointsMap.forEach((modes, endpoint) => {
        if (!modes.has(EndpointModeKind.Pinned)) return;
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
