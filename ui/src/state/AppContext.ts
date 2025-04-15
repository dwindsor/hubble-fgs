import { createContext, useContext } from "react";
import type { ApplicationModelEvent, ApplicationProcessGroup } from "~/proto";
import { assert } from "~/utils/assert";
import { type Endpoint, EndpointModeKind } from "~/utils/endpoints";
import type { XY } from "~/utils/geometry";
import {
  type TreePath,
  type TreePathHash,
  type TreePathStatus,
  calcTreePathHash,
} from "~/utils/tree";
import { UrlParams, getQueryParam, setQueryParam } from "~/utils/url";
import { AppEmitter, EmitterEventKind } from "./AppEmitter";
import { createAppState } from "./AppState";

export type AppState = ReturnType<typeof useAppState>;

export type AppContextType = ReturnType<typeof createAppContext>;

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
    getQueryParam(UrlParams.Expanded)
      ?.split(",")
      .forEach((hash) => {
        inner.treePathsMap.set(hash, { expanded: true });
      });
    getQueryParam(UrlParams.Pinned)
      ?.split(",")
      .forEach((endpointHash) => {
        const endpoint = state.endpointsHashMap.get(endpointHash);
        if (!endpoint) {
          return;
        }
        const modes = new Set<EndpointModeKind>();
        modes.add(EndpointModeKind.Pinned);
        inner.highlightedEndpointsMap.set(endpoint, modes);
      });
  }

  const emitter = new AppEmitter();

  const that = {
    model,
    persistInUrl,

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

    setTreePathStatus(path: TreePath, status: TreePathStatus) {
      const pathHash = calcTreePathHash(path);
      inner.treePathsMap.set(
        pathHash,
        Object.assign(inner.treePathsMap.get(pathHash) ?? {}, status),
      );

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

      emitter.emitter.emit(
        EmitterEventKind.TreePathStatusChanged,
        path,
        inner.treePathsMap.get(pathHash) ?? {},
      );
    },

    onTreePathStatusChanged: emitter.createSubscriber(EmitterEventKind.TreePathStatusChanged),

    toggleTreePath(path: TreePath) {
      const pathHash = calcTreePathHash(path);
      that.setTreePathStatus(path, { expanded: !inner.treePathsMap.get(pathHash)?.expanded });
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

    get endpointsHashMap() {
      return state.endpointsHashMap;
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

    highlightEndpoint(endpoint: Endpoint, highlight: boolean, mode: EndpointModeKind) {
      const modes = inner.highlightedEndpointsMap.get(endpoint) ?? new Set();
      if (!highlight) {
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
        if (!modes.has(EndpointModeKind.Pinned)) return;
        const endpointInfo = state.endpointsMap.get(endpoint);
        if (!endpointInfo) {
          return;
        }
        pinned.push(endpointInfo.hash);
      });
      if (pinned.length) {
        that.setQueryParam(UrlParams.Pinned, pinned.sort().join(","));
      } else {
        that.setQueryParam(UrlParams.Pinned, undefined);
      }

      emitter.emitter.emit(EmitterEventKind.HighlightEndpoint, endpoint, highlight, mode);

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
    model: {},
    getTreeOffset: () => ({}),
  }),
);

export const useAppState = () => useContext(AppContext);
