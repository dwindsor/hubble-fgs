import clsx from "clsx";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useAppState } from "~/state/AppContext";
import type { EndpointStat, TreeEntryStat } from "~/state/utils";
import { EndpointKind, type PropertyValues } from "~/types";
import { useConnector } from "./useConnector";

export const VisualState = {
  __proto__: null,
  Base: "base",
  Highlighted: "highlighted",
  Muted: "muted",
} as const;

export type VisualStateType = PropertyValues<typeof VisualState>;

export function useTreeEntry(args: { statInfo: TreeEntryStat | undefined }) {
  const state = useAppState();

  const connector = useConnector();

  const [selectedEndpoint, setSelectedEndpoint] = useState<string | null>(null);

  const [visualState, setVisualState] = useState<VisualStateType>(VisualState.Base);

  const getVisibleEndpoints = useCallback(() => {
    const entryEndpoints = new Set(args.statInfo?.endpointsMap.keys());
    if (entryEndpoints.size === 0) {
      return undefined;
    }
    const visibleEndpoints = new Set<string>();
    let hasVisibleEndpoints = false;
    state.endpointsMap.forEach((endpointInfo, endpoint) => {
      hasVisibleEndpoints ||= !!endpointInfo.visible;
      if (entryEndpoints.has(endpoint) && endpointInfo.visible) {
        visibleEndpoints.add(endpoint);
      }
    });
    return hasVisibleEndpoints ? visibleEndpoints : entryEndpoints;
  }, [state, args.statInfo]);

  const [visibleEndpoints, setVisibleEndpoints] = useState(getVisibleEndpoints());

  useEffect(() => {
    return state.onEndpointUpdated(() => {
      setVisibleEndpoints(getVisibleEndpoints());
    });
  }, [state, getVisibleEndpoints]);

  const endpointKind = useMemo(() => {
    if (!selectedEndpoint) {
      return null;
    }
    return state.endpointsMap.get(selectedEndpoint)?.kind ?? null;
  }, [state, selectedEndpoint]);

  const hasConnections = useMemo(() => {
    return !!visibleEndpoints?.size;
  }, [visibleEndpoints]);

  const stat = useMemo((): TreeEntryStat | null => {
    if (!args.statInfo) {
      return null;
    }
    if (selectedEndpoint) {
      const endpointStat = args.statInfo.endpointsMap.get(selectedEndpoint);
      if (!endpointStat) {
        return null;
      }
      const endpointsMap = new Map<string, EndpointStat>();
      endpointsMap.set(selectedEndpoint, endpointStat);
      return {
        ...endpointStat,
        hasSuspiciousEvents: args.statInfo.hasSuspiciousEvents,
        endpointsMap,
      };
    }
    const stat: TreeEntryStat = {
      totalBytesSent: 0,
      totalBytesReceived: 0,
      hasSuspiciousEvents: args.statInfo.hasSuspiciousEvents,
      endpointsMap: new Map(),
    };
    args.statInfo.endpointsMap.forEach((endpointStat, endpoint) => {
      if (visibleEndpoints?.has(endpoint)) {
        stat.totalBytesSent += endpointStat.totalBytesSent;
        stat.totalBytesReceived += endpointStat.totalBytesReceived;
        stat.endpointsMap.set(endpoint, endpointStat);
      }
    });
    return stat;
  }, [args.statInfo, selectedEndpoint, visibleEndpoints]);

  const connectorEndpoints = useMemo(() => {
    if (selectedEndpoint) {
      const set = new Set<string>();
      set.add(selectedEndpoint);
      return set;
    }
    return visibleEndpoints;
  }, [selectedEndpoint, visibleEndpoints]);

  const className = useMemo(() => {
    return clsx("ipt-interactive", {
      "ipt-highlighted": visualState === VisualState.Highlighted || selectedEndpoint,
      "ipt-muted": visualState === VisualState.Muted,
      "ipt-endpoint-outer-dns": endpointKind === EndpointKind.OuterDns,
      "ipt-endpoint-k8s": endpointKind === EndpointKind.K8s,
    });
  }, [visualState, selectedEndpoint, endpointKind]);

  useEffect(() => {
    return state.onEndpointHighlight((endpoint, value) => {
      if (!value) {
        setSelectedEndpoint(null);
        setVisualState(VisualState.Base);
        return;
      }
      if (!visibleEndpoints?.has(endpoint)) {
        setSelectedEndpoint(null);
        setVisualState(VisualState.Muted);
        return;
      }
      setSelectedEndpoint(endpoint);
      setVisualState(VisualState.Highlighted);
    });
  }, [state, visibleEndpoints]);

  return useMemo(
    () => ({
      stat,
      connector,
      connectorEndpoints,
      className,
      hasConnections,
      endpoint: selectedEndpoint,
      endpointKind,
      setVisualState,
    }),
    [
      stat,
      connector,
      connectorEndpoints,
      className,
      hasConnections,
      selectedEndpoint,
      endpointKind,
    ],
  );
}
