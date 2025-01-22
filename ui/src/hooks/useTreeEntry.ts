import clsx from "clsx";
import { useEffect, useMemo, useState } from "react";
import { useAppState } from "~/state/AppContext";
import { Stat, TreeEntryStat } from "~/state/utils";
import { EndpointKind, PropertyValues } from "~/types";
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

  const [visualState, setVisualState] = useState<VisualStateType>(
    VisualState.Base
  );

  const getVisibleEndpoints = () => {
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
  };

  const [endpoints, setEndpoints] = useState(getVisibleEndpoints());
  useEffect(() => {
    return state.onEndpointUpdated(() => {
      setEndpoints(getVisibleEndpoints());
    });
  }, []);

  const endpointKind = useMemo(() => {
    if (!selectedEndpoint) {
      return null;
    }
    return state.endpointsMap.get(selectedEndpoint)?.kind ?? null;
  }, [selectedEndpoint]);

  const hasConnections = useMemo(() => {
    return !!endpoints?.size;
  }, [endpoints]);

  const stat = useMemo((): Stat | null => {
    if (!args.statInfo) {
      return null;
    }
    if (!selectedEndpoint) {
      return args.statInfo ?? null;
    }
    return args.statInfo.endpointsMap.get(selectedEndpoint) ?? null;
  }, [args.statInfo, selectedEndpoint]);

  const connectorEndpoints = useMemo(() => {
    if (selectedEndpoint) {
      const set = new Set<string>();
      set.add(selectedEndpoint);
      return set;
    }
    return endpoints;
  }, [selectedEndpoint, endpoints]);

  const className = useMemo(() => {
    return clsx("ipt-interactive", {
      "ipt-highlighted":
        visualState === VisualState.Highlighted || selectedEndpoint,
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
      if (!endpoints?.has(endpoint)) {
        setSelectedEndpoint(null);
        setVisualState(VisualState.Muted);
        return;
      }
      setSelectedEndpoint(endpoint);
      setVisualState(VisualState.Highlighted);
    });
  }, [endpoints]);

  return {
    stat,
    connector,
    connectorEndpoints,
    className,
    hasConnections,
    endpoint: selectedEndpoint,
    endpointKind,
    setVisualState,
  };
}
