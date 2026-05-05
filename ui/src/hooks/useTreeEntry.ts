import clsx from "clsx";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useAppState } from "~/state/AppContext";
import { DestinationKind } from "~/utils/destination";
import type { Endpoint } from "~/utils/endpoints";
import { Enum, type EnumType } from "~/utils/enum";
import { advanceStat, createTreeEntryStat, type Stat, type TreeEntryStat } from "~/utils/stat";
import { useConnector } from "./useConnector";

export const VisualStateKind = Enum({
  Base: "base",
  Highlighted: "highlighted",
  Muted: "muted",
});

export type VisualStateKind = EnumType<typeof VisualStateKind>;

export function useTreeEntry(args: { statInfo: TreeEntryStat | undefined }) {
  const state = useAppState();

  const connector = useConnector();

  const [selectedEndpoint, setSelectedEndpoint] = useState<Endpoint | null>(null);

  const [visualState, setVisualState] = useState<VisualStateKind>(VisualStateKind.Base);

  const getVisibleEndpoints = useCallback(() => {
    const entryEndpoints = new Set(args.statInfo?.endpointsMap.keys());
    if (entryEndpoints.size === 0) {
      return undefined;
    }
    const visibleEndpoints = new Set<Endpoint>();
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

  const endpointSubKind = useMemo(() => {
    if (!selectedEndpoint) {
      return null;
    }
    return state.endpointsMap.get(selectedEndpoint)?.subKind ?? null;
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
      const endpointsMap = new Map<Endpoint, Stat>();
      endpointsMap.set(selectedEndpoint, endpointStat);
      return {
        ...endpointStat,
        hasSuspiciousProcs: args.statInfo.hasSuspiciousProcs,
        endpointsMap,
      };
    }
    const stat = createTreeEntryStat({
      hasSuspiciousProcs: args.statInfo.hasSuspiciousProcs,
    });
    args.statInfo.endpointsMap.forEach((endpointStat, endpoint) => {
      if (visibleEndpoints?.has(endpoint)) {
        advanceStat(stat, endpointStat);
        stat.endpointsMap.set(endpoint, endpointStat);
      }
    });
    return stat;
  }, [args.statInfo, selectedEndpoint, visibleEndpoints]);

  const connectorEndpoints = useMemo(() => {
    if (selectedEndpoint) {
      const set = new Set<Endpoint>();
      set.add(selectedEndpoint);
      return set;
    }
    return visibleEndpoints;
  }, [selectedEndpoint, visibleEndpoints]);

  const className = useMemo(() => {
    return clsx("ipt-interactive", {
      "ipt-highlighted": visualState === VisualStateKind.Highlighted || selectedEndpoint,
      "ipt-muted": visualState === VisualStateKind.Muted,
      "ipt-endpoint-external": endpointSubKind === DestinationKind.ExternalDns,
      "ipt-endpoint-kube": endpointSubKind === DestinationKind.Kubernetes,
    });
  }, [visualState, selectedEndpoint, endpointSubKind]);

  useEffect(() => {
    return state.onEndpointHighlight((endpoint, value) => {
      if (!value) {
        setSelectedEndpoint(null);
        setVisualState(VisualStateKind.Base);
        return;
      }
      if (!visibleEndpoints?.has(endpoint)) {
        setSelectedEndpoint(null);
        setVisualState(VisualStateKind.Muted);
        return;
      }
      setSelectedEndpoint(endpoint);
      setVisualState(VisualStateKind.Highlighted);
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
      endpointSubKind,
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
      endpointSubKind,
    ],
  );
}
