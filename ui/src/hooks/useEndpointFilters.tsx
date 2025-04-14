import { useCallback, useMemo, useState } from "react";
import { FileEventKind } from "~/proto";
import { useAppState } from "~/state/AppContext";
import { DestinationFilterKind, DestinationKind } from "~/utils/destination";
import { type Endpoint, EndpointKind, inferEndpointSubKind } from "~/utils/endpoints";
import { FileEventFilterKind } from "~/utils/file-event";
import { UrlParams, getQueryParam, setQueryParam } from "~/utils/url";

export type FilterKind = DestinationFilterKind | FileEventFilterKind;

export interface EndpointFiltersState {
  value: Set<FilterKind>;
  toggle: (kind: FilterKind) => void;
  checkEndpointPassesFilters: (endpoint: Endpoint) => boolean;
}

export function useEndpointFilters() {
  const state = useAppState();

  const initialValue = state.persistInUrl
    ? (() => {
        const filters = new Set<FilterKind>();
        getQueryParam(UrlParams.EndpointFilters)
          ?.split(",")
          .forEach((filter) => {
            filters.add(filter as FilterKind);
          });
        return filters;
      })()
    : new Set<FilterKind>();

  const [endpointFilters, setEndpointFilters] = useState(initialValue);

  const toggle = useCallback(
    (kind: FilterKind) => {
      setEndpointFilters((prev) => {
        const cloned = new Set(prev);
        if (cloned.has(kind)) {
          cloned.delete(kind);
        } else {
          cloned.add(kind);
        }

        if (state.persistInUrl) {
          const value = [...cloned].sort().join(",");
          if (value) {
            setQueryParam(UrlParams.EndpointFilters, value);
          } else {
            setQueryParam(UrlParams.EndpointFilters, undefined);
          }
        }
        return cloned;
      });
    },
    [state.persistInUrl],
  );

  return useMemo((): EndpointFiltersState => {
    return {
      value: endpointFilters,
      toggle,
      checkEndpointPassesFilters(endpoint) {
        return checkEndpointPassesFilters(endpointFilters, endpoint);
      },
    };
  }, [endpointFilters, toggle]);
}

function checkEndpointPassesFilters(filters: Set<FilterKind>, endpoint: Endpoint): boolean {
  if (filters.size === 0) {
    return true;
  }

  if ("port" in endpoint) {
    const subKind = inferEndpointSubKind(endpoint, EndpointKind.Destination);
    if (
      (subKind === DestinationKind.OuterIp || subKind === DestinationKind.OuterDns) &&
      filters.has(DestinationFilterKind.Outer)
    ) {
      return true;
    }

    if (
      (subKind === DestinationKind.InnerIp || subKind === DestinationKind.InnerDns) &&
      filters.has(DestinationFilterKind.Inner)
    ) {
      return true;
    }

    if (
      (subKind === DestinationKind.Kubernetes || subKind === DestinationKind.HostMetadataService) &&
      filters.has(DestinationFilterKind.Kubernetes)
    ) {
      return true;
    }

    if (subKind === DestinationKind.Other && filters.has(DestinationFilterKind.Other)) {
      return true;
    }
  } else {
    const subKind = inferEndpointSubKind(endpoint, EndpointKind.FileEvent);

    if (subKind === FileEventKind.Read && filters.has(FileEventFilterKind.Read)) {
      return true;
    }

    if (subKind === FileEventKind.Write && filters.has(FileEventFilterKind.Write)) {
      return true;
    }
  }

  return false;
}
