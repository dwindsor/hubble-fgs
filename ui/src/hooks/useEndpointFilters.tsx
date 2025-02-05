import { useCallback, useMemo, useState } from "react";
import { useAppState } from "~/state/AppContext";
import {
  type Endpoint,
  EndpointFilterKind,
  EndpointKind,
  inferEndpointKind,
} from "~/utils/endpoints";
import { UrlParams, getQueryParam, setQueryParam } from "~/utils/url";

export interface EndpointFiltersState {
  value: Set<EndpointFilterKind>;
  toggle: (kind: EndpointFilterKind) => void;
  checkEndpointPassesFilters: (endpoint: Endpoint) => boolean;
}

export function useEndpointFilters() {
  const state = useAppState();

  const initialValue = state.persistInUrl
    ? (() => {
        const filters = new Set<EndpointFilterKind>();
        getQueryParam(UrlParams.EndpointFilters)
          ?.split(",")
          .forEach((filter) => {
            filters.add(filter as EndpointFilterKind);
          });
        return filters;
      })()
    : new Set<EndpointFilterKind>();

  const [endpointFilters, setEndpointFilters] = useState(initialValue);

  const toggle = useCallback(
    (kind: EndpointFilterKind) => {
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

function checkEndpointPassesFilters(filters: Set<EndpointFilterKind>, endpoint: Endpoint): boolean {
  if (filters.size === 0) {
    return true;
  }

  const kind = inferEndpointKind(endpoint);
  if (
    (kind === EndpointKind.OuterIp || kind === EndpointKind.OuterDns) &&
    filters.has(EndpointFilterKind.Outer)
  ) {
    return true;
  }

  if (
    (kind === EndpointKind.InnerIp || kind === EndpointKind.InnerDns) &&
    filters.has(EndpointFilterKind.Inner)
  ) {
    return true;
  }

  if (
    (kind === EndpointKind.Kube || kind === EndpointKind.HostMetadataService) &&
    filters.has(EndpointFilterKind.Kube)
  ) {
    return true;
  }

  if (kind === EndpointKind.Other && filters.has(EndpointFilterKind.Other)) {
    return true;
  }

  return false;
}
