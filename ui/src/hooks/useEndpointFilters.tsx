import { useCallback, useMemo, useState } from "react";
import {
  type Endpoint,
  EndpointFilterKind,
  EndpointKind,
  inferEndpointKind,
} from "~/utils/endpoints";

export interface EndpointFiltersState {
  value: Set<EndpointFilterKind>;
  toggle: (kind: EndpointFilterKind) => void;
  checkEndpointPassesFilters: (endpoint: Endpoint) => boolean;
}

export function useEndpointFilters() {
  const [endpointFilters, setEndpointFilters] = useState(new Set<EndpointFilterKind>());

  const toggle = useCallback((kind: EndpointFilterKind) => {
    setEndpointFilters((prev) => {
      const cloned = new Set(prev);
      if (cloned.has(kind)) {
        cloned.delete(kind);
      } else {
        cloned.add(kind);
      }
      return cloned;
    });
  }, []);

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
