import debounce from "lodash/debounce";
import React, { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useElementSize } from "~/hooks/useElementSize";
import { type AppState, useAppState } from "~/state/AppContext";
import type { PropertyValues } from "~/types";
import { EndpointMode, endpointsKindOrder } from "~/utils/endpoints";
import { Endpoint } from "./Endpoint";
import css from "./Endpoints.module.css";

export const Endpoints = memo(function Endpoints() {
  const state = useAppState();

  const ref = useRef<HTMLDivElement>(null);

  const size = useElementSize(ref);

  // biome-ignore lint/correctness/useExhaustiveDependencies: notify geometry change because size was changed
  useEffect(() => {
    state.changeEndpointsList();
  }, [state, size]);

  const [searchQuery, setSearchQuery] = useState("");

  const endpoints = useEndpoints(searchQuery);

  const onSearch = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(e.target.value);
  }, []);

  const onEndpointSelect = useCallback(() => {
    setSearchQuery("");
  }, []);

  const isEmptySearch = useMemo(() => {
    return searchQuery.length >= 3 && endpoints[0]?.kind !== EndpointItemKind.Search;
  }, [searchQuery, endpoints]);

  return (
    <div>
      <div className={css.search}>
        <input value={searchQuery} onChange={onSearch} placeholder="Search endpoint..." />
      </div>
      <div ref={ref} className={css.endpointsList}>
        {isEmptySearch && (
          <div className={css.emptySearch}>
            <div className={css.emptySearchTitle}>Endpoints not found</div>
            <hr />
          </div>
        )}
        {endpoints.map(({ kind, endpoint }, idx) => {
          const prev = endpoints[idx - 1];
          return (
            <React.Fragment key={endpoint}>
              {prev && prev.kind !== kind && <hr />}
              <Endpoint endpoint={endpoint} onSelect={onEndpointSelect} />
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
});

function useEndpoints(searchQuery: string) {
  const state = useAppState();

  const [endpoints, setEndpoints] = useState<EndpointsList>(createEndpoints(state, searchQuery));

  const debouncedUpdate = useMemo(() => {
    return debounce(() => {
      setEndpoints(createEndpoints(state, searchQuery));
    });
  }, [state, searchQuery]);

  useEffect(() => {
    return debouncedUpdate();
  }, [debouncedUpdate]);

  useEffect(() => {
    return state.onProcUpdated(() => {
      debouncedUpdate();
    });
  }, [state, debouncedUpdate]);

  useEffect(() => {
    return state.onEndpointHighlight((_endpoint, _state, mode) => {
      if (mode === EndpointMode.Pinned) {
        debouncedUpdate();
      }
    });
  }, [state, debouncedUpdate]);

  return endpoints;
}

const EndpointItemKind = {
  __proto__: null,
  Search: "search",
  Visible: "visible",
} as const;

type EndpointItemKindType = PropertyValues<typeof EndpointItemKind>;

type EndpointsList = Array<{ kind: EndpointItemKindType; endpoint: string }>;

function createEndpoints(state: AppState, searchQuery: string): EndpointsList {
  const visibleEndpoint = new Set<string>();
  const searchEndpoints = new Set<string>();

  state.highlightedEndpointsMap.forEach((modes, endpoint) => {
    if (modes.has(EndpointMode.Pinned)) {
      visibleEndpoint.add(endpoint);
    }
  });

  for (const endpoint of state.endpointsMap.keys()) {
    if (searchQuery.length >= 3 && endpoint.includes(searchQuery)) {
      searchEndpoints.add(endpoint);
    }

    const procs = state.connectionsMap.get(endpoint);
    procs?.forEach((proc) => {
      const procInfo = state.processesMap.get(proc);
      if (procInfo?.visible) {
        visibleEndpoint.add(endpoint);
      }
    });
  }

  visibleEndpoint.forEach((endpoint) => {
    searchEndpoints.delete(endpoint);
  });

  const sortedUVisibleEndpoints = sortEndpoints(state, visibleEndpoint);
  const sortedSearchEndpoints = sortEndpoints(state, searchEndpoints);

  const list: EndpointsList = [];

  list.push(
    ...sortedSearchEndpoints.map((endpoint) => ({
      kind: EndpointItemKind.Search,
      endpoint,
    })),
  );

  list.push(
    ...sortedUVisibleEndpoints.map((endpoint) => ({
      kind: EndpointItemKind.Visible,
      endpoint,
    })),
  );

  return list;
}

function sortEndpoints(state: AppState, endpoints: Set<string>): string[] {
  return Array.from(endpoints).sort((a, b) => {
    const x = state.endpointsMap.get(a);
    const y = state.endpointsMap.get(b);

    if (x && y && x?.kind !== y?.kind) {
      return endpointsKindOrder[x.kind] - endpointsKindOrder[y.kind];
    }

    return a.localeCompare(b);
  });
}
