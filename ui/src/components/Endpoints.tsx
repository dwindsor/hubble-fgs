import debounce from "lodash/debounce";
import React, { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useElementSize } from "~/hooks/useElementSize";
import { type EndpointFiltersState, useEndpointFilters } from "~/hooks/useEndpointFilters";
import { type AppState, useAppState } from "~/state/AppContext";
import { type Endpoint, EndpointModeKind, endpointsKindOrder } from "~/utils/endpoints";
import { Enum, type EnumType } from "~/utils/enum";
import { EndpointItem } from "./Endpoint";
import { EndpointFilters } from "./EndpointFilters";
import css from "./Endpoints.module.css";

export const Endpoints = memo(function Endpoints() {
  const state = useAppState();

  const ref = useRef<HTMLDivElement>(null);

  const size = useElementSize(ref);

  const [searchQuery, setSearchQuery] = useState("");

  const endpointFilters = useEndpointFilters();

  const endpoints = useEndpoints(searchQuery, endpointFilters);

  // biome-ignore lint/correctness/useExhaustiveDependencies: notify endpoints list change because it's size was changed
  useEffect(() => {
    state.changeEndpointsList();
  }, [state, size]);

  const onSearch = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(e.target.value);
  }, []);

  const onEndpointSelect = useCallback(() => {
    setSearchQuery("");
  }, []);

  const isEmptySearchResult = useMemo(() => {
    return (
      (searchQuery.length >= 3 && endpoints[0]?.kind !== EndpointItemKind.Search) ||
      (endpointFilters.value.size > 0 && endpoints.length === 0)
    );
  }, [searchQuery, endpoints, endpointFilters]);

  return (
    <div>
      <div className={css.header}>
        <div className={css.search}>
          <input value={searchQuery} onChange={onSearch} placeholder="Search endpoint..." />
        </div>
        <div className={css.filters}>
          <EndpointFilters filters={endpointFilters} />
        </div>
      </div>
      <div ref={ref} className={css.endpointsList}>
        {isEmptySearchResult && (
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
              <EndpointItem endpoint={endpoint} onSelect={onEndpointSelect} />
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
});

function useEndpoints(searchQuery: string, endpointFilters: EndpointFiltersState) {
  const state = useAppState();

  const [endpoints, setEndpoints] = useState<EndpointsList>(
    createEndpoints(state, searchQuery, endpointFilters),
  );

  const debouncedUpdate = useMemo(() => {
    return debounce(() => {
      setEndpoints(createEndpoints(state, searchQuery, endpointFilters));
    });
  }, [state, searchQuery, endpointFilters]);

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
      if (mode === EndpointModeKind.Pinned) {
        debouncedUpdate();
      }
    });
  }, [state, debouncedUpdate]);

  return endpoints;
}

const EndpointItemKind = Enum({
  Search: "search",
  Visible: "visible",
});

type EndpointItemKind = EnumType<typeof EndpointItemKind>;

type EndpointsList = Array<{ kind: EndpointItemKind; endpoint: Endpoint }>;

function createEndpoints(
  state: AppState,
  searchQuery: string,
  endpointFilters: EndpointFiltersState,
): EndpointsList {
  const visibleEndpoints = new Set<Endpoint>();
  const searchEndpoints = new Set<Endpoint>();

  const addEndpoint = (target: Set<Endpoint>, endpoint: Endpoint) => {
    if (endpointFilters.checkEndpointPassesFilters(endpoint)) {
      target.add(endpoint);
    }
  };

  state.highlightedEndpointsMap.forEach((modes, endpoint) => {
    if (modes.has(EndpointModeKind.Pinned)) {
      addEndpoint(visibleEndpoints, endpoint);
    }
  });

  for (const endpoint of state.endpointsMap.keys()) {
    if (searchQuery.length >= 3 && endpoint.includes(searchQuery)) {
      addEndpoint(searchEndpoints, endpoint);
    }

    const procs = state.connectionsMap.get(endpoint);
    procs?.forEach((proc) => {
      const procInfo = state.processesMap.get(proc);
      if (procInfo?.visible) {
        addEndpoint(visibleEndpoints, endpoint);
      }
    });
  }

  visibleEndpoints.forEach((endpoint) => {
    searchEndpoints.delete(endpoint);
  });

  const sortedUVisibleEndpoints = sortEndpoints(state, visibleEndpoints);
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

function sortEndpoints(state: AppState, endpoints: Set<Endpoint>): Endpoint[] {
  return Array.from(endpoints).sort((a, b) => {
    const x = state.endpointsMap.get(a);
    const y = state.endpointsMap.get(b);

    if (x && y && x?.kind !== y?.kind) {
      return endpointsKindOrder[x.kind] - endpointsKindOrder[y.kind];
    }

    return a.localeCompare(b);
  });
}
