import debounce from "lodash/debounce";
import React, { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useElementSize } from "~/hooks/useElementSize";
import { type EndpointFiltersState, useEndpointFilters } from "~/hooks/useEndpointFilters";
import { type AppState, useAppState } from "~/state/AppContext";
import { type Endpoint, EndpointModeKind, endpointsKindOrder } from "~/utils/endpoints";
import { Enum, type EnumType } from "~/utils/enum";
import { UrlParams, getQueryParam, setQueryParam } from "~/utils/url";
import { EndpointItem } from "./Endpoint";
import { EndpointFilters } from "./EndpointFilters";
import css from "./Endpoints.module.css";

export const Endpoints = memo(function Endpoints() {
  const state = useAppState();

  const ref = useRef<HTMLDivElement>(null);

  const size = useElementSize(ref);

  const [searchQuery, setSearchQuery] = useState(getQueryParam(UrlParams.SearchQuery) ?? "");

  const endpoints = useEndpoints(searchQuery);

  // biome-ignore lint/correctness/useExhaustiveDependencies: notify endpoints list change because it's size was changed
  useEffect(() => {
    state.changeEndpointsList();
  }, [state, size]);

  const onSearch = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setSearchQuery(e.target.value);
      if (state.persistInUrl) {
        if (e.target.value.length) {
          setQueryParam(UrlParams.SearchQuery, e.target.value);
        } else {
          setQueryParam(UrlParams.SearchQuery, undefined);
        }
      }
    },
    [state.persistInUrl],
  );

  const isEmptySearchResult = useMemo(() => {
    return (
      (searchQuery.length > 0 && endpoints.list[0]?.kind !== EndpointItemKind.Search) ||
      (endpoints.filters.value.size > 0 && endpoints.list.length === 0)
    );
  }, [searchQuery, endpoints]);

  const isNotShowingEndpoints = useMemo(() => {
    return (
      endpoints.list.length === 0 && endpoints.filters.value.size === 0 && searchQuery.length === 0
    );
  }, [searchQuery, endpoints]);

  return (
    <div>
      <div className={css.header}>
        <div className={css.filters}>
          <EndpointFilters filters={endpoints.filters} />
        </div>
        <div className={css.search}>
          <input
            type="search"
            value={searchQuery}
            onChange={onSearch}
            placeholder="Search for network connections..."
          />
        </div>
      </div>
      <div ref={ref} className={css.endpointsList}>
        {isEmptySearchResult && (
          <div className={css.emptySearch}>
            <div className={css.emptySearchTitle}>Entries not found</div>
            <hr />
          </div>
        )}
        {isNotShowingEndpoints && (
          <div className={css.noEndpoints}>
            <div className={css.noEndpointsTitle}>
              Open the processes tree or use filters/search to see entries
            </div>
          </div>
        )}
        {endpoints.list.map(({ kind, endpoint }, idx) => {
          const endpointInfo = state.endpointsMap.get(endpoint);
          const prev = endpoints.list[idx - 1];
          return (
            <React.Fragment key={endpointInfo?.hash ?? idx}>
              {prev && prev.kind !== kind && <hr />}
              <EndpointItem endpoint={endpoint} />
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
});

function useEndpoints(searchQuery: string) {
  const state = useAppState();

  const filters = useEndpointFilters();

  const [list, setList] = useState<EndpointsList>(createEndpointsList(state, searchQuery, filters));

  const debouncedUpdate = useMemo(() => {
    return debounce(() => {
      setList(createEndpointsList(state, searchQuery, filters));
    });
  }, [state, searchQuery, filters]);

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

  return useMemo(() => ({ list, filters }), [list, filters]);
}

const EndpointItemKind = Enum({
  Search: "search",
  Visible: "visible",
});

type EndpointItemKind = EnumType<typeof EndpointItemKind>;

type EndpointsList = Array<{ kind: EndpointItemKind; endpoint: Endpoint }>;

function createEndpointsList(
  state: AppState,
  query: string,
  filters: EndpointFiltersState,
): EndpointsList {
  const visibleEndpoints = new Set<Endpoint>();
  const searchEndpoints = new Set<Endpoint>();

  const addEndpoint = (target: Set<Endpoint>, endpoint: Endpoint) => {
    if (filters.checkEndpointPassesFilters(endpoint)) {
      target.add(endpoint);
    }
  };

  state.highlightedEndpointsMap.forEach((modes, endpoint) => {
    if (modes.has(EndpointModeKind.Pinned)) {
      addEndpoint(visibleEndpoints, endpoint);
    }
  });

  for (const [endpointHash, endpoint] of state.endpointsHashMap.entries()) {
    if (query.length > 0 && endpointHash.includes(query)) {
      addEndpoint(searchEndpoints, endpoint);
    }

    const procs = state.connectionsMap.get(endpoint);
    procs?.forEach((proc) => {
      const procInfo = state.processesMap.get(proc);
      if (query.length === 0 || (query.length > 0 && endpointHash.includes(query))) {
        if (procInfo?.visible) {
          addEndpoint(visibleEndpoints, endpoint);
        } else if (filters.value.size > 0) {
          addEndpoint(searchEndpoints, endpoint);
        }
      }
    });
  }

  visibleEndpoints.forEach((endpoint) => {
    searchEndpoints.delete(endpoint);
  });

  const sortedVisibleEndpoints = sortEndpoints(state, visibleEndpoints);
  const sortedSearchEndpoints = sortEndpoints(state, searchEndpoints);

  const list: EndpointsList = [];

  list.push(
    ...sortedSearchEndpoints.map((endpoint) => ({
      kind: EndpointItemKind.Search,
      endpoint,
    })),
  );

  list.push(
    ...sortedVisibleEndpoints.map((endpoint) => ({
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

    if (x && y && x?.subKind !== y?.subKind) {
      return endpointsKindOrder[x.subKind] - endpointsKindOrder[y.subKind];
    }

    return x?.hash.localeCompare(y?.hash ?? "") ?? 0;
  });
}
