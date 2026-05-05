import debounce from "lodash/debounce";
import React, { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useElementSize } from "~/hooks/useElementSize";
import { type EndpointFiltersState, useEndpointFilters } from "~/hooks/useEndpointFilters";
import { type AppState, useAppState } from "~/state/AppContext";
import { type Endpoint, EndpointModeKind, endpointsKindOrder } from "~/utils/endpoints";
import { Enum, type EnumType } from "~/utils/enum";
import { getQueryParam, setQueryParam, UrlParams } from "~/utils/url";
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
    const hasSearchOrVisible = endpoints.list.some(
      ({ kind }) => kind === EndpointItemKind.Search || kind === EndpointItemKind.Visible,
    );
    return (
      (searchQuery.length > 0 && !hasSearchOrVisible) ||
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
          const isSectionStart = !prev || prev.kind !== kind;
          const showHeader = isSectionStart && endpoints.sectionCount > 1;
          return (
            <React.Fragment key={endpointInfo?.hash ?? idx}>
              {prev && prev.kind !== kind && <hr />}
              {showHeader && <div className={css.sectionHeader}>{sectionTitle(kind)}</div>}
              <EndpointItem endpoint={endpoint} />
            </React.Fragment>
          );
        })}
        {isEmptySearchResult && (
          <div className={css.emptySearch}>
            {endpoints.list.length > 0 && <hr />}
            <div className={css.emptySearchTitle}>Entries not found</div>
          </div>
        )}
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

  const sectionCount = useMemo(() => {
    const kinds = new Set<EndpointItemKind>();
    for (const { kind } of list) {
      kinds.add(kind);
    }
    return kinds.size;
  }, [list]);

  return useMemo(() => ({ list, filters, sectionCount }), [list, filters, sectionCount]);
}

function sectionTitle(kind: EndpointItemKind): string {
  switch (kind) {
    case EndpointItemKind.Pinned:
      return "Pinned";
    case EndpointItemKind.Visible:
      return "From visible processes";
    case EndpointItemKind.Search:
      return "Search results";
  }
}

const EndpointItemKind = Enum({
  Pinned: "pinned",
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
  const pinnedEndpoints = new Set<Endpoint>();
  const visibleEndpoints = new Set<Endpoint>();
  const searchEndpoints = new Set<Endpoint>();

  const addEndpoint = (target: Set<Endpoint>, endpoint: Endpoint) => {
    if (filters.checkEndpointPassesFilters(endpoint)) {
      target.add(endpoint);
    }
  };

  state.highlightedEndpointsMap.forEach((modes, endpoint) => {
    if (modes.has(EndpointModeKind.Pinned)) {
      addEndpoint(pinnedEndpoints, endpoint);
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

  pinnedEndpoints.forEach((endpoint) => {
    visibleEndpoints.delete(endpoint);
    searchEndpoints.delete(endpoint);
  });

  visibleEndpoints.forEach((endpoint) => {
    searchEndpoints.delete(endpoint);
  });

  const sortedPinnedEndpoints = sortEndpoints(state, pinnedEndpoints);
  const sortedVisibleEndpoints = sortEndpoints(state, visibleEndpoints);
  const sortedSearchEndpoints = sortEndpoints(state, searchEndpoints);

  const list: EndpointsList = [];

  list.push(
    ...sortedPinnedEndpoints.map((endpoint) => ({
      kind: EndpointItemKind.Pinned,
      endpoint,
    })),
  );

  list.push(
    ...sortedVisibleEndpoints.map((endpoint) => ({
      kind: EndpointItemKind.Visible,
      endpoint,
    })),
  );

  list.push(
    ...sortedSearchEndpoints.map((endpoint) => ({
      kind: EndpointItemKind.Search,
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
