import debounce from "lodash/debounce";
import { memo, useCallback, useEffect, useMemo, useState } from "react";
import { AppState, useAppState } from "~/state/AppContext";
import { EndpointMode, endpointsKindOrder } from "~/utils/endpoints";
import { Endpoint } from "./Endpoint";
import css from "./Endpoints.module.css";

export const Endpoints = memo(function Endpoints() {
  const state = useAppState();

  const endpoints = useEndpoints();

  const [searchQuery, setSearchQuery] = useState("");
  const [foundEndpoints, setFoundEndpoints] = useState<string[]>([]);

  useEffect(() => {
    if (searchQuery.length < 3) {
      setFoundEndpoints([]);
      return;
    }

    const currentEndpointsSet = new Set(endpoints);
    const foundEndpoints = new Set<string>();
    for (const endpoint of state.endpointsMap.keys()) {
      if (
        !currentEndpointsSet.has(endpoint) &&
        endpoint.includes(searchQuery)
      ) {
        foundEndpoints.add(endpoint);
      }
    }
    setFoundEndpoints(sortEndpoints(state, foundEndpoints));
  }, [searchQuery, endpoints]);

  const onSearch = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(e.target.value);
  }, []);

  return (
    <div>
      <div className={css.search}>
        <input
          value={searchQuery}
          onChange={onSearch}
          placeholder="Search endpoint..."
        />
      </div>
      {!!foundEndpoints.length && (
        <div className={css.searchResults}>
          {foundEndpoints.map((endpoint) => {
            return (
              <Endpoint key={endpoint} ephimeral={true} endpoint={endpoint} />
            );
          })}
        </div>
      )}
      {!!endpoints.length && (
        <div className={css.endpointsList}>
          {endpoints.map((endpoint) => {
            return <Endpoint key={endpoint} endpoint={endpoint} />;
          })}
        </div>
      )}
    </div>
  );
});

function useEndpoints() {
  const state = useAppState();

  const [endpoints, setEndpoints] = useState<string[]>(createEndpoints(state));

  const debouncedUpdate = useMemo(() => {
    return debounce(() => {
      setEndpoints(createEndpoints(state));
    });
  }, []);

  useEffect(() => {
    return state.onTreeChanged(debouncedUpdate);
  }, [debouncedUpdate]);

  useEffect(() => {
    return state.onEndpointHighlight(debouncedUpdate);
  }, [debouncedUpdate]);

  useEffect(() => {
    return state.onEndpointUpdated(debouncedUpdate);
  }, [debouncedUpdate]);

  return endpoints;
}

function createEndpoints(state: AppState): string[] {
  const endpoints = new Set<string>();

  state.highlightedEndpointsMap.forEach((modes, endpoint) => {
    if (modes.has(EndpointMode.Pinned)) {
      endpoints.add(endpoint);
    }
  });

  for (const endpoint of state.endpointsMap.keys()) {
    const procs = state.connectionsMap.get(endpoint);
    procs?.forEach((proc) => {
      const procInfo = state.processesMap.get(proc);
      if (procInfo?.visible) {
        endpoints.add(endpoint);
      }
    });
  }

  return sortEndpoints(state, endpoints);
}

function sortEndpoints(state: AppState, endpoints: Set<string>): string[] {
  return Array.from(endpoints).sort((a, b) => {
    const x = state.endpointsMap.get(a)!;
    const y = state.endpointsMap.get(b)!;

    if (x.kind !== y.kind) {
      return endpointsKindOrder[x.kind] - endpointsKindOrder[y.kind];
    }

    return a.localeCompare(b);
  });
}
