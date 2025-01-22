import { memo, useEffect, useMemo, useState } from "react";
import { AppState, useAppState } from "~/state/AppContext";
import { EndpointMode, endpointsKindOrder } from "~/utils/endpoints";
import { Endpoint } from "./Endpoint";
import debounce from "lodash/debounce";

export const Endpoints = memo(function Endpoints() {
  const endpoints = useEndpoints();

  return (
    <div>
      {endpoints.map((endpoint) => {
        return <Endpoint key={endpoint} endpoint={endpoint} />;
      })}
    </div>
  );
});

function useEndpoints() {
  const state = useAppState();

  console.log(state);

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
    return state.onToggleEndpoint(debouncedUpdate);
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

  return Array.from(endpoints).sort((a, b) => {
    const x = state.endpointsMap.get(a)!;
    const y = state.endpointsMap.get(b)!;

    if (x.kind !== y.kind) {
      return endpointsKindOrder[x.kind] - endpointsKindOrder[y.kind];
    }

    return a.localeCompare(b);
  });
}
