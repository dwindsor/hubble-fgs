import { memo, useEffect, useState } from "react";
import { Endpoint } from "./Endpoint";
import { AppState, useAppState } from "~/state/AppContext";

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

  const [endpoints, setEndpoints] = useState<string[]>(createEndpoints(state));

  useEffect(() => {
    return state.onRedrawConnectionsLines(() => {
      setEndpoints(createEndpoints(state));
      state.changeTree();
    });
  }, []);

  return endpoints;
}

function createEndpoints(state: AppState): string[] {
  const endpoints = new Set<string>();

  for (const endpoint of state.endpointsMap.keys()) {
    const procs = state.connectionsMap.get(endpoint);
    procs?.forEach((proc) => {
      const procInfo = state.processesMap.get(proc);
      if (procInfo?.visible) {
        endpoints.add(endpoint);
      }
    });
  }

  return Array.from(endpoints).sort((a, b) => a.localeCompare(b));
}
