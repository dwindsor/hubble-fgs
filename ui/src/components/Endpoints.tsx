import { memo, useEffect, useState } from "react";
import { Endpoint } from "./Endpoint";
import { AppState, useAppState } from "~/state/AppContext";
import { EndpointKind } from "~/types";

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

  const order = [
    EndpointKind.OuterDns,
    EndpointKind.K8s,
    EndpointKind.HostMetadataService,
    EndpointKind.Ip,
    EndpointKind.InnerDns,
  ].reduce((acc, item, idx) => {
    acc[item] = idx;
    return acc;
  }, {} as { [key in EndpointKind]: number });

  return Array.from(endpoints).sort((a, b) => {
    const x = state.endpointsMap.get(a)!;
    const y = state.endpointsMap.get(b)!;

    if (x.kind !== y.kind) {
      return order[x.kind] - order[y.kind];
    }

    return a.localeCompare(b);
  });
}
