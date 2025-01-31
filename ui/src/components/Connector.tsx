import clsx from "clsx";
import { memo, useMemo } from "react";
import type { useConnector } from "~/hooks/useConnector";
import { useAppState } from "~/state/AppContext";
import { type Endpoint, EndpointKind, endpointsKindOrder } from "~/utils/endpoints";
import css from "./Connector.module.css";

export interface Props {
  endpoints: Set<Endpoint> | undefined;
  connector?: ReturnType<typeof useConnector>;
}

const CLASS_NAMES = {
  [EndpointKind.OuterIp]: css.entityOuter,
  [EndpointKind.OuterDns]: css.entityOuter,
  [EndpointKind.Kube]: css.entityKube,
  [EndpointKind.HostMetadataService]: css.entityKube,
} as { [key: string]: string };

export const Connector = memo(function Connector(props: Props) {
  const state = useAppState();

  const classNames = useMemo(() => {
    if (!props.endpoints) {
      return [];
    }
    const sorted = Array.from(props.endpoints).sort((a, b) => {
      const x = state.endpointsMap.get(a)?.kind ?? EndpointKind.Other;
      const y = state.endpointsMap.get(b)?.kind ?? EndpointKind.Other;
      return endpointsKindOrder[x] - endpointsKindOrder[y];
    });
    const classNames = new Set<string>();
    sorted.forEach((endpoint) => {
      const kind = state.endpointsMap.get(endpoint)?.kind ?? EndpointKind.Other;
      classNames.add(CLASS_NAMES[kind] ?? "");
    });
    return Array.from(classNames);
  }, [state, props.endpoints]);

  return (
    <div ref={props.connector?.ref} className={css.connector}>
      {classNames.map((className) => {
        return <div key={className} className={clsx(css.part, className)} />;
      })}
    </div>
  );
});
