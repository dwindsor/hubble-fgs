import clsx from "clsx";
import { memo, useMemo } from "react";
import type { useConnector } from "~/hooks/useConnector";
import { FileEventKind } from "~/proto";
import { useAppState } from "~/state/AppContext";
import { DestinationKind } from "~/utils/destination";
import { type Endpoint, endpointsKindOrder } from "~/utils/endpoints";
import css from "./Connector.module.css";

export interface Props {
  endpoints: Set<Endpoint> | undefined;
  connector?: ReturnType<typeof useConnector>;
}

const CLASS_NAMES = {
  [DestinationKind.ExternalIp]: css.entityDestinationExternal,
  [DestinationKind.ExternalDns]: css.entityDestinationExternal,
  [DestinationKind.Kubernetes]: css.entityDestinationKubernetes,
  [DestinationKind.HostMetadataService]: css.entityDestinationKubernetes,
  [FileEventKind.Read]: css.entityFileEventRead,
  [FileEventKind.Write]: css.entityFileEventWrite,
} as { [key: string]: string };

export const Connector = memo(function Connector(props: Props) {
  const state = useAppState();

  const classNames = useMemo(() => {
    if (!props.endpoints) {
      return [];
    }
    const sorted = Array.from(props.endpoints).sort((a, b) => {
      const x = state.endpointsMap.get(a)?.subKind ?? DestinationKind.Other;
      const y = state.endpointsMap.get(b)?.subKind ?? DestinationKind.Other;
      return endpointsKindOrder[x] - endpointsKindOrder[y];
    });
    const classNames = new Set<string>();
    sorted.forEach((endpoint) => {
      const subKind = state.endpointsMap.get(endpoint)?.subKind ?? DestinationKind.Other;
      classNames.add(CLASS_NAMES[subKind] ?? "");
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
