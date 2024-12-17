import { memo, useCallback, useEffect, useMemo, useRef } from "react";
import debounce from "lodash/debounce";
import { useAppState } from "~/state/AppContext";

import css from "./Endpoint.module.css";
import { useConnector } from "~/hooks/useConnector";

export interface Props {
  endpoint: string;
}

export const Endpoint = memo(function Endpoint(props: Props) {
  const connectorRef = useRef<HTMLDivElement>(null);

  const state = useAppState();

  const connector = useConnector(connectorRef);

  const debouncedUpdate = useMemo(() => {
    return debounce((visible = true) => {
      const cur = state.endpointsMap.get(props.endpoint);
      const xy = connector.getXY();

      if (
        cur &&
        cur.visible === visible &&
        cur.xy?.x === xy?.x &&
        cur.xy?.y === xy?.y
      ) {
        return;
      }

      state.updateEndpoint(props.endpoint, visible, xy);
    });
  }, [props.endpoint, connector]);

  useEffect(() => {
    debouncedUpdate(true);
    return () => debouncedUpdate(false);
  }, []);

  useEffect(() => state.onTreeSizeChanged(debouncedUpdate), [debouncedUpdate]);

  useEffect(() => state.onTreeChanged(debouncedUpdate), [debouncedUpdate]);

  return (
    <div className={css.endpoint}>
      <div ref={connectorRef} className={css.connector} />
      {props.endpoint}
    </div>
  );
});
