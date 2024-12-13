import { memo, useCallback, useEffect, useRef } from "react";
import { useAppState } from "~/state/AppContext";

import css from "./Endpoint.module.css";

export interface Props {
  endpoint: string;
}

export const Endpoint = memo(function Endpoint(props: Props) {
  const connectorRef = useRef<HTMLDivElement>(null);

  const state = useAppState();

  const getConnectorXY = useCallback(() => {
    if (!connectorRef.current) return;
    const box = connectorRef.current.getBoundingClientRect();
    return { x: box.x + 2.5, y: box.y + 2.5 + state.getTreeOffset() };
  }, [connectorRef]);

  const updateEndpoint = useCallback(() => {
    const xy = getConnectorXY();
    if (!xy) return;
    state.updateEndpoint(props.endpoint, xy);
  }, [props.endpoint, getConnectorXY]);

  useEffect(() => {
    return state.onTreeSizeChanged(updateEndpoint);
  }, [updateEndpoint]);

  return (
    <div className={css.endpoint}>
      <div ref={connectorRef} className={css.connector} />
      {props.endpoint}
    </div>
  );
});
