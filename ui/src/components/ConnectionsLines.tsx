import debounce from "lodash/debounce";
import { memo, useCallback, useEffect, useMemo, useRef } from "react";
import { useAppState } from "~/state/AppContext";
import { Connection, WH } from "~/types";

export interface Props {
  size: WH;
  connections: Connection[];
}

export const ConnectionsLines = memo(function ConnectionsLines(props: Props) {
  const state = useAppState();

  const ref = useRef<HTMLCanvasElement>(null);

  const draw = useCallback(() => {
    const canvas = ref.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    props.connections.forEach((connection) => {
      const proc = state.processesMap.get(connection.proc);
      const endpoint = state.endpointsMap.get(connection.endpoint);

      if (!proc?.xy || !endpoint?.xy || !proc?.visible) {
        return;
      }

      const x1 = proc.xy.x;
      const y1 = proc.xy.y;

      const x2 = endpoint.xy.x;
      const y2 = endpoint.xy.y;

      drawLine(ctx, x1, y1, x2, y2);
    });
  }, [props.connections]);

  const debouncedDraw = useMemo(() => debounce(draw, 16), [draw]);

  useEffect(() => {
    if (!ref.current) return;

    ref.current.width = props.size.width;
    ref.current.height = props.size.height;

    debouncedDraw();
  }, [debouncedDraw, props.size]);

  useEffect(() => {
    return state.onRedrawConnectionsLines(debouncedDraw);
  }, [debouncedDraw]);

  return <canvas ref={ref} />;
});

function drawLine(
  ctx: CanvasRenderingContext2D,
  x1: number,
  y1: number,
  x2: number,
  y2: number
) {
  ctx.beginPath();
  ctx.strokeStyle = "#666";
  ctx.moveTo(x1, y1);
  ctx.bezierCurveTo(x2 - 100, y1, x2 - 100, y2, x2, y2);
  ctx.stroke();
  ctx.closePath();
}
