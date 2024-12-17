import { memo, useCallback, useEffect, useRef } from "react";
import { useAppState } from "~/state/AppContext";
import { WH } from "~/types";

export interface Props {
  size: WH;
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

    state.connectionsMap.forEach((procs, endpoint) => {
      const endpointInfo = state.endpointsMap.get(endpoint);

      procs.forEach((proc) => {
        const procInfo = state.processesMap.get(proc);

        if (
          !procInfo?.xy ||
          !endpointInfo?.xy ||
          !procInfo?.visible ||
          !endpointInfo?.visible
        ) {
          return;
        }

        const x1 = procInfo.xy.x;
        const y1 = procInfo.xy.y;

        const x2 = endpointInfo.xy.x;
        const y2 = endpointInfo.xy.y;

        drawLine(ctx, x1, y1, x2, y2);
      });
    });
  }, []);

  useEffect(() => {
    if (!ref.current) return;

    ref.current.width = props.size.width;
    ref.current.height = props.size.height;

    draw();
  }, [draw, props.size]);

  useEffect(() => {
    return state.onRedrawConnectionsLines(draw);
  }, [draw]);

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
