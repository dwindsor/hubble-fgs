import { memo, useCallback, useEffect, useRef } from "react";
import { useAppState } from "~/state/AppContext";
import { ConnectionLine, Connector, EndpointKind, Line, WH, XY } from "~/types";

export interface Props {
  size: WH;
}

const BASE_LINE_COLOR = {
  [EndpointKind.OuterDns]: "#9e83df",
  [EndpointKind.K8s]: "#78bbe8",
  [EndpointKind.HostMetadataService]: "#ccc",
  [EndpointKind.Ip]: "#ccc",
  [EndpointKind.InnerDns]: "#ccc",
  [EndpointKind.Other]: "#ccc",
} as const;

const HIGHLIGHTED_LINE_COLOR = {
  [EndpointKind.OuterDns]: "#7748e4",
  [EndpointKind.K8s]: "#0b81d0",
  [EndpointKind.HostMetadataService]: "#888",
  [EndpointKind.Ip]: "#888",
  [EndpointKind.InnerDns]: "#888",
  [EndpointKind.Other]: "#888",
} as const;

const MUTED_LINE_COLOR = "#eee";

export const ConnectionsLines = memo(function ConnectionsLines(props: Props) {
  const state = useAppState();

  const ref = useRef<HTMLCanvasElement>(null);

  const draw = useCallback(() => {
    const canvas = ref.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const foregroundLines: ConnectionLine[] = [];
    const backgroundLines: ConnectionLine[] = [];

    state.connectionsMap.forEach((procs, endpoint) => {
      const endpointInfo = state.endpointsMap.get(endpoint);

      if (!endpointInfo?.xy || !endpointInfo?.visible) {
        return;
      }

      let baseLineColor = BASE_LINE_COLOR[endpointInfo.kind];
      let highlightedLineColor = HIGHLIGHTED_LINE_COLOR[endpointInfo.kind];

      let color = state.highlightedEndpointsMap.size
        ? state.highlightedEndpointsMap.has(endpoint)
          ? highlightedLineColor
          : MUTED_LINE_COLOR
        : baseLineColor;

      const x2 = endpointInfo.xy.x;
      const y2 = endpointInfo.xy.y;

      procs.forEach((proc) => {
        const procInfo = state.processesMap.get(proc);

        if (!procInfo?.xy || !procInfo?.visible) {
          return;
        }

        color = state.highlightedProc
          ? proc === state.highlightedProc
            ? highlightedLineColor
            : MUTED_LINE_COLOR
          : color;

        const x1 = procInfo.xy.x;
        const y1 = procInfo.xy.y;

        const line = { from: { x: x1, y: y1 }, to: { x: x2, y: y2 }, color };

        if (color === highlightedLineColor) {
          foregroundLines.push(line);
        } else {
          backgroundLines.push(line);
        }
      });
    });

    backgroundLines.forEach((line) => drawLine(ctx, line));
    foregroundLines.forEach((line) => drawLine(ctx, line));
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

  useEffect(() => {
    return state.onEndpointHighlight(draw);
  }, [draw]);

  useEffect(() => {
    return state.onProcHighlight(draw);
  }, [draw]);

  return <canvas ref={ref} />;
});

function drawLine(ctx: CanvasRenderingContext2D, line: ConnectionLine) {
  ctx.beginPath();
  ctx.strokeStyle = line.color;
  ctx.lineWidth = 1.25;
  ctx.moveTo(line.from.x, line.from.y);
  ctx.bezierCurveTo(
    Math.max(line.from.x, line.to.x - 100),
    line.from.y,
    Math.max(line.from.x, line.to.x - 100),
    line.to.y,
    line.to.x,
    line.to.y
  );
  ctx.stroke();
  ctx.closePath();
}
