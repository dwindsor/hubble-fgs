import { memo, useCallback, useEffect, useRef } from "react";
import { useAppState } from "~/state/AppContext";
import { ConnectionLine, Connector, EndpointKind, Line, WH, XY } from "~/types";

export interface Props {
  size: WH;
}

const LINE_COLOR = "#ccc";
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
    const foregroundConnectors: Connector[] = [];
    const backgroundLines: ConnectionLine[] = [];
    const backgroundConnectors: Connector[] = [];

    state.connectionsMap.forEach((procs, endpoint) => {
      const endpointInfo = state.endpointsMap.get(endpoint);

      if (!endpointInfo?.xy || !endpointInfo?.visible) {
        return;
      }

      let highlightedLineColor = HIGHLIGHTED_LINE_COLOR[endpointInfo.kind];

      let color = state.highlightedEndpoint
        ? endpoint === state.highlightedEndpoint
          ? highlightedLineColor
          : MUTED_LINE_COLOR
        : LINE_COLOR;

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
        const procConnector = { x: x1, y: y1, color };

        if (color === highlightedLineColor) {
          foregroundLines.push(line);
          foregroundConnectors.push(procConnector);
        } else {
          backgroundLines.push(line);
          backgroundConnectors.push(procConnector);
        }
      });
    });

    backgroundLines.forEach((line) => drawLine(ctx, line));
    backgroundConnectors.forEach((connector) => drawConnector(ctx, connector));
    foregroundLines.forEach((line) => drawLine(ctx, line));
    foregroundConnectors.forEach((connector) => drawConnector(ctx, connector));
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
    return state.onToggleEndpointHighlight(draw);
  }, [draw]);

  useEffect(() => {
    return state.onToggleProcHighlight(draw);
  }, [draw]);

  return <canvas ref={ref} />;
});

function drawLine(ctx: CanvasRenderingContext2D, line: ConnectionLine) {
  ctx.beginPath();
  ctx.strokeStyle = line.color;
  ctx.lineWidth = 1.25;
  ctx.moveTo(line.from.x, line.from.y);
  ctx.bezierCurveTo(
    line.to.x - 100,
    line.from.y,
    line.to.x - 100,
    line.to.y,
    line.to.x,
    line.to.y
  );
  ctx.stroke();
  ctx.closePath();
}

function drawConnector(ctx: CanvasRenderingContext2D, connector: Connector) {
  ctx.beginPath();
  ctx.arc(connector.x, connector.y, 2, 0, 2 * Math.PI);
  ctx.fillStyle = connector.color;
  ctx.fill();
  ctx.strokeStyle = connector.color;
  ctx.stroke();
}
