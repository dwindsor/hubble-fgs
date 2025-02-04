import { memo, useCallback, useEffect, useMemo, useRef } from "react";
import { type AppState, useAppState } from "~/state/AppContext";
import { colors } from "~/theme/colors";
import type { ConnectionLine } from "~/utils/connections";
import { type Endpoint, EndpointKind, EndpointModeKind } from "~/utils/endpoints";
import type { WH } from "~/utils/geometry";

export interface Props {
  size: WH;
}

const BASE_LINE_COLOR = {
  [EndpointKind.OuterDns]: colors.entityOuter,
  [EndpointKind.OuterIp]: colors.entityOuter,
  [EndpointKind.HostMetadataService]: colors.entityKube,
  [EndpointKind.Kube]: colors.entityKube,
  [EndpointKind.InnerDns]: colors.entityInner,
  [EndpointKind.InnerIp]: colors.entityInner,
  [EndpointKind.Other]: colors.entityInner,
} as const;

const HIGHLIGHTED_LINE_COLOR = {
  [EndpointKind.OuterDns]: colors.entityOuterHighlighted,
  [EndpointKind.OuterIp]: colors.entityOuterHighlighted,
  [EndpointKind.HostMetadataService]: colors.entityKubeHighlighted,
  [EndpointKind.Kube]: colors.entityKubeHighlighted,
  [EndpointKind.InnerDns]: colors.entityInnerHighlighted,
  [EndpointKind.InnerIp]: colors.entityInnerHighlighted,
  [EndpointKind.Other]: colors.entityInnerHighlighted,
} as const;

const MUTED_LINE_COLOR = colors.entityMuted;

export const ConnectionsLines = memo(function ConnectionsLines(props: Props) {
  const state = useAppState();

  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const dpi = window.devicePixelRatio;
    ctx.scale(dpi, dpi);
  }, []);

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

      const endpointX = endpointInfo.xy.x * window.devicePixelRatio;
      const endpointY = endpointInfo.xy.y * window.devicePixelRatio;

      procs.forEach((proc) => {
        const procInfo = state.processesMap.get(proc);

        if (!procInfo?.xy || !procInfo?.visible) {
          return;
        }

        const highlightedLineColor = HIGHLIGHTED_LINE_COLOR[endpointInfo.kind];
        const color = state.highlightedProc
          ? proc === state.highlightedProc
            ? highlightedLineColor
            : MUTED_LINE_COLOR
          : getLineColor(state, endpoint);

        const procX = procInfo.xy.x * window.devicePixelRatio;
        const procY = procInfo.xy.y * window.devicePixelRatio;

        const line: ConnectionLine = {
          from: { x: procX, y: procY },
          to: { x: endpointX, y: endpointY },
          color,
        };

        if (color === highlightedLineColor) {
          foregroundLines.push(line);
        } else {
          backgroundLines.push(line);
        }
      });
    });

    [backgroundLines, foregroundLines].forEach((lines) => {
      lines.forEach((line) => drawLine(ctx, line));
    });
  }, [state]);

  useEffect(() => {
    if (!ref.current) return;

    ref.current.width = props.size.width * 2;
    ref.current.height = props.size.height * 2;

    draw();
  }, [draw, props.size]);

  const style = useMemo(() => {
    return {
      width: `${props.size.width}px`,
      height: `${props.size.height}px`,
    };
  }, [props.size]);

  useEffect(() => {
    return state.onRedrawConnectionsLines(draw);
  }, [state, draw]);

  return <canvas style={style} ref={ref} />;
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
    line.to.y,
  );
  ctx.stroke();
  ctx.closePath();
}

function getLineColor(state: AppState, endpoint: Endpoint): string {
  const endpointInfo = state.endpointsMap.get(endpoint);

  if (!endpointInfo) {
    return "";
  }

  const baseLineColor = BASE_LINE_COLOR[endpointInfo.kind];
  const highlightedLineColor = HIGHLIGHTED_LINE_COLOR[endpointInfo.kind];

  let color: string = baseLineColor;
  if (state.highlightedEndpointsMap.size) {
    const modes = state.highlightedEndpointsMap.get(endpoint);
    if (!modes) {
      color = MUTED_LINE_COLOR;
    } else {
      let noHighlihts = true;
      state.highlightedEndpointsMap.forEach((modes) => {
        noHighlihts &&= !modes.has(EndpointModeKind.Hovered);
      });
      if (noHighlihts || modes.has(EndpointModeKind.Hovered)) {
        color = highlightedLineColor;
      } else {
        color = MUTED_LINE_COLOR;
      }
    }
  }

  return color;
}
