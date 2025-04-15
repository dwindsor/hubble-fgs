import { memo, useCallback, useEffect, useMemo, useState } from "react";
import { useAppState } from "~/state/AppContext";

import clsx from "clsx";
import React from "react";
import { useConnector } from "~/hooks/useConnector";
import { useDebouncedCallback } from "~/hooks/useDebouncedCallback";
import { type ApplicationProcessGroup, type Destination, FileEventKind } from "~/proto";
import { DestinationKind } from "~/utils/destination";
import {
  type Endpoint,
  type EndpointInfo,
  EndpointKind,
  EndpointModeKind,
  inferEndpointTitle,
} from "~/utils/endpoints";
import { isSuspiciousProc } from "~/utils/procs";
import { type Stat, advanceStat, createStat } from "~/utils/stat";
import type { TreePath } from "~/utils/tree";
import css from "./Endpoint.module.css";
import { ExpandVerticalIcon } from "./Icons/ExpandVerticalIcon";
import { Statistic } from "./Statistic";
import { Tooltip, TooltipContent, TooltipTrigger } from "./ui/Tooltip";

export interface Props {
  endpoint: Endpoint;
}

export const EndpointItem = memo(function Endpoint(props: Props) {
  const state = useAppState();

  const connector = useConnector();

  const [highlightedProc, setHighlightedProc] = useState<ApplicationProcessGroup | null>(null);

  const [isPinned, setIsPinned] = useState<boolean>(
    !!state.highlightedEndpointsMap.get(props.endpoint)?.has(EndpointModeKind.Pinned),
  );

  const endpointInfo = useMemo(() => {
    return state.endpointsMap.get(props.endpoint) as EndpointInfo;
  }, [state.endpointsMap, props.endpoint]);

  const title = useMemo(() => {
    return inferEndpointTitle(props.endpoint, endpointInfo.kind);
  }, [props.endpoint, endpointInfo]);

  const port = useMemo(() => {
    if (endpointInfo.kind === EndpointKind.Destination) {
      return (props.endpoint as Destination).port?.toString() ?? null;
    }
    return null;
  }, [props.endpoint, endpointInfo]);

  const stat = useMemo(() => {
    if (!highlightedProc) {
      return state.stat.endpointsMap.get(props.endpoint) ?? null;
    }
    const stat = createStat();
    let was = false;
    highlightedProc.connections?.forEach((conn) => {
      if (props.endpoint === conn.destination) {
        was = true;
        advanceStat(stat, {
          txBytes: Number(conn.stats?.tx_bytes || 0),
          rxBytes: Number(conn.stats?.rx_bytes || 0),
          txDrops: Number(conn.stats?.tx_drops || 0),
          hasSuspiciousProcs: isSuspiciousProc(highlightedProc),
        });
      }
    });
    if (!was) {
      return null;
    }
    return stat;
  }, [state, props.endpoint, highlightedProc]);

  const update = useCallback(
    (visible = true) => {
      const info = state.endpointsMap.get(props.endpoint);

      const xy = connector.getXY();

      if (info && info.visible === visible && info.xy?.x === xy?.x && info.xy?.y === xy?.y) {
        return;
      }

      state.updateEndpoint(props.endpoint, visible, xy);
    },
    [state, connector, props.endpoint],
  );

  // biome-ignore lint/correctness/useExhaustiveDependencies: don't do unnecessary unmounts
  useEffect(() => {
    update(true);
    return () => {
      return state.updateEndpoint(props.endpoint, false, undefined);
    };
  }, [state, props.endpoint]);

  const debouncedUpdate = useDebouncedCallback(update);

  useEffect(() => {
    return state.onEndpointsListChanged(() => {
      debouncedUpdate();
    });
  }, [state, debouncedUpdate]);

  useEffect(() => {
    return state.onScrolled(() => {
      debouncedUpdate();
    });
  }, [state, debouncedUpdate]);

  useEffect(() => {
    return state.onEndpointHighlight((endpoint) => {
      if (props.endpoint !== endpoint) {
        return;
      }
      setIsPinned(
        !!state.highlightedEndpointsMap.get(props.endpoint)?.has(EndpointModeKind.Pinned),
      );
    });
  }, [state, props.endpoint]);

  useEffect(() => {
    return state.onProcHighlight((proc, value) => {
      if (!state.connectionsMap.get(props.endpoint)?.has(proc)) {
        setHighlightedProc(null);
        return;
      }
      setHighlightedProc(value ? proc : null);
    });
  }, [state, props.endpoint]);

  const onMouseEnter = useCallback(() => {
    state.highlightEndpoint(props.endpoint, true, EndpointModeKind.Hovered);
  }, [state, props.endpoint]);

  const onMouseLeave = useCallback(() => {
    state.highlightEndpoint(props.endpoint, false, EndpointModeKind.Hovered);
  }, [state, props.endpoint]);

  const onClick = useCallback(() => {
    const modes = state.highlightedEndpointsMap.get(props.endpoint);
    if (modes?.has(EndpointModeKind.Pinned)) {
      state.highlightEndpoint(props.endpoint, false, EndpointModeKind.Pinned);
      return;
    }
    state.highlightEndpoint(props.endpoint, true, EndpointModeKind.Pinned);
  }, [state, props.endpoint]);

  const className = clsx(css.endpoint, classNameFromEndpointInfo(endpointInfo), {
    [css.highlighted]: highlightedProc,
  });

  return (
    <div
      className={className}
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
      onClick={onClick}
    >
      <div ref={connector.ref} className={css.connector} />
      <span className={css.endpointContent}>
        {renderEndpoint(endpointInfo, title, port, stat, isPinned)}
      </span>
    </div>
  );
});

function renderEndpoint(
  endpointInfo: EndpointInfo,
  title: string,
  port: string | null,
  stat: Stat | null,
  isPinned: boolean,
) {
  switch (endpointInfo.subKind) {
    case DestinationKind.Kubernetes:
      return (
        <>
          <KubernetesEndpoint title={title} port={port} isPinned={isPinned} />
          {stat && (
            <>
              {" "}
              <Statistic showSuspiciousMarker stat={stat} />
            </>
          )}
        </>
      );
    case DestinationKind.OuterDns:
      return (
        <span className={css.title}>
          {isPinned && <Pin />}
          {title}
          {port && <Port port={port} />}
          {stat && (
            <>
              {" "}
              <Statistic showSuspiciousMarker stat={stat} />
            </>
          )}
        </span>
      );
    case DestinationKind.OuterIp:
    case DestinationKind.InnerIp:
    case DestinationKind.HostMetadataService:
      return (
        <>
          <IpEndpoint ip={title} port={port} isPinned={isPinned} />
          {stat && (
            <>
              {" "}
              <Statistic showSuspiciousMarker stat={stat} />
            </>
          )}
        </>
      );
    case FileEventKind.Read:
    case FileEventKind.Write: {
      const kind = endpointInfo.subKind === FileEventKind.Read ? "Read" : "Write";
      return (
        <span className={css.title}>
          {isPinned && <Pin />}
          {title}
          <span className={css.fileEventKind}>{kind}</span>
        </span>
      );
    }
    default:
      return (
        <span className={css.title}>
          {isPinned && <Pin />}
          {title}
          {port && <Port port={port} />}
          {stat && (
            <>
              {" "}
              <Statistic showSuspiciousMarker stat={stat} />
            </>
          )}
        </span>
      );
  }
}

function classNameFromEndpointInfo(endpointInfo: EndpointInfo): string | null {
  switch (endpointInfo.subKind) {
    case DestinationKind.OuterIp:
    case DestinationKind.OuterDns:
      return css.entityDestinationOuter;
    case DestinationKind.Kubernetes:
    case DestinationKind.HostMetadataService:
      return css.entityDestinationKubernetes;
    case FileEventKind.Read:
      return css.entityFileEventRead;
    case FileEventKind.Write:
      return css.entityFileEventWrite;
    default:
      return null;
  }
}

function IpEndpoint(props: {
  ip: string;
  port: string | null;
  isPinned: boolean;
}) {
  const { parts, separator } = useMemo(() => {
    const separator = props.ip.includes(".") ? "." : ":";
    return {
      parts: props.ip.split(separator),
      separator,
    };
  }, [props.ip]);

  const lastIdx = parts.length - 1;

  return (
    <span className={css.title}>
      {props.isPinned && <Pin />}
      {parts.map((part, idx) => {
        const isLast = idx === lastIdx;
        return (
          <React.Fragment key={`${idx}:${part}`}>
            <span className={css.ipPart}>{part}</span>
            {!isLast && <span className={css.separator}>{separator}</span>}
          </React.Fragment>
        );
      })}
      {props.port && <Port port={props.port} />}
    </span>
  );
}

function KubernetesEndpoint(props: { title: string; port: string | null; isPinned: boolean }) {
  const state = useAppState();

  const { workloadName, workloadKind, workloadNamespace } = useMemo(() => {
    const parts = props.title.split(/[\/:]/);
    return {
      workloadNamespace: parts[0],
      workloadKind: parts[1],
      workloadName: parts[2],
    };
  }, [props.title]);

  const onClickExpandLink = useCallback(
    (event: React.MouseEvent) => {
      event.preventDefault();
      event.stopPropagation();

      const treePathsToExpand: TreePath[] = [
        { cluster: true },
        { node: true },
        { namespaces: true },
        { namespace: workloadNamespace },
        { namespace: workloadNamespace, workload: workloadName },
      ];
      treePathsToExpand.forEach((treePath) => {
        state.setTreePathStatus(treePath, { expanded: true });
      });
    },
    [state, workloadNamespace, workloadName],
  );

  return (
    <span>
      <span className={css.title}>
        {props.isPinned && <Pin />}
        {workloadName}
        {props.port && <Port port={props.port} />}
      </span>{" "}
      <span className={css.entityDestinationKubernetesNamespace}>{workloadNamespace}</span>{" "}
      <span className={css.entityDestinationKubernetesKind}>{workloadKind}</span>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className={css.entityDestinationKubernetesExpandLink} onClick={onClickExpandLink}>
            <ExpandVerticalIcon size={12} color="transparent" />
          </span>
        </TooltipTrigger>
        <TooltipContent className="ipt-tooltip">Expand in processes tree</TooltipContent>
      </Tooltip>
    </span>
  );
}

function Port(props: { port: string }) {
  return (
    <span className={css.port}>
      <span className={css.separator}>:</span>
      {props.port}
    </span>
  );
}

function Pin() {
  return <span className={css.pin}>●</span>;
}
