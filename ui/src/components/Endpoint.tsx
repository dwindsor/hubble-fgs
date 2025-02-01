import { memo, useCallback, useEffect, useMemo, useState } from "react";
import { useAppState } from "~/state/AppContext";

import clsx from "clsx";
import React from "react";
import { useConnector } from "~/hooks/useConnector";
import { useDebouncedCallback } from "~/hooks/useDebouncedCallback";
import type { ApplicationProcessGroup } from "~/proto";
import { type EndpointStat, getEndpointHash } from "~/state/utils";
import { EndpointKind, type EndpointKindType } from "~/types";
import {
  EndpointMode,
  getEndpointPort,
  inferEndpointKind,
  trimEndpointPort,
} from "~/utils/endpoints";
import { isSuspiciousProc } from "~/utils/procs";
import css from "./Endpoint.module.css";
import { Statistic } from "./Statistic";

export interface Props {
  endpoint: string;
  onSelect?: () => void;
}

export const Endpoint = memo(function Endpoint(props: Props) {
  const state = useAppState();

  const connector = useConnector();

  const [highlightedProc, setHighlightedProc] = useState<ApplicationProcessGroup | null>(null);

  const [isPinned, setIsPinned] = useState<boolean>(
    !!state.highlightedEndpointsMap.get(props.endpoint)?.has(EndpointMode.Pinned),
  );

  const kind = useMemo(() => {
    return inferEndpointKind(props.endpoint);
  }, [props.endpoint]);

  const title = useMemo(() => {
    return trimEndpointPort(props.endpoint);
  }, [props.endpoint]);

  const port = useMemo(() => {
    return getEndpointPort(props.endpoint);
  }, [props.endpoint]);

  const stat = useMemo(() => {
    if (!highlightedProc) {
      return state.stat.endpointsMap.get(props.endpoint) ?? null;
    }
    const stat: EndpointStat = {
      totalBytesSent: 0,
      totalBytesReceived: 0,
      hasSuspiciousProcs: false,
    };
    let was = false;
    highlightedProc.connections?.forEach((conn) => {
      if (props.endpoint === getEndpointHash(conn)) {
        was = true;
        stat.totalBytesSent += Number(conn.bytesSent || 0);
        stat.totalBytesReceived += Number(conn.bytesReceived || 0);
        stat.hasSuspiciousProcs ||= isSuspiciousProc(highlightedProc);
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
    return state.onEndpointHighlight((endpoint) => {
      if (props.endpoint !== endpoint) {
        return;
      }
      setIsPinned(!!state.highlightedEndpointsMap.get(props.endpoint)?.has(EndpointMode.Pinned));
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
    state.highlightEndpoint(props.endpoint, true, EndpointMode.Hovered);
  }, [state, props.endpoint]);

  const onMouseLeave = useCallback(() => {
    state.highlightEndpoint(props.endpoint, false, EndpointMode.Hovered);
  }, [state, props.endpoint]);

  const onClick = useCallback(() => {
    props.onSelect?.();
    const modes = state.highlightedEndpointsMap.get(props.endpoint);
    if (modes?.has(EndpointMode.Pinned)) {
      state.highlightEndpoint(props.endpoint, false, EndpointMode.Pinned);
      return;
    }
    state.highlightEndpoint(props.endpoint, true, EndpointMode.Pinned);
  }, [state, props.endpoint, props.onSelect]);

  const className = clsx(css.endpoint, classNameFromEndpointKind(kind), {
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
        {renderEndpoint(kind, title, port, stat, isPinned)}
      </span>
    </div>
  );
});

function renderEndpoint(
  kind: EndpointKindType,
  title: string,
  port: string | null,
  stat: EndpointStat | null,
  isPinned: boolean,
) {
  switch (kind) {
    case EndpointKind.K8s:
      return (
        <>
          <K8sEndpoint str={title} port={port} isPinned={isPinned} />
          {stat && (
            <>
              {" "}
              <Statistic showSuspiciousMarker stat={stat} />
            </>
          )}
        </>
      );
    case EndpointKind.OuterDns:
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
    case EndpointKind.OuterIp:
    case EndpointKind.InnerIp:
    case EndpointKind.HostMetadataService:
      return (
        <>
          <IpEndpoint kind={kind} ip={title} port={port} isPinned={isPinned} />
          {stat && (
            <>
              {" "}
              <Statistic showSuspiciousMarker stat={stat} />
            </>
          )}
        </>
      );
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

function classNameFromEndpointKind(kind: EndpointKindType): string | null {
  switch (kind) {
    case EndpointKind.OuterIp:
    case EndpointKind.OuterDns:
      return css.outerEntity;
    case EndpointKind.K8s:
    case EndpointKind.HostMetadataService:
      return css.k8sEntity;
    default:
      return null;
  }
}

function IpEndpoint(props: {
  kind: EndpointKindType;
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

function K8sEndpoint(props: { str: string; port: string | null; isPinned: boolean }) {
  const { title, type, namespace } = useMemo(() => {
    const parts = props.str.split(/[\/:]/);
    return {
      title: parts[2],
      type: parts[1],
      namespace: parts[0],
    };
  }, [props.str]);

  return (
    <span className={css.k8sParts}>
      <span className={css.title}>
        {props.isPinned && <Pin />}
        {title}
        {props.port && <Port port={props.port} />}
      </span>{" "}
      <Namespace namespace={namespace} /> <K8sEntityType type={type} />
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

function Namespace(props: { namespace: string }) {
  return <span className={css.namespace}>{props.namespace}</span>;
}

function K8sEntityType(props: { type: string }) {
  return <span className={css.k8sEntityType}>{props.type}</span>;
}

function Pin() {
  return <span className={css.pin}>●</span>;
}
