import debounce from 'lodash/debounce';
import { memo, useCallback, useEffect, useMemo, useState } from 'react';
import { useAppState } from '~/state/AppContext';

import clsx from 'clsx';
import React from 'react';
import { useConnector } from '~/hooks/useConnector';
import { ApplicationProcess } from '~/proto';
import { EndpointStat, getEndpointHash } from '~/state/utils';
import { EndpointKind } from '~/types';
import {
  EndpointMode,
  getEndpointPort,
  inferEndpointKind,
  trimEndpointPort,
} from '~/utils/endpoints';
import css from './Endpoint.module.css';
import { Statistic } from './Statistic';

export interface Props {
  endpoint: string;
  ephimeral?: boolean;
}

export const Endpoint = memo(function Endpoint(props: Props) {
  const state = useAppState();

  const connector = useConnector();

  const [highlightedProc, setHighlightedProc] = useState<ApplicationProcess | null>(null);

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
      hasSuspiciousEvents: false,
    };
    let was = false;
    highlightedProc.connections?.forEach((conn) => {
      if (props.endpoint === getEndpointHash(conn)) {
        was = true;
        stat.totalBytesSent += Number(conn.bytesSent || 0);
        stat.totalBytesReceived += Number(conn.bytesReceived || 0);
        stat.hasSuspiciousEvents ||= !!highlightedProc.inInitTree;
      }
    });
    if (!was) {
      return null;
    }
    return stat;
  }, [props.endpoint, highlightedProc]);

  const update = (visible = true) => {
    const cur = state.endpointsMap.get(props.endpoint);
    const xy = connector.getXY();

    if (cur && cur.visible === visible && cur.xy?.x === xy?.x && cur.xy?.y === xy?.y) {
      return;
    }

    if (!props.ephimeral) {
      state.updateEndpoint(props.endpoint, visible, xy);
    }
  };

  const debouncedUpdate = useMemo(() => debounce(update), [props.endpoint, connector]);

  useEffect(() => {
    update(true);
    return () => state.updateEndpoint(props.endpoint, false, undefined);
  }, []);

  useEffect(() => state.onAppSizeChanged(() => debouncedUpdate()), [debouncedUpdate]);

  useEffect(() => {
    return state.onEndpointHighlight((endpoint) => {
      if (props.endpoint !== endpoint) {
        return;
      }
      setIsPinned(!!state.highlightedEndpointsMap.get(props.endpoint)?.has(EndpointMode.Pinned));
    });
  }, [props.endpoint]);

  useEffect(() => {
    return state.onProcHighlight((proc, value) => {
      if (!state.connectionsMap.get(props.endpoint)?.has(proc)) {
        setHighlightedProc(null);
        return;
      }
      setHighlightedProc(value ? proc : null);
    });
  }, [props.endpoint]);

  const onMouseEnter = useCallback(() => {
    state.highlightEndpoint(props.endpoint, true, EndpointMode.Hovered);
  }, [props.endpoint]);

  const onMouseLeave = useCallback(() => {
    state.highlightEndpoint(props.endpoint, false, EndpointMode.Hovered);
  }, [props.endpoint]);

  const onClick = useCallback(() => {
    const modes = state.highlightedEndpointsMap.get(props.endpoint);
    if (modes?.has(EndpointMode.Pinned)) {
      state.highlightEndpoint(props.endpoint, false, EndpointMode.Pinned);
      return;
    }
    state.highlightEndpoint(props.endpoint, true, EndpointMode.Pinned);
  }, [props.endpoint]);

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
  kind: EndpointKind,
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
              {' '}
              <Statistic showSuspiciousMarker stat={stat} />
            </>
          )}
        </>
      );
    case EndpointKind.OuterDns:
      return (
        <span className={clsx(css.title)}>
          {isPinned && <Pin />}
          {title}
          {port && <Port port={port} />}
          {stat && (
            <>
              {' '}
              <Statistic showSuspiciousMarker stat={stat} />
            </>
          )}
        </span>
      );
    case EndpointKind.Ip:
    case EndpointKind.HostMetadataService:
      return (
        <>
          <IpEndpoint ip={title} port={port} isPinned={isPinned} />
          {stat && (
            <>
              {' '}
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
              {' '}
              <Statistic showSuspiciousMarker stat={stat} />
            </>
          )}
        </span>
      );
  }
}

function classNameFromEndpointKind(kind: EndpointKind): string | null {
  switch (kind) {
    case EndpointKind.OuterDns:
      return css.outerDns;
    case EndpointKind.K8s:
      return css.k8sEntity;
    default:
      return null;
  }
}

function IpEndpoint(props: { ip: string; port: string | null; isPinned: boolean }) {
  const { parts, separator } = useMemo(() => {
    const separator = props.ip.includes('.') ? '.' : ':';
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
      <span className={clsx(css.title, css.k8sEntityName)}>
        {props.isPinned && <Pin />}
        {title}
        {props.port && <Port port={props.port} />}
      </span>{' '}
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
