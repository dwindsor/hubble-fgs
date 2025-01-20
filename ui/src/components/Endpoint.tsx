import { memo, useCallback, useEffect, useMemo, useRef } from "react";
import debounce from "lodash/debounce";
import { useAppState } from "~/state/AppContext";

import css from "./Endpoint.module.css";
import { useConnector } from "~/hooks/useConnector";
import { ArrowRightIcon } from "./Icons/ArrowRightIcon";
import {
  getEndpointPort,
  inferEndpointKind,
  trimEndpointPort,
} from "~/utils/endpoints";
import { EndpointKind, EndpointKindUnion } from "~/types";
import React from "react";
import clsx from "clsx";

export interface Props {
  endpoint: string;
}

export const Endpoint = memo(function Endpoint(props: Props) {
  const connectorRef = useRef<HTMLDivElement>(null);

  const state = useAppState();

  const kind = useMemo(() => {
    return inferEndpointKind(props.endpoint);
  }, [props.endpoint]);

  const title = useMemo(() => {
    return trimEndpointPort(props.endpoint);
  }, [props.endpoint]);

  const port = useMemo(() => {
    return getEndpointPort(props.endpoint);
  }, [props.endpoint]);

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

  const highlight = useCallback(() => {
    state.toggleEndpontHighlight(props.endpoint, true);
  }, [props.endpoint]);

  const unhighlight = useCallback(() => {
    state.toggleEndpontHighlight(props.endpoint, false);
  }, [props.endpoint]);

  return (
    <div
      className={css.endpoint}
      onMouseEnter={highlight}
      onMouseLeave={unhighlight}
    >
      <div ref={connectorRef} className={css.connector} />
      <span className={css.endpointContent}>
        {renderEndpoint(kind, title, port)}
      </span>
    </div>
  );
});

function renderEndpoint(
  kind: EndpointKindUnion,
  title: string,
  port: string | null
) {
  switch (kind) {
    case EndpointKind.K8s:
      return <K8sEndpoint str={title} port={port} />;
    case EndpointKind.OuterDns:
      return (
        <>
          <span className={clsx(css.title, css.outerDns)}>{title}</span>
          {port && <Port port={port} />}
        </>
      );
    case EndpointKind.Ip:
    case EndpointKind.HostMetadataService:
      return (
        <>
          <IpEndpoint ip={title} />
          {port && <Port port={port} />}
        </>
      );
    default:
      return (
        <>
          <span className={css.title}>{title}</span>
          {port && <Port port={port} />}
        </>
      );
  }
}

function IpEndpoint(props: { ip: string }) {
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
      {parts.map((part, idx) => {
        const isLast = idx === lastIdx;
        return (
          <React.Fragment key={`${idx}:${part}`}>
            <span className={css.ipPart}>{part}</span>
            {!isLast && <span className={css.separator}>{separator}</span>}
          </React.Fragment>
        );
      })}
    </span>
  );
}

function K8sEndpoint(props: { str: string; port: string | null }) {
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
      <span className={clsx(css.title, css.k8sEntityName)}>{title}</span>
      {props.port && <Port port={props.port} />}{" "}
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
