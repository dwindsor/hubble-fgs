import debounce from "lodash/debounce";
import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useAppState } from "~/state/AppContext";

import clsx from "clsx";
import React from "react";
import { useConnector } from "~/hooks/useConnector";
import { EndpointKind } from "~/types";
import {
  getEndpointPort,
  inferEndpointKind,
  trimEndpointPort,
} from "~/utils/endpoints";
import css from "./Endpoint.module.css";

export interface Props {
  endpoint: string;
}

export const Endpoint = memo(function Endpoint(props: Props) {
  const connectorRef = useRef<HTMLDivElement>(null);

  const state = useAppState();

  const [highlighted, setHighlighted] = useState<boolean>(false);

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

  useEffect(
    () => state.onTreeSizeChanged(() => debouncedUpdate()),
    [debouncedUpdate]
  );

  useEffect(
    () => state.onTreeChanged(() => debouncedUpdate()),
    [debouncedUpdate]
  );

  useEffect(() => {
    return state.onToggleProcHighlight((proc, value) => {
      if (!state.connectionsMap.get(props.endpoint)?.has(proc)) {
        setHighlighted(false);
        return;
      }
      setHighlighted(value);
    });
  }, [props.endpoint]);

  const highlight = useCallback(() => {
    state.toggleEndpontHighlight(props.endpoint, true);
  }, [props.endpoint]);

  const unhighlight = useCallback(() => {
    state.toggleEndpontHighlight(props.endpoint, false);
  }, [props.endpoint]);

  return (
    <div
      className={clsx(css.endpoint, { [css.highlighted]: highlighted })}
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
  kind: EndpointKind,
  title: string,
  port: string | null
) {
  switch (kind) {
    case EndpointKind.K8s:
      return <K8sEndpoint str={title} port={port} />;
    case EndpointKind.OuterDns:
      return (
        <span className={clsx(css.title, css.outerDns)}>
          {title}
          {port && <Port port={port} />}
        </span>
      );
    case EndpointKind.Ip:
    case EndpointKind.HostMetadataService:
      return <IpEndpoint ip={title} port={port} />;
    default:
      return (
        <span className={css.title}>
          {title}
          {port && <Port port={port} />}
        </span>
      );
  }
}

function IpEndpoint(props: { ip: string; port: string | null }) {
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
      {props.port && <Port port={props.port} />}
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
      <span className={clsx(css.title, css.k8sEntityName)}>
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
