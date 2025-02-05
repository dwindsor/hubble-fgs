import clsx from "clsx";
import { memo, useMemo } from "react";
import type { EndpointFiltersState } from "~/hooks/useEndpointFilters";
import { EndpointFilterKind } from "~/utils/endpoints";
import css from "./EndpointFilters.module.css";

export interface Props {
  filters: EndpointFiltersState;
}

export const EndpointFilters = memo(function EndpointFilters(props: Props) {
  return (
    <ul className={css.wrapper}>
      <EndpointFilter
        kind={EndpointFilterKind.Outer}
        status={props.filters.value.has(EndpointFilterKind.Outer)}
        onClick={() => props.filters.toggle(EndpointFilterKind.Outer)}
      />
      <EndpointFilter
        kind={EndpointFilterKind.Kube}
        status={props.filters.value.has(EndpointFilterKind.Kube)}
        onClick={() => props.filters.toggle(EndpointFilterKind.Kube)}
      />
      <EndpointFilter
        kind={EndpointFilterKind.Inner}
        status={props.filters.value.has(EndpointFilterKind.Inner)}
        onClick={() => props.filters.toggle(EndpointFilterKind.Inner)}
      />
    </ul>
  );
});

interface EndpointFilterProps {
  kind: EndpointFilterKind;
  status: boolean;
  onClick: () => void;
}

const EndpointFilter = memo(function EndpointFilter(props: EndpointFilterProps) {
  const title = useMemo(() => {
    if (props.kind === EndpointFilterKind.Outer) {
      return "Outer";
    }
    if (props.kind === EndpointFilterKind.Kube) {
      return "Kubernetes";
    }
    if (props.kind === EndpointFilterKind.Inner) {
      return "Inner";
    }
    return "Other";
  }, [props.kind]);

  const className = clsx(css[`entity-${props.kind}`], {
    [css.selected]: props.status,
  });

  return (
    <li className={className}>
      <button type="button" onClick={props.onClick}>
        <input type="checkbox" readOnly checked={props.status} /> {title}
      </button>
    </li>
  );
});
