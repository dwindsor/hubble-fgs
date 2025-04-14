import clsx from "clsx";
import { memo, useMemo } from "react";
import type { EndpointFiltersState, FilterKind } from "~/hooks/useEndpointFilters";
import { DestinationFilterKind } from "~/utils/destination";
import { FileEventFilterKind } from "~/utils/file-event";
import css from "./EndpointFilters.module.css";
import { Checkbox } from "./ui/Checkbox";

export interface Props {
  filters: EndpointFiltersState;
}

export const EndpointFilters = memo(function EndpointFilters(props: Props) {
  return (
    <div className={css.filtersContainer}>
      <div className={css.filterGroup}>
        <span className={css.filterGroupTitle}>Connections</span>
        <ul className={css.wrapper}>
          <EndpointSubFilter
            kind={DestinationFilterKind.Inner}
            status={props.filters.value.has(DestinationFilterKind.Inner)}
            onClick={() => props.filters.toggle(DestinationFilterKind.Inner)}
          />
          <EndpointSubFilter
            kind={DestinationFilterKind.Outer}
            status={props.filters.value.has(DestinationFilterKind.Outer)}
            onClick={() => props.filters.toggle(DestinationFilterKind.Outer)}
          />
          <EndpointSubFilter
            kind={DestinationFilterKind.Kubernetes}
            status={props.filters.value.has(DestinationFilterKind.Kubernetes)}
            onClick={() => props.filters.toggle(DestinationFilterKind.Kubernetes)}
          />
        </ul>
      </div>
      {/* <div className={css.filterGroup}>
        <span className={css.filterGroupTitle}>Files</span>
        <ul className={css.wrapper}>
          <EndpointSubFilter
            kind={FileEventFilterKind.Read}
            status={props.filters.value.has(FileEventFilterKind.Read)}
            onClick={() => props.filters.toggle(FileEventFilterKind.Read)}
          />
          <EndpointSubFilter
            kind={FileEventFilterKind.Write}
            status={props.filters.value.has(FileEventFilterKind.Write)}
            onClick={() => props.filters.toggle(FileEventFilterKind.Write)}
          />
        </ul>
      </div> */}
    </div>
  );
});

interface EndpointSubFilterProps {
  kind: FilterKind;
  status: boolean;
  onClick: () => void;
}

const EndpointSubFilter = memo(function EndpointSubFilter(props: EndpointSubFilterProps) {
  const title = useMemo(() => {
    if (props.kind === DestinationFilterKind.Outer) {
      return "Outer";
    }
    if (props.kind === DestinationFilterKind.Kubernetes) {
      return "Kubernetes";
    }
    if (props.kind === DestinationFilterKind.Inner) {
      return "Inner";
    }
    if (props.kind === FileEventFilterKind.Read) {
      return "Read";
    }
    if (props.kind === FileEventFilterKind.Write) {
      return "Write";
    }
    return "Other";
  }, [props.kind]);

  const className = clsx(css[`entity-${props.kind}`], {
    [css.selected]: props.status,
  });

  return (
    <li className={className}>
      <button type="button" onClick={props.onClick}>
        <Checkbox readOnly checked={props.status} /> {title}
      </button>
    </li>
  );
});
