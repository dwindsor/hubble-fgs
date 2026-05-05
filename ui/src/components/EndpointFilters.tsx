import clsx from "clsx";
import { memo, useMemo } from "react";
import type { EndpointFiltersState, FilterKind } from "~/hooks/useEndpointFilters";
import { DestinationFilterKind } from "~/utils/destination";
import { FileEventFilterKind } from "~/utils/file-event";
import css from "./EndpointFilters.module.css";
import { Checkbox } from "./ui/Checkbox";
import { Tooltip, TooltipContent, TooltipTrigger } from "./ui/Tooltip";

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
            kind={DestinationFilterKind.Internal}
            status={props.filters.value.has(DestinationFilterKind.Internal)}
            onClick={() => props.filters.toggle(DestinationFilterKind.Internal)}
          />
          <EndpointSubFilter
            kind={DestinationFilterKind.External}
            status={props.filters.value.has(DestinationFilterKind.External)}
            onClick={() => props.filters.toggle(DestinationFilterKind.External)}
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
  const { title, tooltip } = useMemo(() => {
    if (props.kind === DestinationFilterKind.External) {
      return {
        title: "External",
        tooltip:
          "Connections to destinations outside the cluster — public IPs, external DNS names, the internet.",
      };
    }
    if (props.kind === DestinationFilterKind.Kubernetes) {
      return {
        title: "Internal Kubernetes",
        tooltip:
          "Connections to Kubernetes workloads (pods, services) identified by namespace and workload name.",
      };
    }
    if (props.kind === DestinationFilterKind.Internal) {
      return {
        title: "Internal",
        tooltip:
          "Connections staying within the host or cluster — loopback, private IP ranges, *.cluster.local, AWS ip-*.internal.",
      };
    }
    if (props.kind === FileEventFilterKind.Read) {
      return { title: "Read", tooltip: "" };
    }
    if (props.kind === FileEventFilterKind.Write) {
      return { title: "Write", tooltip: "" };
    }
    return { title: "Other", tooltip: "" };
  }, [props.kind]);

  const className = clsx(css[`entity-${props.kind}`], {
    [css.selected]: props.status,
  });

  const button = (
    <button type="button" onClick={props.onClick}>
      <Checkbox readOnly checked={props.status} /> {title}
    </button>
  );

  return (
    <li className={className}>
      {tooltip ? (
        <Tooltip>
          <TooltipTrigger asChild>{button}</TooltipTrigger>
          <TooltipContent className="ipt-tooltip">{tooltip}</TooltipContent>
        </Tooltip>
      ) : (
        button
      )}
    </li>
  );
});
