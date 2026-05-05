import clsx from "clsx";
import { memo, useMemo } from "react";
import { colors } from "~/theme/colors";
import type { Stat } from "~/utils/stat";
import { WarningIcon } from "./Icons/WarningIcon";
import css from "./Statistic.module.css";
import { Tooltip, TooltipContent, TooltipTrigger } from "./ui/Tooltip";

export interface Props {
  stat: Stat;
  showSuspiciousMarker?: boolean;
}

export const Statistic = memo(function Statistic(props: Props) {
  return (
    <span className={clsx(css.wrapper, "ipt-tree-item-stat")}>
      {(props.stat.txBytes > 0 || props.stat.rxBytes > 0) && (
        <>
          <Traffic dir="received" bytes={props.stat.rxBytes} />
          {"/"}
          <Traffic dir="sent" bytes={props.stat.txBytes} />
        </>
      )}
      {props.stat.txDrops > 0 && <Drops drops={props.stat.txDrops} />}
      {props.showSuspiciousMarker && props.stat.hasSuspiciousProcs && (
        <Tooltip>
          <TooltipTrigger asChild>
            <span className={css.suspiciousMarker}>
              <WarningIcon color={colors.suspicious} size={14} />
            </span>
          </TooltipTrigger>
          <TooltipContent className="ipt-tooltip">
            Connection opened by a process outside the container's init tree (e.g. spawned
            manually via shell). The process is highlighted orange on the left.
          </TooltipContent>
        </Tooltip>
      )}
    </span>
  );
});

const Traffic = memo(function Traffic(props: { dir: "sent" | "received"; bytes: number }) {
  const value = useMemo(() => {
    const kb = props.bytes / 1024;
    if (kb < 1) {
      return `${props.bytes} B`;
    }
    const mb = kb / 1024;
    if (mb < 1) {
      return `${Math.round(kb)} KB`;
    }
    const gb = mb / 1024;
    if (gb < 1) {
      return `${Math.round(mb)} MB`;
    }
    return `${Math.round(gb)} GB`;
  }, [props.bytes]);

  if (props.dir === "sent") {
    return (
      <>
        {value}
        {" →"}
      </>
    );
  }

  return (
    <>
      {"← "}
      {value}
    </>
  );
});

const Drops = memo(function Drops(props: { drops: number }) {
  return (
    <span className={css.drops}>
      {props.drops}
      <span className={css.dropsIcon}>Drops</span>
    </span>
  );
});
