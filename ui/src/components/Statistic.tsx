import clsx from "clsx";
import { memo, useMemo } from "react";
import type { Stat } from "~/utils/stat";
import { WarningIcon } from "./Icons/WarningIcon";
import css from "./Statistic.module.css";

export interface Props {
  stat: Stat;
  showSuspiciousMarker?: boolean;
}

export const Statistic = memo(function Statistic(props: Props) {
  return (
    <span className={clsx(css.wrapper, "process-tree-item-statistic")}>
      {props.stat.bytesSent > 0 && (
        <>
          <Traffic dir="received" bytes={props.stat.bytesReceived} />
          {"/"}
          <Traffic dir="sent" bytes={props.stat.bytesSent} />
        </>
      )}
      {props.showSuspiciousMarker && props.stat.hasSuspiciousProcs && (
        <span className={css.suspiciousMarker}>
          <WarningIcon color={"#dda02f"} size={14} />
        </span>
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
      return `${+kb.toFixed(1)} KB`;
    }
    const gb = mb / 1024;
    if (gb < 1) {
      return `${+mb.toFixed(1)} MB`;
    }
    return `${+gb.toFixed(1)} GB`;
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
