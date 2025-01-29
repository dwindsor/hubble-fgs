import clsx from "clsx";
import { memo } from "react";
import { useTreeEntry } from "~/hooks/useTreeEntry";
import type { ApplicationHost } from "~/proto";
import { useAppState } from "~/state/AppContext";
import { Collapsible } from "./Collapsible";
import { Connector } from "./Connector";
import css from "./Host.module.css";
import { HostIcon } from "./Icons/HostIcon";
import { ProcsList } from "./Proc";
import { Statistic } from "./Statistic";

export interface HostProps {
  host: ApplicationHost;
}

export const Host = memo(function Host(props: HostProps) {
  const state = useAppState();

  const entry = useTreeEntry({
    statInfo: state.stat.host,
  });

  return (
    <Collapsible
      path={{ host: true }}
      summary={({ onClick }) => (
        <summary className={clsx(css.hostTitle, entry.className)} onClick={onClick}>
          <div className={css.inner}>
            <HostIcon
              className={css.hostIcon}
              size={14}
              color={entry.stat?.hasSuspiciousProcs ? "#d59011" : "#b8b8b8"}
            />
            <span>Host</span>
            {entry.stat && <Statistic stat={entry.stat} />}
            {entry.hasConnections && <Connector endpoints={entry.connectorEndpoints} />}
          </div>
        </summary>
      )}
    >
      <ProcsList
        procs={props.host.processes ?? []}
        className={css.hostProcessesList}
        procItemClassName={css.hostProcessItem}
      />
    </Collapsible>
  );
});
