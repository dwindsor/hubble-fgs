import { memo } from "react";
import { ApplicationHost } from "~/proto";

import css from "./Host.module.css";
import { ProcsList } from "./Proc";

import { HostIcon } from "./Icons/HostIcon";
import { useAppState } from "~/state/AppContext";
import { Statistic } from "./Statistic";
import { Collapsible } from "./Collapsible";

export interface HostProps {
  host: ApplicationHost;
}

export const Host = memo(function Host(props: HostProps) {
  const state = useAppState();

  const stat = state.stat.host;

  return (
    <Collapsible
      initialOpened={false}
      summary={({ onClick }) => (
        <summary className={css.hostTitle} onClick={onClick}>
          <div>
            <HostIcon className={css.hostIcon} size={14} color="#b8b8b8" />
            <span>Host</span>
            <Statistic stat={stat} />
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
