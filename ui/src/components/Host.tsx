import { memo } from "react";
import { useTreeEntry } from "~/hooks/useTreeEntry";
import type { ApplicationHost } from "~/proto";
import { useAppState } from "~/state/AppContext";
import { colors } from "~/theme/colors";
import { TREE_HOST_PATH } from "~/utils/tree";
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
      path={TREE_HOST_PATH}
      summary={({ onClick }) => (
        // biome-ignore lint/a11y/noStaticElementInteractions: <summary> is natively interactive inside <details>
        <summary className={entry.className} onClick={onClick}>
          <div className={css.internal}>
            <HostIcon
              className={css.icon}
              size={14}
              color={entry.stat?.hasSuspiciousProcs ? colors.suspicious : colors.treeBranch}
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
