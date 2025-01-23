import { memo } from "react";
import { useTreeEntry } from "~/hooks/useTreeEntry";
import type { ApplicationNamespace, ApplicationWorkload } from "~/proto";
import { useAppState } from "~/state/AppContext";
import { Collapsible } from "./Collapsible";
import { Connector } from "./Connector";
import { WorkloadIcon } from "./Icons/WorkloadIcon";
import { ProcsList } from "./Proc";
import { Statistic } from "./Statistic";
import css from "./Workload.module.css";

export interface WorkloadProps {
  namespace: ApplicationNamespace;
  workload: ApplicationWorkload;
}

export const Workload = memo(function Workload(props: WorkloadProps) {
  const state = useAppState();

  const entry = useTreeEntry({
    statInfo:
      props.namespace.name && props.workload.name
        ? state.stat.workloadsMap.get(`${props.namespace.name}/${props.workload.name}`)
        : undefined,
  });

  const procs = props.workload.processes ?? [];

  return (
    <li>
      <Collapsible
        summary={({ onClick }) => (
          <summary className={entry.className} onClick={onClick}>
            <div className={css.inner}>
              <WorkloadIcon
                className={css.workloadIcon}
                size={14}
                color={entry.stat?.hasSuspiciousEvents ? "#d59011" : "#b8b8b8"}
              />
              <span>{props.workload.name}</span>
              {entry.stat && <Statistic stat={entry.stat} />}
              {entry.hasConnections && <Connector endpoints={entry.connectorEndpoints} />}
            </div>
          </summary>
        )}
      >
        <ProcsList procs={procs} procItemClassName={css.workloadProcessItem} />
      </Collapsible>
    </li>
  );
});

export interface WorkloadsListProps {
  namespace: ApplicationNamespace;
  workloads: ApplicationWorkload[];
}

export const WorkloadsList = memo(function WorkloadsList(props: WorkloadsListProps) {
  return (
    <ul className={css.workloadsList}>
      {props.workloads.map((workload) => {
        return <Workload key={workload.name} namespace={props.namespace} workload={workload} />;
      })}
    </ul>
  );
});
