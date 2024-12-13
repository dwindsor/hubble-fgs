import { memo } from "react";
import { ApplicationWorkload } from "~/proto/appmodel";
import clsx from "clsx";
import css from "./Workload.module.css";
import { ProcsList } from "./Proc";
import { WorkloadIcon } from "./Icons/WorkloadIcon";
import { useAppState } from "~/state/AppContext";
import { Statistic } from "./Statistic";
import { Collapsible } from "./Collapsible";

export interface WorkloadProps {
  workload: ApplicationWorkload;
}

export const Workload = memo(function Workload(props: WorkloadProps) {
  const state = useAppState();

  const stat = state.stat.workloadsMap[props.workload.name];

  const procs = props.workload.processes ?? [];
  return (
    <li className={clsx(css.workloadItem)}>
      <Collapsible
        summary={({ opened, onClick }) => (
          <summary className={css.workloadName} onClick={onClick}>
            <WorkloadIcon
              className={css.workloadIcon}
              size={14}
              color="#b8b8b8"
            />
            <span>{props.workload.name}</span>
            {!opened && <Statistic stat={stat} />}
          </summary>
        )}
      >
        <ProcsList procs={procs} procItemClassName={css.workloadProcessItem} />
      </Collapsible>
    </li>
  );
});

export interface WorkloadsListProps {
  workloads: ApplicationWorkload[];
}

export const WorkloadsList = memo(function WorkloadsList(
  props: WorkloadsListProps
) {
  return (
    <ul className={css.workloadsList}>
      {props.workloads.map((workload) => {
        return <Workload key={workload.name} workload={workload} />;
      })}
    </ul>
  );
});
