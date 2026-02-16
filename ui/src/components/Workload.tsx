import { memo, useMemo } from "react";
import { useTreeEntry } from "~/hooks/useTreeEntry";
import type { ApplicationNamespace, ApplicationWorkload } from "~/proto";
import { useAppState } from "~/state/AppContext";
import { colors } from "~/theme/colors";
import type { TreeWorkloadPath } from "~/utils/tree";
import { getWorkloadHash } from "~/utils/workloads";
import { Collapsible } from "./Collapsible";
import { Connector } from "./Connector";
import { WorkloadIcon } from "./Icons/WorkloadIcon";
import { Statistic } from "./Statistic";
import { TextOverflow } from "./TextOverflow";
import css from "./Workload.module.css";
import { ContainersList } from "./Container";

export interface WorkloadProps {
  namespace: ApplicationNamespace;
  workload: ApplicationWorkload;
}

export const WorkloadItem = memo(function Workload(props: WorkloadProps) {
  const state = useAppState();

  const containers = useMemo(() => {
    return props.workload.containers ?? [];
  }, [props.workload.containers]);

  const entry = useTreeEntry({
    statInfo:
      props.namespace.name && props.workload.name
        ? state.stat.workloadsMap.get(getWorkloadHash(props.namespace.name, props.workload.name))
        : undefined,
  });

  const path = useMemo((): TreeWorkloadPath | null => {
    if (!props.namespace.name || !props.workload.name) {
      return null;
    }
    return { namespace: props.namespace.name, workload: props.workload.name };
  }, [props.namespace.name, props.workload.name]);

  if (!path) {
    return null;
  }

  return (
    <li>
      <Collapsible
        path={path}
        summary={({ onClick }) => (
          <summary className={entry.className} onClick={onClick}>
            <div className={css.inner}>
              <WorkloadIcon
                className={css.workloadIcon}
                size={14}
                color={entry.stat?.hasSuspiciousProcs ? colors.suspicious : colors.treeBranch}
              />
              <TextOverflow text={props.workload.name ?? ""} trimSide="right" />
              {entry.stat && <Statistic stat={entry.stat} />}
              {entry.hasConnections && <Connector endpoints={entry.connectorEndpoints} />}
            </div>
          </summary>
        )}
      >
        <ContainersList
          namespace={props.namespace}
          workload={props.workload}
          containers={containers}
        />
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
        return <WorkloadItem key={workload.name} namespace={props.namespace} workload={workload} />;
      })}
    </ul>
  );
});
