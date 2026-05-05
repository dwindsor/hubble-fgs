import { memo, useMemo } from "react";
import { useTreeEntry } from "~/hooks/useTreeEntry";
import type { ApplicationContainer, ApplicationNamespace, ApplicationWorkload } from "~/proto";
import { useAppState } from "~/state/AppContext";
import { colors } from "~/theme/colors";
import { getContainerHash } from "~/utils/containers";
import type { TreeContainerPath } from "~/utils/tree";
import { Collapsible } from "./Collapsible";
import { Connector } from "./Connector";
import css from "./Container.module.css";
import { ContainerIcon } from "./Icons/ContainerIcon";
import { ProcsList } from "./Proc";
import { Statistic } from "./Statistic";
import { TextOverflow } from "./TextOverflow";

export interface ContainerProps {
  namespace: ApplicationNamespace;
  workload: ApplicationWorkload;
  container: ApplicationContainer;
}

export const ContainerItem = memo(function Container(props: ContainerProps) {
  const state = useAppState();

  const procs = useMemo(() => {
    return props.container.processes ?? [];
  }, [props.container.processes]);

  const entry = useTreeEntry({
    statInfo:
      props.namespace.name && props.workload.name && props.container.name
        ? state.stat.containersMap.get(
            getContainerHash(props.namespace.name, props.workload.name, props.container.name),
          )
        : undefined,
  });

  const path = useMemo((): TreeContainerPath | null => {
    if (!props.namespace.name || !props.workload.name || !props.container.name) {
      return null;
    }
    return {
      namespace: props.namespace.name,
      workload: props.workload.name,
      container: props.container.name,
    };
  }, [props.namespace.name, props.workload.name, props.container.name]);

  if (!path) {
    return null;
  }

  return (
    <li>
      <Collapsible
        path={path}
        summary={({ onClick }) => (
          // biome-ignore lint/a11y/noStaticElementInteractions: <summary> is natively interactive inside <details>
          <summary className={entry.className} onClick={onClick}>
            <div className={css.internal}>
              <ContainerIcon
                className={css.containerIcon}
                size={14}
                color={entry.stat?.hasSuspiciousProcs ? colors.suspicious : colors.treeBranch}
              />
              <TextOverflow text={props.container.name ?? ""} trimSide="right" />
              {entry.stat && <Statistic stat={entry.stat} />}
              {entry.hasConnections && <Connector endpoints={entry.connectorEndpoints} />}
            </div>
          </summary>
        )}
      >
        <ProcsList procs={procs} procItemClassName={css.containerProcessItem} />
      </Collapsible>
    </li>
  );
});

export interface ContainersListProps {
  namespace: ApplicationNamespace;
  workload: ApplicationWorkload;
  containers: ApplicationContainer[];
}

export const ContainersList = memo(function ContainersList(props: ContainersListProps) {
  return (
    <ul className={css.containersList}>
      {props.containers.map((container) => {
        return (
          <ContainerItem
            key={container.name}
            namespace={props.namespace}
            workload={props.workload}
            container={container}
          />
        );
      })}
    </ul>
  );
});
