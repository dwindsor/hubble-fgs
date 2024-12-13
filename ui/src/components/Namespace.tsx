import { memo } from "react";
import css from "./Namespace.module.css";
import { ApplicationNamespace } from "~/proto/appmodel";
import { WorkloadsList } from "./Workload";
import clsx from "clsx";

import { NamespacesIcon } from "./Icons/NamespacesIcon";
import { NamespaceIcon } from "./Icons/NamespaceIcon";
import { Statistic } from "./Statistic";
import { useAppState } from "~/state/AppContext";
import { Collapsible } from "./Collapsible";

export interface NamespaceProps {
  namespace: ApplicationNamespace;
}

export const Namespace = memo(function Namespace(props: NamespaceProps) {
  const state = useAppState();

  const stat = state.stat.namespacesMap[props.namespace.name];

  const workloads = props.namespace.workloads ?? [];
  return (
    <li className={clsx(css.namespaceItem)}>
      <Collapsible
        summary={({ opened, onClick }) => (
          <summary onClick={onClick}>
            <NamespaceIcon
              className={css.namespaceIcon}
              size={14}
              color="#b8b8b8"
            />
            <span>{props.namespace.name}</span>
            {!opened && <Statistic stat={stat} />}
          </summary>
        )}
      >
        <WorkloadsList workloads={workloads} />
      </Collapsible>
    </li>
  );
});

export interface NamespacesListProps {
  namespaces: ApplicationNamespace[];
}

export const NamespacesList = memo(function NamespacesList(
  props: NamespacesListProps
) {
  const state = useAppState();

  const stat = state.stat.namespaces;

  return (
    <Collapsible
      initialOpened={true}
      summary={({ opened, onClick }) => (
        <summary className={css.namespacesTitle} onClick={onClick}>
          <NamespacesIcon
            className={css.namespacesIcon}
            size={14}
            color="#b8b8b8"
          />
          <span>Namespaces</span>
          {!opened && <Statistic stat={stat} />}
        </summary>
      )}
    >
      <ul className={css.namespacesList}>
        {props.namespaces.map((namespace) => {
          return <Namespace key={namespace.name} namespace={namespace} />;
        })}
      </ul>
    </Collapsible>
  );
});
