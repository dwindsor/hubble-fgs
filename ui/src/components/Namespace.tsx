import { memo } from "react";
import { useTreeEntry } from "~/hooks/useTreeEntry";
import { ApplicationNamespace } from "~/proto";
import { useAppState } from "~/state/AppContext";
import { Collapsible } from "./Collapsible";
import { Connector } from "./Connector";
import { NamespaceIcon } from "./Icons/NamespaceIcon";
import { NamespacesIcon } from "./Icons/NamespacesIcon";
import css from "./Namespace.module.css";
import { Statistic } from "./Statistic";
import { WorkloadsList } from "./Workload";

export interface NamespaceProps {
  namespace: ApplicationNamespace;
}

export const Namespace = memo(function Namespace(props: NamespaceProps) {
  const state = useAppState();

  const entry = useTreeEntry({
    statInfo: props.namespace.name
      ? state.stat.namespacesMap.get(props.namespace.name)
      : undefined,
  });

  const workloads = props.namespace.workloads ?? [];

  return (
    <li>
      <Collapsible
        summary={({ onClick }) => (
          <summary className={entry.className} onClick={onClick}>
            <div className={css.inner}>
              <NamespaceIcon
                className={css.namespaceIcon}
                size={14}
                color="#b8b8b8"
              />
              <span>{props.namespace.name}</span>
              {entry.stat && <Statistic stat={entry.stat} />}
              {entry.hasConnections && (
                <Connector endpoints={entry.connectorEndpoints} />
              )}
            </div>
          </summary>
        )}
      >
        <WorkloadsList namespace={props.namespace} workloads={workloads} />
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
      summary={({ onClick }) => (
        <summary className={css.namespacesTitle} onClick={onClick}>
          <div>
            <NamespacesIcon
              className={css.namespacesIcon}
              size={14}
              color="#b8b8b8"
            />
            <span>Namespaces</span>
            <Statistic stat={stat} />
          </div>
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
