import { memo, useMemo } from "react";
import { useTreeEntry } from "~/hooks/useTreeEntry";
import type { ApplicationNamespace } from "~/proto";
import { useAppState } from "~/state/AppContext";
import { colors } from "~/theme/colors";
import { TREE_NAMESPACES_PATH, type TreeNamespacePath } from "~/utils/tree";
import { Collapsible } from "./Collapsible";
import { Connector } from "./Connector";
import { NamespaceIcon } from "./Icons/NamespaceIcon";
import { NamespacesIcon } from "./Icons/NamespacesIcon";
import css from "./Namespace.module.css";
import { Statistic } from "./Statistic";
import { TextOverflow } from "./TextOverflow";
import { WorkloadsList } from "./Workload";

export interface NamespaceProps {
  namespace: ApplicationNamespace;
}

export const NamespaceItem = memo(function Namespace(props: NamespaceProps) {
  const state = useAppState();

  const workloads = useMemo(() => {
    return props.namespace.workloads ?? [];
  }, [props.namespace.workloads]);

  const entry = useTreeEntry({
    statInfo: props.namespace.name ? state.stat.namespacesMap.get(props.namespace.name) : undefined,
  });

  const path = useMemo((): TreeNamespacePath | null => {
    if (!props.namespace.name) {
      return null;
    }
    return { namespace: props.namespace.name };
  }, [props.namespace.name]);

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
              <NamespaceIcon
                className={css.icon}
                size={14}
                color={entry.stat?.hasSuspiciousProcs ? colors.suspicious : colors.treeBranch}
              />
              <TextOverflow text={props.namespace.name ?? ""} trimSide="right" />
              {entry.stat && <Statistic stat={entry.stat} />}
              {entry.hasConnections && <Connector endpoints={entry.connectorEndpoints} />}
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

export const NamespacesList = memo(function NamespacesList(props: NamespacesListProps) {
  const state = useAppState();

  const entry = useTreeEntry({
    statInfo: state.stat.namespaces,
  });

  return (
    <Collapsible
      path={TREE_NAMESPACES_PATH}
      initialOpen={true}
      summary={({ onClick }) => (
        // biome-ignore lint/a11y/noStaticElementInteractions: <summary> is natively interactive inside <details>
        <summary className={entry.className} onClick={onClick}>
          <div className={css.internal}>
            <NamespacesIcon className={css.icon} size={14} color={colors.treeBranch} />
            <span>Namespaces</span>
            {entry.stat && <Statistic stat={entry.stat} />}
            {entry.hasConnections && <Connector endpoints={entry.connectorEndpoints} />}
          </div>
        </summary>
      )}
    >
      <ul className={css.namespacesList}>
        {props.namespaces.map((namespace) => {
          return <NamespaceItem key={namespace.name} namespace={namespace} />;
        })}
      </ul>
    </Collapsible>
  );
});
