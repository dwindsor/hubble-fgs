import { memo, useMemo } from "react";
import { useTreeEntry } from "~/hooks/useTreeEntry";
import { useAppState } from "~/state/AppContext";
import { colors } from "~/theme/colors";
import { TREE_NODE_PATH } from "~/utils/tree";
import css from "./ClusterNode.module.css";
import { Collapsible } from "./Collapsible";
import { Connector } from "./Connector";
import { Host } from "./Host";
import { NodeIcon } from "./Icons/NodeIcon";
import { NamespacesList } from "./Namespace";
import { Statistic } from "./Statistic";
import { TextOverflow } from "./TextOverflow";

export const ClusterNode = memo(function ClusterNode() {
  const state = useAppState();

  const entry = useTreeEntry({
    statInfo: state.stat.node,
  });

  const host = state.model.application_model?.host;

  const namespaces = useMemo(() => {
    return state.model.application_model?.namespaces ?? [];
  }, [state.model.application_model?.namespaces]);

  return (
    <li className={css.nodeItem}>
      <Collapsible
        path={TREE_NODE_PATH}
        initialOpen={true}
        summary={({ onClick }) => (
          <summary className={entry.className} onClick={onClick}>
            <div className={css.inner}>
              <NodeIcon className={css.icon} size={14} color={colors.treeBranch} />
              <TextOverflow text={state.model.node_name ?? ""} trimSide="center" />
              {entry.stat && <Statistic stat={entry.stat} />}
              {entry.hasConnections && <Connector endpoints={entry.connectorEndpoints} />}
            </div>
          </summary>
        )}
      >
        <ul>
          {host && (
            <li>
              <Host host={host} />
            </li>
          )}
          <li>
            <NamespacesList namespaces={namespaces} />
          </li>
        </ul>
      </Collapsible>
    </li>
  );
});
