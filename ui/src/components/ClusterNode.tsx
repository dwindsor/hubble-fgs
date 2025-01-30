import { memo, useMemo } from "react";
import { useTreeEntry } from "~/hooks/useTreeEntry";
import { useAppState } from "~/state/AppContext";
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

  const host = state.model.applicationModel?.host;

  const namespaces = useMemo(() => {
    return state.model.applicationModel?.namespaces ?? [];
  }, [state.model.applicationModel?.namespaces]);

  return (
    <li className={css.nodeItem}>
      <Collapsible
        path={{ node: true }}
        initialOpen={true}
        summary={({ onClick }) => (
          <summary className={entry.className} onClick={onClick}>
            <div className={css.inner}>
              <NodeIcon className={css.nodeIcon} size={14} color={"#b8b8b8"} />
              <TextOverflow text={state.model.nodeName ?? ""} trimSide="center" />
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
