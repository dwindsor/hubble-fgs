import { memo } from "react";
import { ApplicationModelEvent } from "~/proto";
import css from "./ClusterNode.module.css";
import { NamespacesList } from "./Namespace";
import { Host } from "./Host";
import { NodeIcon } from "./Icons/NodeIcon";
import { Collapsible } from "./Collapsible";

export interface Props {
  model: ApplicationModelEvent;
}

export const ClusterNode = memo(function ClusterNode(props: Props) {
  const host = props.model.applicationModel?.host;
  const namespaces = props.model.applicationModel?.namespaces ?? [];

  return (
    <li className={css.nodeItem}>
      <Collapsible
        initialOpened={true}
        summary={({ onClick }) => (
          <summary className={css.nodeName} onClick={onClick}>
            <NodeIcon className={css.nodeIcon} size={14} color="#b8b8b8" />
            <span>{props.model.nodeName}</span>
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
