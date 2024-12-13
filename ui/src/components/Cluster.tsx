import { memo } from "react";
import { ApplicationModelEvent } from "~/proto/appmodel";
import css from "./Cluster.module.css";
import { ClusterIcon } from "./Icons/ClusterIcon";
import { ClusterNode } from "./ClusterNode";
import { Collapsible } from "./Collapsible";

export interface Props {
  model: ApplicationModelEvent;
}

export const Cluster = memo(function Cluster(props: Props) {
  return (
    <li className={css.clusterItem}>
      <Collapsible
        initialOpened={true}
        summary={({ onClick }) => (
          <summary className={css.clusterName} onClick={onClick}>
            <ClusterIcon
              className={css.clusterIcon}
              size={14}
              color="#b8b8b8"
            />
            <span>{props.model.clusterName}</span>
          </summary>
        )}
      >
        <ul className={css.nodesList}>
          <ClusterNode model={props.model} />
        </ul>
      </Collapsible>
    </li>
  );
});
