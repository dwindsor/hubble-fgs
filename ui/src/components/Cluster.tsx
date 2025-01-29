import { memo } from "react";
import { useAppState } from "~/state/AppContext";
import css from "./Cluster.module.css";
import { ClusterNode } from "./ClusterNode";
import { Collapsible } from "./Collapsible";
import { ClusterIcon } from "./Icons/ClusterIcon";

export const Cluster = memo(function Cluster() {
  const state = useAppState();

  return (
    <li className={css.clusterItem}>
      <Collapsible
        path={{ cluster: true }}
        initialOpen={true}
        summary={({ onClick }) => (
          <summary className={css.clusterName} onClick={onClick}>
            <div>
              <ClusterIcon className={css.clusterIcon} size={14} color="#b8b8b8" />
              <span>{state.model.clusterName}</span>
            </div>
          </summary>
        )}
      >
        <ul className={css.nodesList}>
          <ClusterNode />
        </ul>
      </Collapsible>
    </li>
  );
});
