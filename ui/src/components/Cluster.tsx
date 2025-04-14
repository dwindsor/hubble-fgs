import { memo } from "react";
import { useAppState } from "~/state/AppContext";
import { colors } from "~/theme/colors";
import { TREE_CLUSTER_PATH } from "~/utils/tree";
import css from "./Cluster.module.css";
import { ClusterNode } from "./ClusterNode";
import { Collapsible } from "./Collapsible";
import { ClusterIcon } from "./Icons/ClusterIcon";

export const Cluster = memo(function Cluster() {
  const state = useAppState();

  return (
    <li className={css.clusterItem}>
      <Collapsible
        path={TREE_CLUSTER_PATH}
        initialOpen={true}
        summary={({ onClick }) => (
          <summary className={css.clusterName} onClick={onClick}>
            <div>
              <ClusterIcon className={css.clusterIcon} size={14} color={colors.treeBranch} />
              <span>{state.model.cluster_name}</span>
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
