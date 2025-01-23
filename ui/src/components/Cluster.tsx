import { memo } from "react";
import { ApplicationModelEvent } from "~/proto";
import css from "./Cluster.module.css";
import { ClusterIcon } from "./Icons/ClusterIcon";
import { ClusterNode } from "./ClusterNode";
import { Collapsible } from "./Collapsible";
import { useAppState } from "~/state/AppContext";
import { Statistic } from "./Statistic";

export const Cluster = memo(function Cluster() {
  const state = useAppState();

  return (
    <li className={css.clusterItem}>
      <Collapsible
        initialOpened={true}
        summary={({ onClick }) => (
          <summary className={css.clusterName} onClick={onClick}>
            <div>
              <ClusterIcon
                className={css.clusterIcon}
                size={14}
                color="#b8b8b8"
              />
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
