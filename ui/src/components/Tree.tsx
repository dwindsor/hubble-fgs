import { memo } from "react";
import css from "./Tree.module.css";
import { Cluster } from "./Cluster";
import { useAppState } from "~/state/AppContext";

export const Tree = memo(function Tree() {
  const state = useAppState();

  return (
    <div className={css.tree}>
      <ul className={css.clustersList}>
        <Cluster model={state.model} />
      </ul>
    </div>
  );
});
