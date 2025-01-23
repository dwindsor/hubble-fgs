import { memo } from "react";
import { Cluster } from "./Cluster";
import css from "./Tree.module.css";

export const Tree = memo(function Tree() {
  return (
    <div className={css.tree}>
      <ul className={css.clustersList}>
        <Cluster />
      </ul>
    </div>
  );
});
