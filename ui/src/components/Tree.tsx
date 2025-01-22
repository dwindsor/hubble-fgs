import { memo } from "react";
import css from "./Tree.module.css";
import { Cluster } from "./Cluster";

export const Tree = memo(function Tree() {
  return (
    <div className={css.tree}>
      <ul className={css.clustersList}>
        <Cluster />
      </ul>
    </div>
  );
});
