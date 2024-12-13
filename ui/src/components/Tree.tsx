import { memo } from "react";
import { ApplicationModelEvent } from "~/proto/appmodel";
import css from "./Tree.module.css";
import { Cluster } from "./Cluster";

export interface TreeProps {
  model: ApplicationModelEvent;
}

export const Tree = memo(function Tree(props: TreeProps) {
  return (
    <div className={css.tree}>
      <ul className={css.clustersList}>
        <Cluster model={props.model} />
      </ul>
    </div>
  );
});
