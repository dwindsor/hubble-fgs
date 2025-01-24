import { memo, useEffect, useRef } from "react";
import { useElementSize } from "~/hooks/useElementSize";
import { useAppState } from "~/state/AppContext";
import { Cluster } from "./Cluster";
import css from "./Tree.module.css";

export const Tree = memo(function Tree() {
  const state = useAppState();

  const ref = useRef<HTMLDivElement>(null);

  const size = useElementSize(ref);

  // biome-ignore lint/correctness/useExhaustiveDependencies: notify tree change because size was changed
  useEffect(() => {
    state.changeTree();
  }, [state, size]);

  return (
    <div ref={ref} className={css.tree}>
      <ul className={css.clustersList}>
        <Cluster />
      </ul>
    </div>
  );
});
