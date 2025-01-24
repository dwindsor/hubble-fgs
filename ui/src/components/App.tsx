import { memo, useRef } from "react";
import { useElementSize } from "~/hooks/useElementSize";
import css from "./App.module.css";
import { ConnectionsLines } from "./ConnectionsLines";
import { Endpoints } from "./Endpoints";
import { Tree } from "./Tree";

export const App = memo(function App() {
  const ref = useRef<HTMLDivElement>(null);

  const size = useElementSize(ref);

  return (
    <div ref={ref} className={css.app}>
      <div className={css.tree}>
        <Tree />
      </div>
      <div className={css.endpoints}>
        <Endpoints />
      </div>
      {size && (
        <div className={css.connectionsLines}>
          <ConnectionsLines size={size} />
        </div>
      )}
    </div>
  );
});
