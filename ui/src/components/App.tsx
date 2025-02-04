import { memo, useCallback, useRef } from "react";
import { useElementScroll } from "~/hooks/useElementScroll";
import { useElementSize } from "~/hooks/useElementSize";
import { useAppState } from "~/state/AppContext";
import css from "./App.module.css";
import { ConnectionsLines } from "./ConnectionsLines";
import { Endpoints } from "./Endpoints";
import { Tree } from "./Tree";

export const App = memo(function App() {
  const state = useAppState();

  const appRef = useRef<HTMLDivElement>(null);
  const treeRef = useRef<HTMLDivElement>(null);
  const endpointsRef = useRef<HTMLDivElement>(null);

  const appSize = useElementSize(appRef);

  const onScroll = useCallback(() => {
    const animationFrameId = requestAnimationFrame(state.scroll);
    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, [state.scroll]);

  useElementScroll(treeRef, onScroll);
  useElementScroll(endpointsRef, onScroll);

  return (
    <div ref={appRef} className={css.app}>
      <div ref={treeRef} className={css.tree}>
        <Tree />
      </div>
      <div ref={endpointsRef} className={css.endpoints}>
        <Endpoints />
      </div>
      {appSize && (
        <div className={css.connectionsLines}>
          <ConnectionsLines size={appSize} />
        </div>
      )}
    </div>
  );
});
