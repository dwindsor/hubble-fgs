import { memo } from "react";
import css from "./App.module.css";
import { ConnectionsLines } from "./ConnectionsLines";
import { useAppState } from "~/state/AppContext";
import { Endpoints } from "./Endpoints";
import { Tree } from "./Tree";
import { useTree } from "~/hooks/useTree";

export interface Props {
  appRef: React.RefObject<HTMLDivElement | null>;
}

export const App = memo(function App(props: Props) {
  const state = useAppState();

  const tree = useTree(props.appRef);

  return (
    <div ref={props.appRef} className={css.app}>
      <div className={css.tree}>
        <Tree model={state.model} />
      </div>
      <div className={css.endpoints}>
        <Endpoints endpoints={state.endpoints} />
      </div>
      {tree.size && (
        <div className={css.connectionsLines}>
          <ConnectionsLines size={tree.size} connections={state.connections} />
        </div>
      )}
    </div>
  );
});
