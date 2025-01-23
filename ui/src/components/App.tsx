import { memo } from "react";
import { useTree } from "~/hooks/useTree";
import css from "./App.module.css";
import { ConnectionsLines } from "./ConnectionsLines";
import { Endpoints } from "./Endpoints";
import { Tree } from "./Tree";

export interface Props {
  appRef: React.RefObject<HTMLDivElement | null>;
}

export const App = memo(function App(props: Props) {
  const tree = useTree(props.appRef);

  return (
    <div ref={props.appRef} className={css.app}>
      <div className={css.tree}>
        <Tree />
      </div>
      <div className={css.endpoints}>
        <Endpoints />
      </div>
      {tree.size && (
        <div className={css.connectionsLines}>
          <ConnectionsLines size={tree.size} />
        </div>
      )}
    </div>
  );
});
