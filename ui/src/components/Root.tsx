import { memo, useMemo, useRef } from "react";
import { objectToCamel } from "ts-case-convert";
import type { ApplicationModelEvent } from "~/proto";
import { AppContext, createAppContext } from "~/state/AppContext";
import { App } from "./App";

export interface Props {
  model: ApplicationModelEvent;
  getTreeOffset: () => { x?: number; y?: number };
}

export const Root = memo(function Root(props: Props) {
  const model = useMemo(() => {
    return objectToCamel(props.model) as ApplicationModelEvent;
  }, [props.model]);

  const appRef = useRef<HTMLDivElement>(null);

  const appContext = useMemo(() => {
    return createAppContext({
      model,
      getTreeOffset: props.getTreeOffset,
    });
  }, [model, props.getTreeOffset]);

  return (
    <AppContext.Provider value={appContext}>
      <App appRef={appRef} />
    </AppContext.Provider>
  );
});
