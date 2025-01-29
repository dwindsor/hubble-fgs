import { memo, useMemo } from "react";
import { objectToCamel } from "ts-case-convert";
import type { ApplicationModelEvent } from "~/proto";
import { AppContext, createAppContext } from "~/state/AppContext";
import { App } from "./App";

export interface Props {
  model: ApplicationModelEvent;
  getTreeOffset: () => { x?: number; y?: number };
  persistStateInUrl?: boolean | undefined;
}

export const Root = memo(function Root(props: Props) {
  const model = useMemo(() => {
    return objectToCamel(props.model) as ApplicationModelEvent;
  }, [props.model]);

  const appContext = useMemo(() => {
    return createAppContext({
      model,
      getTreeOffset: props.getTreeOffset,
      persistInUrl: props.persistStateInUrl,
    });
  }, [model, props.getTreeOffset, props.persistStateInUrl]);

  return (
    <AppContext.Provider value={appContext}>
      <App />
    </AppContext.Provider>
  );
});
