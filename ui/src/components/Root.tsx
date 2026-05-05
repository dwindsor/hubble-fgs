import { memo, useMemo } from "react";
import { objectToSnake } from "ts-case-convert";
import type { ApplicationModelEvent } from "~/proto";
import { AppContext, createAppContext } from "~/state/AppContext";
import { injectCSSVars } from "~/theme";
import { App } from "./App";

export interface Props {
  model: ApplicationModelEvent;
  getTreeOffset: () => { x?: number; y?: number };
  persistStateInUrl?: boolean | undefined;
}

injectCSSVars();

export const Root = memo(function Root(props: Props) {
  const appContext = useMemo(() => {
    let model = props.model;
    if ("applicationModel" in props.model) {
      model = objectToSnake(props.model) as ApplicationModelEvent;
    }
    return createAppContext({
      model,
      getTreeOffset: props.getTreeOffset,
      persistInUrl: props.persistStateInUrl,
    });
  }, [props]);

  return (
    <AppContext.Provider value={appContext}>
      <App />
    </AppContext.Provider>
  );
});
