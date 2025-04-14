import { memo, useMemo } from "react";
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
    return createAppContext({
      model: props.model,
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
