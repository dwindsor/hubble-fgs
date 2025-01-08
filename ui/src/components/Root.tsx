import { memo, useMemo, useRef } from "react";
import { AppContext, createAppContext } from "~/state/AppContext";
import { ApplicationModelEvent } from "~/proto";
import { App } from "./App";

export interface Props {
  model: ApplicationModelEvent;
}

export const Root = memo(function Root(props: Props) {
  const appRef = useRef<HTMLDivElement>(null);

  const appContext = useMemo(
    () =>
      createAppContext({
        model: props.model,
        getTreeOffset: () => window.scrollY,
      }),
    [props.model, appRef]
  );

  return (
    <AppContext.Provider value={appContext}>
      <App appRef={appRef} />
    </AppContext.Provider>
  );
});
