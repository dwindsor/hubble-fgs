import { createRoot } from "react-dom/client";
import { Root } from "./components/Root";
import "./global.css";
import type { ApplicationModelEvent } from "./proto";

const root = createRoot(window.document.body);

declare global {
  interface Window {
    IPT_APP_MODEL_JSON?: ApplicationModelEvent;
  }
}

const promise = new Promise<ApplicationModelEvent>((resolve, reject) => {
  if (process.env.NODE_ENV === "development") {
    import("./devmodel.json")
      .then((m) => resolve(m as unknown as ApplicationModelEvent))
      .catch(reject);
    return;
  }
  const model = window.IPT_APP_MODEL_JSON;
  if (!model) {
    return reject(new Error("window.IPT_APP_MODEL_JSON should be in HTML"));
  }
  resolve(model);
});

promise
  .then((model) => {
    root.render(
      <Root
        persistStateInUrl
        model={model}
        getTreeOffset={() => ({ x: 0, y: 0 + window.scrollY })}
      />,
    );
  })
  .catch((error) => {
    console.error(error);
  });
