import { createRoot } from "react-dom/client";
import { Root } from "./components/Root";
import type { ApplicationModelEvent } from "./proto";
import { assert } from "./utils/assert";

const dom = document.getElementById("container");
assert(dom, "dom node doesn't exist");

const root = createRoot(dom);

declare global {
  interface Window {
    APP_MODEL_JSON?: ApplicationModelEvent;
  }
}

const promise = new Promise<ApplicationModelEvent>((resolve, reject) => {
  if (process.env.NODE_ENV === "development") {
    import("./dev-model").then((m) => {
      resolve(m.model as unknown as ApplicationModelEvent);
    });
  } else {
    const model = window.APP_MODEL_JSON;
    if (!model) {
      reject(new Error("window.APP_MODEL_JSON should be in HTML"));
      return;
    }
    resolve(model);
  }
});

promise
  .then((model) => {
    root.render(
      <Root persistStateInUrl model={model} getTreeOffset={() => ({ x: -7.5, y: -7.5 })} />,
    );
  })
  .catch((error) => {
    console.error(error);
  });
