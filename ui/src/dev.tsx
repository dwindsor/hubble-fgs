import { createRoot } from "react-dom/client";
import { Root } from "./components/Root";
import { model as devModel } from "./dev-model";
import { ApplicationModelEvent } from "./proto";

const dom = document.getElementById("container");
if (!dom) {
  throw new Error("dom node doesn't exist");
}
const root = createRoot(dom);

declare global {
  interface Window {
    APP_MODEL_JSON?: ApplicationModelEvent;
  }
}

const globalModel = window.APP_MODEL_JSON;
const model = (globalModel ? globalModel : devModel) as ApplicationModelEvent;

root.render(
  <Root model={model} getTreeOffset={() => ({ x: -7.5, y: -7.5 })} />
);
