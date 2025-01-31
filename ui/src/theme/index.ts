import { colors } from "./colors";
import { setCSSVars } from "./utils";
import { zindex } from "./vars";

export function injectCSSVars() {
  setCSSVars(colors, { keyPrefix: "color" });
  setCSSVars(zindex, { keyPrefix: "z-index" });
}
