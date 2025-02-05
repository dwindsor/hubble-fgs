import { colors } from "./colors";
import { setCSSVars } from "./utils";
import { fonts, zindex } from "./vars";

export function injectCSSVars() {
  setCSSVars(colors, { keyPrefix: "color" });
  setCSSVars(zindex, { keyPrefix: "z-index" });
  setCSSVars(fonts, { keyPrefix: "font" });
}
