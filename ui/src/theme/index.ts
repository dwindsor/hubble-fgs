import { colors } from "./colors";
import { setCSSVars } from "./utils";

export function injectCSSVars() {
  setCSSVars(colors, { keyPrefix: "color" });
}
