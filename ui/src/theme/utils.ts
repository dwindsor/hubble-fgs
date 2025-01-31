import kebabCase from "lodash/kebabCase";

export const ALL_CSS_VARS_PREFIX = "ipt"; // "isovalent process tree" ¯\_(ツ)_/¯

export function setCSSVars(
  vars: Record<string, number | string>,
  opts?: { keyPrefix?: string; valSuffix?: string },
) {
  Object.entries(vars).forEach(([key, value]) => {
    let cssvar = kebabCase(key);
    if (opts?.keyPrefix) {
      cssvar = `${opts.keyPrefix}-${cssvar}`;
    }
    cssvar = `--${ALL_CSS_VARS_PREFIX}-${cssvar}`;
    let val = value;
    if (opts?.valSuffix) {
      val = `${val}${opts.valSuffix}`;
    }
    document.documentElement.style.setProperty(cssvar, String(val));
  });
}
