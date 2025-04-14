import type { ComponentProps } from "react";

import css from "./Checkbox.module.css";

export function Checkbox(props: ComponentProps<"input">) {
  return (
    <input
      type="checkbox"
      {...props}
      className={`${css.element} ${props.className ? props.className : ""}`}
    />
  );
}
