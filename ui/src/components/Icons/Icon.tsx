import { memo, ReactNode } from "react";
import clsx from "clsx";

import css from "./Icon.module.css";

export interface Props {
  size?: number;
  color?: string;
  className?: string;
  children: (color: string) => ReactNode;
}

export const Icon = memo(function Icon(props: Props) {
  const { size = 24, color = "#000" } = props;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={clsx(css.icon, props.className)}
    >
      {props.children(color)}
    </svg>
  );
});
