import clsx from "clsx";
import { memo, useMemo } from "react";
import css from "./TextOverflow.module.css";

export interface Props {
  text: string;
  trimSide?: "left" | "center" | "right";
}

export const TextOverflow = memo((props: Props) => {
  const { trimSide = "right" } = props;

  const className = clsx(css.text, css[`trim-${trimSide}`]);

  const text = useMemo(() => {
    if (props.trimSide !== "center" || props.text.length < 8) {
      return props.text;
    }
    const pivot = Math.round(props.text.length / 2);
    const leftText = props.text.substring(0, pivot);
    const rightText = props.text.substring(pivot);

    if (props.text === "/usr/bin/cilium-agent") {
      console.log("text", leftText, rightText);
    }

    return (
      <>
        <span className={css.ellipsis}>{leftText}</span>
        <span className={css.indent}>{rightText}</span>
      </>
    );
  }, [props.text, props.trimSide]);

  return (
    <span className={className}>
      &lrm;
      {/* needed to fix text-overflow */}
      {text}
      &lrm;
      {/* needed to fix text-overflow */}
    </span>
  );
});
