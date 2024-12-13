import { Stat } from "~/state/utils";
import css from "./Statistic.module.css";

export interface Props {
  stat: Stat;
}

export function Statistic(props: Props) {
  if (true) {
    return null;
  }

  return (
    <span className={css.wrapper}>
      {props.stat.bytesSent > 0 && `${props.stat.bytesSent} bytes sent`}
    </span>
  );
}
