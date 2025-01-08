import clsx from "clsx";
import { memo, useEffect, useMemo, useRef } from "react";
import debounce from "lodash/debounce";
import { useAppState } from "~/state/AppContext";
import { ApplicationProcess } from "~/proto";
import css from "./Proc.module.css";
import { Statistic } from "./Statistic";
import { Collapsible } from "./Collapsible";
import { useConnector } from "~/hooks/useConnector";

export interface ProcProps {
  proc: ApplicationProcess;
  className?: string | undefined;
  childrenProcsListClassName?: string | undefined;
}

export const Proc = memo(function Proc(props: ProcProps) {
  const connectorRef = useRef<HTMLDivElement>(null);

  const state = useAppState();

  const connector = useConnector(connectorRef);

  const stat = useMemo(() => {
    return state.stat.processesMap.get(props.proc)!;
  }, [props.proc]);

  const hasConnections = useMemo(() => {
    const curr = state.processesMap.get(props.proc);
    return !!curr?.endpoints.size;
  }, [props.proc, state.processesMap]);

  const debouncedUpdate = useMemo(() => {
    return debounce((visible = true) => {
      const cur = state.processesMap.get(props.proc);
      const xy = connector.getXY();

      if (
        cur &&
        cur.visible === visible &&
        cur.xy?.x === xy?.x &&
        cur.xy?.y === xy?.y
      ) {
        return;
      }

      state.updateProcess(props.proc, visible, xy);
    });
  }, [props.proc, connector]);

  useEffect(() => {
    debouncedUpdate(true);
    return () => debouncedUpdate(false);
  }, []);

  useEffect(() => state.onTreeSizeChanged(debouncedUpdate), [debouncedUpdate]);

  useEffect(() => state.onTreeChanged(debouncedUpdate), [debouncedUpdate]);

  const children = props.proc.children ?? [];

  return (
    <li className={clsx(css.proc, props.className)}>
      {children.length ? (
        <Collapsible
          summary={({ opened, onClick }) => (
            <summary className={css.procLine} onClick={onClick}>
              <span>
                {props.proc.name}{" "}
                <span className={css.arguments}>{props.proc.arguments}</span>
              </span>
              {!opened && <Statistic stat={stat} />}
              {hasConnections && (
                <div ref={connectorRef} className={css.connector} />
              )}
            </summary>
          )}
        >
          <ProcsList
            procs={children}
            className={props.childrenProcsListClassName}
            procItemClassName={props.className}
          />
        </Collapsible>
      ) : (
        <div className={css.procLine}>
          <span>
            {props.proc.name}{" "}
            <span className={css.arguments}>{props.proc.arguments}</span>
            <Statistic stat={stat} />
          </span>
          {hasConnections && (
            <div ref={connectorRef} className={css.connector} />
          )}
        </div>
      )}
    </li>
  );
});

export interface ProcsListProps {
  procs: ApplicationProcess[];
  className?: string | undefined;
  procItemClassName?: string | undefined;
}

export const ProcsList = memo(function ProcsList(props: ProcsListProps) {
  return (
    <ul className={clsx(css.list, props.className)}>
      {props.procs.map((proc) => {
        return (
          <Proc
            key={proc.hash}
            proc={proc}
            className={clsx(props.procItemClassName)}
            childrenProcsListClassName={props.className}
          />
        );
      })}
    </ul>
  );
});
