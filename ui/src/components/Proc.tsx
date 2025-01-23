import clsx from "clsx";
import debounce from "lodash/debounce";
import { memo, useCallback, useEffect, useMemo } from "react";
import { useTreeEntry } from "~/hooks/useTreeEntry";
import type { ApplicationProcess } from "~/proto";
import { useAppState } from "~/state/AppContext";
import { isSuspiciousProc } from "~/utils/procs";
import { Collapsible } from "./Collapsible";
import { Connector } from "./Connector";
import css from "./Proc.module.css";
import { Statistic } from "./Statistic";

export interface ProcProps {
  proc: ApplicationProcess;
  className?: string | undefined;
  childrenProcsListClassName?: string | undefined;
}

export const Proc = memo(function Proc(props: ProcProps) {
  const state = useAppState();

  const procInfo = state.processesMap.get(props.proc) ?? null;

  const entry = useTreeEntry({
    statInfo: state.stat.processesMap.get(props.proc),
  });

  const update = useCallback(
    (visible = true) => {
      const xy = entry.connector.getXY();

      if (
        procInfo &&
        procInfo.visible === visible &&
        procInfo.xy?.x === xy?.x &&
        procInfo.xy?.y === xy?.y
      ) {
        return;
      }

      state.updateProcess(props.proc, visible, xy);
    },
    [state, props.proc, procInfo, entry],
  );

  const debouncedUpdate = useMemo(() => {
    return debounce(update);
  }, [update]);

  const highlight = useCallback(() => {
    state.highlightProc(props.proc, true);
  }, [state, props.proc]);

  const unhighlight = useCallback(() => {
    state.highlightProc(props.proc, false);
  }, [state, props.proc]);

  const children = props.proc.children ?? [];

  useEffect(() => {
    update(true);
    return () => {
      state.updateProcess(props.proc, false, undefined);
    };
  }, [state, props.proc, update]);

  useEffect(() => {
    return state.onAppSizeChanged(() => debouncedUpdate());
  }, [state, debouncedUpdate]);

  useEffect(() => {
    return debouncedUpdate();
  }, [debouncedUpdate]);

  useEffect(() => {
    return state.onProcHighlight((proc, value) => {
      if (!proc || !value) {
        entry.setVisualState("base");
        return;
      }
      if (proc === props.proc && value) {
        entry.setVisualState("highlighted");
        return;
      }
      entry.setVisualState("muted");
      return;
    });
  }, [state, entry, props.proc]);

  const className = clsx(css.proc, props.className, {
    [css.suspicious]: isSuspiciousProc(props.proc),
  });

  const innerClassName = clsx(css.inner, entry.className);

  return (
    <li className={className} onMouseEnter={highlight} onMouseLeave={unhighlight}>
      {children.length ? (
        <Collapsible
          summary={({ onClick }) => (
            <summary className={innerClassName} onClick={onClick}>
              <div>
                <Binary name={props.proc.name} />{" "}
                <span className={css.arguments} title={props.proc.arguments}>
                  {props.proc.arguments}
                </span>
                {entry.stat && <Statistic stat={entry.stat} />}
                {entry.hasConnections && (
                  <Connector connector={entry.connector} endpoints={entry.connectorEndpoints} />
                )}
              </div>
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
        <div className={innerClassName}>
          <Binary name={props.proc.name} />{" "}
          <span className={css.arguments} title={props.proc.arguments}>
            {props.proc.arguments}
          </span>
          {entry.stat && <Statistic stat={entry.stat} />}
          {entry.hasConnections && (
            <Connector connector={entry.connector} endpoints={entry.connectorEndpoints} />
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
        const key = `${proc.name}:[${proc.arguments}]`;
        return (
          <Proc
            key={key}
            proc={proc}
            className={clsx(props.procItemClassName)}
            childrenProcsListClassName={props.className}
          />
        );
      })}
    </ul>
  );
});

function Binary(props: { name?: string | undefined }) {
  return (
    <span className={css.binary}>
      &lrm;
      {/* needed to fix text-overflow */}
      {props.name ?? "-"}
      &lrm;
      {/* needed to fix text-overflow */}
    </span>
  );
}
