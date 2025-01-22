import clsx from "clsx";
import debounce from "lodash/debounce";
import { memo, useCallback, useEffect, useMemo } from "react";
import { useTreeEntry } from "~/hooks/useTreeEntry";
import { ApplicationProcess } from "~/proto";
import { useAppState } from "~/state/AppContext";
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
    [props.proc, procInfo, entry.connector]
  );

  const debouncedUpdate = useMemo(() => {
    return debounce(update);
  }, [update]);

  const highlight = useCallback(() => {
    state.toggleProcHighlight(props.proc, true);
  }, [props.proc]);

  const unhighlight = useCallback(() => {
    state.toggleProcHighlight(props.proc, false);
  }, [props.proc]);

  const children = props.proc.children ?? [];

  useEffect(() => {
    update(true);
    return () => {
      state.updateProcess(props.proc, false, undefined);
    };
  }, []);

  useEffect(() => {
    return state.onAppSizeChanged(() => debouncedUpdate());
  }, [debouncedUpdate]);

  useEffect(() => {
    return debouncedUpdate();
  }, [entry.endpoint]);

  useEffect(() => {
    return state.onToggleProcHighlight((proc, value) => {
      if (!proc || !value) {
        entry.setVisualState("base");
        return;
      } else if (proc === props.proc && value) {
        entry.setVisualState("highlighted");
        return;
      } else {
        entry.setVisualState("muted");
        return;
      }
    });
  }, [props.proc]);

  return (
    <li
      className={clsx(css.proc, props.className)}
      onMouseEnter={highlight}
      onMouseLeave={unhighlight}
    >
      {children.length ? (
        <Collapsible
          summary={({ onClick }) => (
            <summary
              className={clsx(css.inner, entry.className)}
              onClick={onClick}
            >
              <div>
                <Binary name={props.proc.name} />{" "}
                <span className={css.arguments} title={props.proc.arguments}>
                  {props.proc.arguments}
                </span>
                {entry.stat && <Statistic stat={entry.stat} />}
                {entry.hasConnections && (
                  <Connector
                    connector={entry.connector}
                    endpoints={entry.connectorEndpoints}
                  />
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
        <div className={clsx(css.inner, entry.className)}>
          <Binary name={props.proc.name} />{" "}
          <span className={css.arguments} title={props.proc.arguments}>
            {props.proc.arguments}
          </span>
          {entry.stat && <Statistic stat={entry.stat} />}
          {entry.hasConnections && (
            <Connector
              connector={entry.connector}
              endpoints={entry.connectorEndpoints}
            />
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

function Binary(props: { name?: string | undefined }) {
  return (
    <span className={css.binary}>
      <>&lrm;</>
      {/* needed to fix text-overflow */}
      {props.name ?? "-"}
      <>&lrm;</>
      {/* needed to fix text-overflow */}
    </span>
  );
}
