import clsx from "clsx";
import { memo, useCallback, useEffect } from "react";
import { useDebouncedCallback } from "~/hooks/useDebouncedCallback";
import { useTreeEntry } from "~/hooks/useTreeEntry";
import type { ApplicationProcessGroup } from "~/proto";
import { useAppState } from "~/state/AppContext";
import { getProcHash, isSuspiciousProc } from "~/utils/procs";
import { Collapsible } from "./Collapsible";
import { Connector } from "./Connector";
import css from "./Proc.module.css";
import { Statistic } from "./Statistic";
import { TextOverflow } from "./TextOverflow";

export interface ProcProps {
  proc: ApplicationProcessGroup;
  className?: string | undefined;
  childrenProcsListClassName?: string | undefined;
}

export const ProcItem = memo(function Proc(props: ProcProps) {
  const state = useAppState();

  const info = state.processesMap.get(props.proc);

  const entry = useTreeEntry({
    statInfo: state.stat.processesMap.get(props.proc),
  });

  const update = useCallback(
    (visible = true) => {
      const info = state.processesMap.get(props.proc) ?? null;

      const xy = entry.connector.getXY();

      if (info && info.visible === visible && info.xy?.x === xy?.x && info.xy?.y === xy?.y) {
        return;
      }

      state.updateProcess(props.proc, visible, xy);
    },
    [state, props.proc, entry],
  );

  // biome-ignore lint/correctness/useExhaustiveDependencies: don't do unnecessary unmounts
  useEffect(() => {
    update(true);
    return () => {
      state.updateProcess(props.proc, false, undefined);
    };
  }, [state, props.proc]);

  const debouncedUpdate = useDebouncedCallback(update);

  useEffect(() => {
    return state.onTreeChanged(() => {
      debouncedUpdate();
    });
  }, [state, debouncedUpdate]);

  useEffect(() => {
    return state.onEndpointUpdated(() => {
      debouncedUpdate();
    });
  }, [state, debouncedUpdate]);

  const highlight = useCallback(() => {
    state.highlightProc(props.proc, true);
  }, [state, props.proc]);

  const unhighlight = useCallback(() => {
    state.highlightProc(props.proc, false);
  }, [state, props.proc]);

  const children = props.proc.children ?? [];

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

  if (!info) {
    return null;
  }

  return (
    <li className={className} onMouseEnter={highlight} onMouseLeave={unhighlight}>
      {children.length ? (
        <Collapsible
          path={info.path}
          summary={({ onClick }) => (
            <summary className={entry.className} onClick={onClick}>
              <div className={css.inner}>
                <Binary name={props.proc.name} /> <Arguments arguments={props.proc.arguments} />
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
        <div className={clsx(css.inner, entry.className)}>
          <Binary name={props.proc.name} /> <Arguments arguments={props.proc.arguments} />
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
  procs: ApplicationProcessGroup[];
  className?: string | undefined;
  procItemClassName?: string | undefined;
}

export const ProcsList = memo(function ProcsList(props: ProcsListProps) {
  return (
    <ul className={clsx(css.list, props.className)}>
      {props.procs.map((proc) => {
        return (
          <ProcItem
            key={getProcHash(proc)}
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
  return <TextOverflow text={props.name ?? "-"} trimSide="left" title={props.name} />;
}

function Arguments(props: { arguments?: string | undefined }) {
  return (
    <TextOverflow
      text={props.arguments ?? ""}
      trimSide="right"
      title={props.arguments}
      className={css.arguments}
    />
  );
}
