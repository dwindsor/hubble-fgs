import { type ReactNode, memo, useCallback, useEffect, useMemo, useState } from "react";
import { useAppState } from "~/state/AppContext";
import { type TreePath, calcTreePathHash } from "~/utils/tree";

export interface Props {
  path: TreePath;
  initialOpen?: boolean;
  summary: (arg: { opened: boolean; onClick: (event: React.MouseEvent) => void }) => ReactNode;
  children: ReactNode | ReactNode[];
}

export const Collapsible = memo(function Collapsible(props: Props) {
  const state = useAppState();

  const pathHash = useMemo(() => calcTreePathHash(props.path), [props.path]);

  const [expanded, setExpanded] = useState(
    state.getTreePathStatus(pathHash)?.expanded ?? props.initialOpen ?? false,
  );

  useEffect(() => {
    return state.onTreePathStatusChanged((changedPath, changedPathStatus) => {
      const changedPathHash = calcTreePathHash(changedPath);
      if (pathHash !== changedPathHash) {
        return;
      }
      setExpanded(!!changedPathStatus.expanded);
    });
  }, [state, pathHash]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: ignore "expanded" specificaly, we only want to control visibility
  useEffect(() => {
    state.setTreePathStatus(props.path, { visible: true, expanded });
    return () => {
      state.setTreePathStatus(props.path, { visible: false });
    };
  }, [state, props.path]);

  const onClick = useCallback(
    (event: React.MouseEvent) => {
      event.preventDefault();
      state.toggleTreePath(props.path);
    },
    [state, props.path],
  );

  return (
    <details open={expanded}>
      {props.summary({ opened: expanded, onClick })}
      {expanded && props.children}
    </details>
  );
});
