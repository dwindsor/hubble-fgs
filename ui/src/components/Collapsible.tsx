import hashsum from "hash-sum";
import { type ReactNode, memo, useCallback, useEffect, useMemo, useState } from "react";
import { useAppState } from "~/state/AppContext";
import type { TreePath } from "~/types";

export interface Props {
  path: TreePath;
  initialOpen?: boolean;
  summary: (arg: {
    opened: boolean;
    onClick: (event: React.MouseEvent) => void;
  }) => ReactNode;
  children: ReactNode | ReactNode[];
}

export const Collapsible = memo(function Collapsible(props: Props) {
  const state = useAppState();

  const pathHash = useMemo(() => hashsum(props.path), [props.path]);

  const [expanded, setExpanded] = useState(
    state.getTreePathStatus(pathHash)?.expanded ?? props.initialOpen ?? false,
  );

  useEffect(() => {
    state.setTreePathStatus(pathHash, { visible: true });
    return () => {
      state.setTreePathStatus(pathHash, { visible: false });
    };
  }, [state, pathHash]);

  const onClick = useCallback(
    (event: React.MouseEvent) => {
      event.preventDefault();
      setExpanded((prev) => {
        const next = !prev;
        state.setTreePathStatus(pathHash, { expanded: next });
        return next;
      });
    },
    [state, pathHash],
  );

  return (
    <details open={expanded}>
      {props.summary({ opened: expanded, onClick })}
      {expanded && props.children}
    </details>
  );
});
