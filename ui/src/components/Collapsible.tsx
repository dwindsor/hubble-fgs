import hashsum from "hash-sum";
import { type ReactNode, memo, useCallback, useMemo, useState } from "react";
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

  const [open, setOpen] = useState(state.treePathsMap.get(pathHash) ?? props.initialOpen ?? false);

  const onClick = useCallback(
    (event: React.MouseEvent) => {
      event.preventDefault();
      setOpen((prev) => {
        const next = !prev;
        state.treePathsMap.set(pathHash, next);
        return next;
      });
    },
    [state.treePathsMap, pathHash],
  );

  return (
    <details open={open}>
      {props.summary({ opened: open, onClick })}
      {open && props.children}
    </details>
  );
});
