import { useCallback, useMemo, useRef } from "react";
import { useAppState } from "~/state/AppContext";

export interface Props {
  endpoint: string;
}

export function useConnector() {
  const ref = useRef<HTMLDivElement>(null);

  const state = useAppState();

  const getXY = useCallback(() => {
    if (!ref.current) return;
    const box = ref.current.getBoundingClientRect();
    const offset = state.getTreeOffset();
    return {
      x: box.x + box.width / 2 + (offset.x ?? 0),
      y: box.y + box.height / 2 + (offset.y ?? 0),
    };
  }, [ref]);

  return useMemo(
    () => ({
      ref,
      getXY,
    }),
    [getXY]
  );
}
