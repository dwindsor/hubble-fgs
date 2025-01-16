import { useCallback, useMemo } from "react";
import { useAppState } from "~/state/AppContext";

export interface Props {
  endpoint: string;
}

export function useConnector(ref: React.RefObject<HTMLDivElement | null>) {
  const state = useAppState();

  const getXY = useCallback(() => {
    if (!ref.current) return;
    const box = ref.current.getBoundingClientRect();
    const offset = state.getTreeOffset();
    return {
      x: box.x + 2.5 + (offset.x ?? 0),
      y: box.y + 2.5 + (offset.y ?? 0),
    };
  }, [ref]);

  return useMemo(
    () => ({
      getXY,
    }),
    [getXY]
  );
}
