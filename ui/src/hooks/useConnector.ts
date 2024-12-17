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
    return { x: box.x + 2.5, y: box.y + 2.5 + state.getTreeOffset() };
  }, [ref]);

  return useMemo(
    () => ({
      getXY,
    }),
    [getXY]
  );
}
