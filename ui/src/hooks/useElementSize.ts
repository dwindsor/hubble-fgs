import { useCallback, useEffect, useLayoutEffect, useState } from "react";
import type { WH } from "~/utils/geometry";

export function useElementSize(ref: React.RefObject<HTMLDivElement | null>) {
  const [size, setSize] = useState<WH | null>(null);

  const set = useCallback(() => {
    setSize((prev) => {
      if (!ref.current) {
        return prev;
      }
      const width = ref.current.scrollWidth;
      const height = ref.current.scrollHeight;
      if (prev?.width === width && prev?.height === height) {
        return prev;
      }
      return {
        width,
        height,
      };
    });
  }, [ref.current]);

  useLayoutEffect(() => set(), [set]);

  useEffect(() => {
    if (!ref.current) return;
    const resizeObserver = new ResizeObserver(() => {
      set();
    });
    resizeObserver.observe(ref.current);
    return () => resizeObserver.disconnect();
  }, [ref.current, set]);

  return size;
}
