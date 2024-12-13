import { useEffect, useLayoutEffect, useState } from "react";
import { useAppState } from "~/state/AppContext";
import { WH } from "../types";

export function useTree(ref: React.RefObject<HTMLDivElement | null>) {
  const state = useAppState();

  const [size, setSize] = useState<WH | null>(null);

  useLayoutEffect(() => {
    if (!ref.current) return;
    setSize({
      width: ref.current.scrollWidth,
      height: ref.current.scrollHeight,
    });
  }, []);

  useEffect(() => {
    if (!ref.current) return;
    const resizeObserver = new ResizeObserver(() => {
      if (!ref.current) return;
      setSize({
        width: ref.current.scrollWidth,
        height: ref.current.scrollHeight,
      });
    });
    resizeObserver.observe(ref.current);
    return () => resizeObserver.disconnect();
  }, []);

  useEffect(() => {
    if (size) {
      state.changeAppSize(size);
    }
  }, [size]);

  return { size };
}
