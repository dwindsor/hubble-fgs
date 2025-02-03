import { useEffect } from "react";

export function useElementScroll(
  ref: React.RefObject<HTMLDivElement | null>,
  callback: () => void,
) {
  useEffect(() => {
    const dom = ref.current;
    if (!dom) return;
    dom.addEventListener("scroll", callback);
    return () => {
      dom.removeEventListener("scroll", callback);
    };
  }, [ref.current, callback]);
}
