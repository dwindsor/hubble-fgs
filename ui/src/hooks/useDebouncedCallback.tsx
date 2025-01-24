import debounce from "lodash/debounce";
import { useEffect, useMemo } from "react";

export function useDebouncedCallback(callback: () => void) {
  const debouncedCallback = useMemo(() => {
    return debounce(callback);
  }, [callback]);

  useEffect(() => {
    return debouncedCallback();
  }, [debouncedCallback]);

  return debouncedCallback;
}
