import { useEffect, useRef, useState } from "react";

export interface Polled<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
}

/**
 * Poll a JSON endpoint on an interval.
 *
 * The fetcher is held in a ref so callers can pass an inline arrow function
 * without restarting the timer on every render; only `intervalMs` and the
 * supplied `deps` re-arm it. In-flight results are discarded on unmount.
 */
export function usePolled<T>(
  fetcher: () => Promise<T>,
  intervalMs: number,
  deps: readonly unknown[] = [],
): Polled<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const depsKey = deps.map((value) => String(value)).join("\u0000");

  useEffect(() => {
    let active = true;
    let timer: number | undefined;

    const run = async () => {
      try {
        const result = await fetcherRef.current();
        if (!active) return;
        setData(result);
        setError(null);
      } catch (caught) {
        if (!active) return;
        setError(caught instanceof Error ? caught.message : String(caught));
      } finally {
        if (active) {
          setLoading(false);
          timer = window.setTimeout(run, intervalMs);
        }
      }
    };

    setLoading(true);
    void run();

    return () => {
      active = false;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [intervalMs, depsKey]);

  return { data, error, loading };
}
