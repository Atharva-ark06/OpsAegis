import { useEffect, useRef } from "react";

export const DATA_CHANGED_EVENT = "opsaegis:data-changed";

export interface LiveRefreshOptions {
  enabled?: boolean;
  intervalMs?: number;
}

/**
 * Keeps a mounted workspace synchronized with persisted API state.
 * Polling pauses in background tabs; successful API mutations and tab focus
 * trigger an immediate refresh. A single in-flight refresh is allowed.
 */
export function useLiveRefresh(
  refresh: () => void | Promise<void>,
  { enabled = true, intervalMs = 15000 }: LiveRefreshOptions = {},
): void {
  const refreshRef = useRef(refresh);
  const runningRef = useRef(false);
  const lastRunRef = useRef(0);

  useEffect(() => {
    refreshRef.current = refresh;
  }, [refresh]);

  useEffect(() => {
    if (!enabled) return;
    let active = true;

    const run = () => {
      if (!active || document.visibilityState === "hidden" || runningRef.current) return;
      const now = Date.now();
      if (now - lastRunRef.current < 1000) return;
      runningRef.current = true;
      lastRunRef.current = now;
      Promise.resolve(refreshRef.current()).catch(() => {
        // The owning workspace retains and renders its own last-known data/error state.
      }).finally(() => {
        runningRef.current = false;
      });
    };

    const timer = window.setInterval(run, intervalMs);
    window.addEventListener(DATA_CHANGED_EVENT, run);
    window.addEventListener("focus", run);
    document.addEventListener("visibilitychange", run);

    return () => {
      active = false;
      window.clearInterval(timer);
      window.removeEventListener(DATA_CHANGED_EVENT, run);
      window.removeEventListener("focus", run);
      document.removeEventListener("visibilitychange", run);
    };
  }, [enabled, intervalMs]);
}
