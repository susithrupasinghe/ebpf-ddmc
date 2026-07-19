import { useEffect, useRef, useState } from 'react';

/**
 * Polls `fetchFn` every `intervalMs` and keeps the latest resolved value in
 * state. Ignores results from a call that resolves after a newer one has
 * already started, so a slow response can't clobber fresher data.
 */
export function usePolling(fetchFn, intervalMs = 2000, initial = null) {
  const [data, setData] = useState(initial);
  const seq = useRef(0);

  useEffect(() => {
    let cancelled = false;
    let timer;

    async function tick() {
      const id = ++seq.current;
      try {
        const result = await fetchFn();
        if (!cancelled && id === seq.current) setData(result);
      } catch (err) {
        console.error('EDDMC poll failed:', err && err.message);
      }
      if (!cancelled) timer = setTimeout(tick, intervalMs);
    }

    tick();
    return () => { cancelled = true; clearTimeout(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs]);

  return data;
}
