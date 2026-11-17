import { useCallback, useEffect, useState } from "react";

export type Loaded<T> = { data: T | null; error: string | null; loading: boolean; reload: () => void };

/** Load something from the server when the component appears or `key` changes. */
export function useLoad<T>(load: () => Promise<T>, key: string): Loaded<T> {
  const [state, setState] = useState<{ data: T | null; error: string | null; loading: boolean }>({
    data: null,
    error: null,
    loading: true,
  });
  const [version, setVersion] = useState(0);

  useEffect(() => {
    let current = true;
    setState((before) => ({ ...before, loading: true, error: null }));
    load().then(
      (data) => current && setState({ data, error: null, loading: false }),
      (error: unknown) =>
        current && setState({ data: null, error: error instanceof Error ? error.message : String(error), loading: false }),
    );
    return () => {
      current = false;
    };
    // `load` is a new function on every render; `key` says when the request really changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, version]);

  const reload = useCallback(() => setVersion((v) => v + 1), []);
  return { ...state, reload };
}

/** The part of the address after "#", e.g. "/runs/abc". */
export function useRoute(): string {
  const read = () => window.location.hash.replace(/^#/, "") || "/";
  const [route, setRoute] = useState(read);
  useEffect(() => {
    const onChange = () => {
      setRoute(read());
      window.scrollTo(0, 0);
    };
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}

export function go(route: string): void {
  window.location.hash = route;
}
