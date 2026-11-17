import { getConfig } from "./api";
import { useLoad, useRoute } from "./hooks";
import { CapturePage } from "./pages/CapturePage";
import { HomePage } from "./pages/HomePage";
import { RunPage } from "./pages/RunPage";

export function App() {
  const route = useRoute();
  const config = useLoad(getConfig, "config");
  const [, section, id] = route.split("/");

  let page;
  if (section === "captures" && id) page = <CapturePage key={id} id={decodeURIComponent(id)} config={config.data} />;
  else if (section === "runs" && id) page = <RunPage key={id} id={decodeURIComponent(id)} />;
  else page = <HomePage config={config.data} />;

  return (
    <>
      <header className="topbar">
        <a className="brand" href="#/">
          <svg viewBox="0 0 32 32" width="26" height="26" aria-hidden="true">
            <rect width="32" height="32" rx="7" fill="var(--accent)" />
            <path
              d="M7 21l6-9 5 6 3-4 4 7"
              fill="none"
              stroke="var(--on-accent)"
              strokeWidth="2.4"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          <span>NetTriage</span>
        </a>
        <span className="tagline">An AI analyst for network captures. Every claim cites its flows.</span>
        {config.data?.read_only && <span className="pill">read-only</span>}
      </header>
      <main>{page}</main>
      <footer className="footer">
        {config.data ? `NetTriage ${config.data.version}` : "NetTriage"} · reports are written by a model and checked
        against the capture; treat them as an analyst's draft.
      </footer>
    </>
  );
}
