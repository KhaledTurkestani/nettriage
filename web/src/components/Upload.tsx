import { useRef, useState } from "react";

import { type Config, uploadCapture } from "../api";
import { go } from "../hooks";
import { Notice } from "./bits";

/** Pick or drop a capture file. It is sent to the server, read there, and opened when ready. */
export function Upload({ config }: { config: Config }) {
  const input = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [over, setOver] = useState(false);

  async function send(file: File | undefined) {
    if (!file || busy) return;
    setError(null);
    const suffix = file.name.slice(file.name.lastIndexOf(".")).toLowerCase();
    if (!config.upload_suffixes.includes(suffix)) {
      setError(`Choose a file ending in ${config.upload_suffixes.join(", ")}.`);
      return;
    }
    if (file.size > config.max_upload_mb * 1024 * 1024) {
      setError(`That file is larger than ${config.max_upload_mb} MB.`);
      return;
    }
    setBusy(file.name);
    try {
      const capture = await uploadCapture(file);
      go(`/captures/${encodeURIComponent(capture.id)}`);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : String(problem));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div>
      <button
        type="button"
        className={`dropzone${over ? " is-over" : ""}`}
        disabled={busy !== null}
        onClick={() => input.current?.click()}
        onDragOver={(event) => {
          event.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(event) => {
          event.preventDefault();
          setOver(false);
          void send(event.dataTransfer.files[0]);
        }}
      >
        {busy ? (
          <>
            <strong>Reading {busy}…</strong>
            <span className="muted">Large packet captures take a while: about 12,000 packets a second.</span>
          </>
        ) : (
          <>
            <strong>Add a capture</strong>
            <span className="muted">
              Drop a packet capture ({config.upload_suffixes.filter((s) => s !== ".csv").join(", ")}) or a CICFlowMeter
              .csv here, or click to choose. Up to {config.max_upload_mb} MB.
            </span>
          </>
        )}
      </button>
      <input
        ref={input}
        type="file"
        hidden
        accept={config.upload_suffixes.join(",")}
        onChange={(event) => {
          void send(event.target.files?.[0]);
          event.target.value = "";
        }}
      />
      {error && <Notice kind="error">{error}</Notice>}
    </div>
  );
}
