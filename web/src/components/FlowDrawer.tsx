import { useEffect, useRef } from "react";

import { getFlows } from "../api";
import { bytes, clock, duration, oneLine, plural, protocol } from "../format";
import { useLoad } from "../hooks";
import { Loading, Notice } from "./bits";
import { DataTable } from "./DataTable";
import type { FlowRequest } from "./ReportView";

const FLAGS: [string, string][] = [
  ["syn_count", "SYN"],
  ["fin_count", "FIN"],
  ["rst_count", "RST"],
  ["psh_count", "PSH"],
  ["ack_count", "ACK"],
];

/** The flows a piece of evidence cites, read from the capture itself. */
export function FlowDrawer({
  captureId,
  request,
  onClose,
}: {
  captureId: string;
  request: FlowRequest;
  onClose: () => void;
}) {
  const ids = request.ids.slice(0, 200);
  const flows = useLoad(() => getFlows(captureId, ids), `${captureId}:${ids.join(",")}`);
  const close = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    close.current?.focus();
    const onKey = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  let table = null;
  if (flows.data) {
    const at = (name: string) => flows.data!.columns.indexOf(name);
    const rows = flows.data.rows.map((row) => {
      const get = (name: string) => row[at(name)];
      const flags = FLAGS.filter(([column]) => Number(get(column)) > 0)
        .map(([column, word]) => `${word} ${get(column)}`)
        .join(" · ");
      return [
        get("flow_id"),
        clock(get("ts") as string),
        `${get("src_ip")}:${get("src_port")}`,
        `${get("dst_ip")}:${get("dst_port")}`,
        protocol(get("protocol") as number),
        duration(get("duration_us") as number),
        `${get("fwd_pkts")} / ${get("bwd_pkts")}`,
        `${bytes(get("fwd_bytes") as number)} / ${bytes(get("bwd_bytes") as number)}`,
        flags || (get("syn_count") == null ? "not recorded" : "none"),
      ];
    });
    table = (
      <DataTable
        caption="Cited flows"
        columns={["flow", "started", "from", "to", "protocol", "lasted", "packets out / back", "payload out / back", "TCP flags"]}
        rows={rows}
        highlight={(row) => row[0] === request.focus}
      />
    );
  }

  return (
    <aside className="drawer" role="dialog" aria-label="Cited flows">
      <header>
        <div>
          <strong>{plural(ids.length, "cited flow")}</strong>
          <span className="muted"> · {oneLine(request.title, 140)}</span>
        </div>
        <button ref={close} type="button" className="link" onClick={onClose}>
          Close
        </button>
      </header>
      {flows.loading && <Loading what="flows" />}
      {flows.error && <Notice kind="error">{flows.error}</Notice>}
      {table}
      {flows.data && flows.data.missing.length > 0 && (
        <Notice kind="error">Not in the capture: {flows.data.missing.join(", ")}.</Notice>
      )}
      <p className="muted small">
        These rows come straight from the capture, not from the model. Payload counts leave out packet headers.
      </p>
    </aside>
  );
}
