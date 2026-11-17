// Everything the page asks the server goes through this file.
//
// Paths are relative ("api/..."), so the page works wherever it is served from.
// Text that comes back in a run (tool output, report prose) was written by a
// model reading traffic an attacker may have crafted. It is only ever placed in
// the page as text.

export type CaptureKind = "upload" | "dataset" | "eval case";

export type Capture = {
  id: string;
  source: string;
  original_name: string;
  created_at: string;
  flow_count: number;
  dns_count: number;
  http_count: number;
  first_ts: string | null;
  last_ts: string | null;
  notes: Record<string, unknown>;
  kind: CaptureKind;
  runs: number;
};

export type Overview = {
  source: string;
  first_flow: string;
  last_flow: string;
  flows: number;
  dns_rows: number;
  http_rows: number;
  protocols: { protocol: number; flows: number }[];
  top_sources: { src_ip: string; flows: number; dst_ips: number; dst_ports: number; bytes: number }[];
  top_destinations: { dst_ip: string; flows: number; src_ips: number; dst_ports: number }[];
  top_destination_ports: { dst_port: number; protocol: number; flows: number; src_ips: number }[];
  timeline: { start: string; flows: number; src_ips: number }[];
  timeline_bucket_seconds: number;
};

export type RunSummary = {
  run_id: string;
  capture_id: string;
  status: RunStatus;
  verdict: Verdict | null;
  findings: number;
  tool_calls: number;
  cost_usd: number | null;
  started_at: string | null;
};

export type CaptureDetail = Capture & { overview: Overview | null; run_list: RunSummary[] };

export type Verdict = "malicious_activity" | "no_malicious_activity" | "inconclusive";
export type RunStatus = "running" | "completed" | "refused" | "failed";

export type Evidence = { claim: string; flow_ids: number[] };

export type Finding = {
  title: string;
  attack_type: string;
  severity: "low" | "medium" | "high" | "critical";
  confidence: "low" | "medium" | "high";
  attacker_ips: string[];
  victim_ips: string[];
  first_seen: string;
  last_seen: string;
  description: string;
  evidence: Evidence[];
};

export type Report = { verdict: Verdict; summary: string; findings: Finding[]; limitations: string[] };

export type Usage = {
  input_tokens: number;
  output_tokens: number;
  cache_creation_input_tokens: number;
  cache_read_input_tokens: number;
};

export type ModelEvent = {
  n: number;
  type: "model";
  stop_reason: string | null;
  served_by: string;
  thinking: string[];
  text: string;
  tool_calls: { name: string; input: Record<string, unknown> }[];
  usage: Usage;
};
export type ToolEvent = {
  n: number;
  type: "tool";
  name: string;
  input: Record<string, unknown>;
  output: string;
  is_error: boolean;
  ms: number;
};
export type CheckEvent = {
  n: number;
  type: "evidence_check";
  round: number;
  findings: number;
  rejected: { finding: string; problems: string[] }[];
};
export type ReportEvent = { n: number; type: "report"; verdict: Verdict; findings: number };
export type EndEvent = { n: number; type: "end"; status: RunStatus; error: string | null };
export type RunEvent = ModelEvent | ToolEvent | CheckEvent | ReportEvent | EndEvent;

export type RunRecord = {
  run_id: string;
  capture_id: string;
  model: string;
  effort: string;
  status: RunStatus;
  report: Report | null;
  events: RunEvent[];
  error?: string | null;
  prompt?: string;
  max_tool_calls?: number;
  validation?: {
    findings_reported?: number;
    rejected_on_first_check?: number;
    correction_round?: boolean;
    findings_removed?: number;
    findings_kept?: number;
  };
  usage?: Usage;
  cost_usd?: number | null;
  api_calls?: number;
  tool_calls?: number;
  fallback_used?: boolean;
  served_by?: string[];
  started_at?: string;
  finished_at?: string;
};

export type Config = {
  version: string;
  read_only: boolean;
  can_investigate: boolean;
  can_upload: boolean;
  max_upload_mb: number;
  upload_suffixes: string[];
  default_model: string;
  models: { id: string; default_effort: string; input_per_mtok: number; output_per_mtok: number }[];
  prompt: string;
  prompts: string[];
  default_max_tool_calls: number;
  max_tool_calls_limit: number;
};

export type FlowRows = { columns: string[]; rows: (string | number | null)[][]; missing: number[] };

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`api/${path}`, init);
  } catch {
    throw new ApiError("The server did not answer. Is it still running?", 0);
  }
  if (!response.ok) {
    let detail = `The server answered ${response.status}.`;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") detail = body.detail;
    } catch {
      // Not JSON: keep the generic message.
    }
    throw new ApiError(detail, response.status);
  }
  return (await response.json()) as T;
}

export const getConfig = () => request<Config>("config");
export const listCaptures = () => request<Capture[]>("captures");
export const getCapture = (id: string) => request<CaptureDetail>(`captures/${encodeURIComponent(id)}`);
export const listRuns = () => request<RunSummary[]>("runs");
export const getRun = (id: string) => request<RunRecord>(`runs/${encodeURIComponent(id)}`);

export const getFlows = (captureId: string, ids: number[]) =>
  request<FlowRows>(`captures/${encodeURIComponent(captureId)}/flows?ids=${ids.join(",")}`);

export const uploadCapture = (file: File) =>
  request<Capture>(`captures?name=${encodeURIComponent(file.name)}`, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: file,
  });

export type StartRunInput = { capture_id: string; model: string; max_tool_calls: number };

export const startRun = (input: StartRunInput) =>
  request<RunRecord>("runs", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });

/** Follow a running investigation. Returns a function that stops listening. */
export function followRun(
  runId: string,
  after: number,
  onEvent: (event: RunEvent) => void,
  onDone: () => void,
  onLost: () => void,
): () => void {
  const source = new EventSource(`api/runs/${encodeURIComponent(runId)}/events?after=${after}`);
  let closed = false;
  const close = () => {
    closed = true;
    source.close();
  };
  source.onmessage = (message) => {
    try {
      onEvent(JSON.parse(message.data) as RunEvent);
    } catch {
      // A line that is not an event is ignored.
    }
  };
  source.addEventListener("done", () => {
    close();
    onDone();
  });
  source.onerror = () => {
    // The browser retries by itself and says where it got to. Only a closed stream is final.
    if (!closed && source.readyState === EventSource.CLOSED) onLost();
  };
  return close;
}
