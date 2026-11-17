import type { RunStatus, Verdict } from "./api";

const numbers = new Intl.NumberFormat("en-US");

export const count = (value: number | null | undefined) => (value == null ? "n/a" : numbers.format(value));

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${count(n)} ${n === 1 ? one : many}`;
}

export function money(value: number | null | undefined): string {
  if (value == null) return "price not known";
  return value < 0.1 ? `$${value.toFixed(3)}` : `$${value.toFixed(2)}`;
}

/** Timestamps arrive as ISO text without a zone. They are shown as they are, to the second. */
export function clock(iso: string | null | undefined): string {
  if (!iso) return "";
  return iso.replace("T", " ").replace(/\.\d+/, "").replace(/(Z|[+-]\d\d:\d\d)$/, "");
}

export function timeOnly(iso: string | null | undefined): string {
  return clock(iso).slice(11);
}

export function span(first: string | null, last: string | null): string {
  if (!first || !last) return "no flows";
  const a = clock(first);
  const b = clock(last);
  return a.slice(0, 10) === b.slice(0, 10) ? `${a} to ${b.slice(11)}` : `${a} to ${b}`;
}

export function seconds(startIso?: string, endIso?: string): number | null {
  if (!startIso || !endIso) return null;
  const ms = Date.parse(endIso) - Date.parse(startIso);
  return Number.isFinite(ms) && ms >= 0 ? Math.round(ms / 1000) : null;
}

export function duration(us: number | null): string {
  if (us == null) return "";
  if (us < 1000) return `${us} µs`;
  if (us < 1_000_000) return `${(us / 1000).toFixed(us < 10_000 ? 1 : 0)} ms`;
  return `${(us / 1_000_000).toFixed(us < 10_000_000 ? 2 : 1)} s`;
}

export function bytes(value: number | null): string {
  if (value == null) return "";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} kB`;
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MB`;
  return `${(value / 1024 ** 3).toFixed(2)} GB`;
}

/** A length of time given in whole seconds, in the largest unit that reads well. */
export function every(secondsLong: number): string {
  if (secondsLong < 120) return `${secondsLong} s`;
  if (secondsLong < 7200) return `${Math.round(secondsLong / 60)} min`;
  return `${(secondsLong / 3600).toFixed(1)} h`;
}

export function protocol(number: number | null): string {
  if (number === 6) return "TCP";
  if (number === 17) return "UDP";
  if (number === 1) return "ICMP";
  return number == null ? "" : `proto ${number}`;
}

export const VERDICT_WORDS: Record<Verdict, string> = {
  malicious_activity: "Malicious activity",
  no_malicious_activity: "No malicious activity",
  inconclusive: "Inconclusive",
};

export const STATUS_WORDS: Record<RunStatus, string> = {
  running: "Running",
  completed: "Completed",
  refused: "Declined by the model",
  failed: "Failed",
};

export const ATTACK_WORDS: Record<string, string> = {
  brute_force: "Password guessing",
  dos: "Denial of service",
  port_scan: "Port scan",
  web_attack: "Web attack",
  botnet: "Botnet",
  other: "Other",
};

export function oneLine(text: string, limit = 110): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > limit ? `${flat.slice(0, limit - 1)}…` : flat;
}
