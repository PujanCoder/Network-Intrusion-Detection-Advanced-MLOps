import type { NetworkEvent } from "./api";

const BYTE_UNITS = ["B", "KB", "MB", "GB", "TB", "PB"];

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return value.toLocaleString();
}

export function formatBytes(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  if (value <= 0) return "0 B";
  const exponent = Math.min(BYTE_UNITS.length - 1, Math.floor(Math.log(value) / Math.log(1024)));
  const scaled = value / 1024 ** exponent;
  const digits = scaled >= 100 || exponent === 0 ? 0 : 1;
  return `${scaled.toFixed(digits)} ${BYTE_UNITS[exponent]}`;
}

function pad(value: number): string {
  return value.toString().padStart(2, "0");
}

export function formatTime(ts: number | null | undefined): string {
  if (ts === null || ts === undefined || Number.isNaN(ts)) return "—";
  const date = new Date(ts * 1000);
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

export function formatDateTime(ts: number | null | undefined): string {
  if (ts === null || ts === undefined || Number.isNaN(ts)) return "—";
  const date = new Date(ts * 1000);
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

export function toIsoLocal(date: Date): string {
  const offset = date.getTimezoneOffset() * 60_000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 16);
}

export function relativeSeconds(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || Number.isNaN(seconds)) return "—";
  const total = Math.max(0, Math.round(seconds));
  if (total < 1) return "just now";
  if (total < 60) return `${total}s ago`;
  if (total < 3600) return `${Math.floor(total / 60)}m ${total % 60}s ago`;
  return `${Math.floor(total / 3600)}h ${Math.floor((total % 3600) / 60)}m ago`;
}

export function severityClass(severity: string | null | undefined): string {
  switch ((severity ?? "").toUpperCase()) {
    case "CRITICAL":
      return "sev-critical";
    case "HIGH":
      return "sev-high";
    case "MEDIUM":
      return "sev-medium";
    case "LOW":
      return "sev-low";
    case "INFO":
      return "sev-info";
    default:
      return "sev-none";
  }
}

export function predictionClass(event: NetworkEvent): string {
  if (event.is_malicious) return "pred-attack";
  if (event.prediction) return "pred-benign";
  return "pred-unclassified";
}
