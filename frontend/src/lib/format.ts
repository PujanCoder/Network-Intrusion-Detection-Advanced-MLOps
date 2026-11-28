import type { Severity } from "./api";

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

export function parseTs(value: string | number | null | undefined): Date | null {
  if (value === null || value === undefined || value === "") return null;
  const date = typeof value === "number" ? new Date(value * 1000) : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatTime(value: string | number | null | undefined): string {
  const date = parseTs(value);
  if (!date) return "—";
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

export function formatDateTime(value: string | number | null | undefined): string {
  const date = parseTs(value);
  if (!date) return "—";
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(
    date.getMinutes(),
  )}:${pad(date.getSeconds())}`;
}

export function relativeSeconds(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || Number.isNaN(seconds)) return "—";
  const total = Math.max(0, Math.round(seconds));
  if (total < 1) return "just now";
  if (total < 60) return `${total}s ago`;
  if (total < 3600) return `${Math.floor(total / 60)}m ${total % 60}s ago`;
  if (total < 86400) return `${Math.floor(total / 3600)}h ${Math.floor((total % 3600) / 60)}m ago`;
  return `${Math.floor(total / 86400)}d ago`;
}

export function secondsSince(value: string | number | null | undefined): number | null {
  const date = parseTs(value);
  if (!date) return null;
  return Math.max(0, (Date.now() - date.getTime()) / 1000);
}

export function relativeFrom(value: string | number | null | undefined): string {
  return relativeSeconds(secondsSince(value));
}

export function confidence(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return `${(value * 100).toFixed(1)}%`;
}

export function severityTone(severity: Severity | string | null | undefined): string {
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

export function toLocalInput(date: Date): string {
  const offset = date.getTimezoneOffset() * 60_000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 16);
}

export function duration(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  if (value < 1) return `${(value * 1000).toFixed(0)} ms`;
  if (value < 60) return `${value.toFixed(2)} s`;
  return `${(value / 60).toFixed(1)} min`;
}
