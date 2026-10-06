import type { HistorySample, StatusSnapshot } from "./types";

export function policyLabel(policy?: string): string {
  return policy === "killswitch" ? "VPN-only" : "Fail-open";
}

export function modeLabel(mode?: string): string {
  if (mode === "pinned") return "Pinned";
  if (mode === "direct") return "Direct";
  return "Auto";
}

export function formatAgo(unixSeconds?: number): string {
  if (!unixSeconds) return "—";
  const diff = Math.max(0, Math.floor(Date.now() / 1000) - unixSeconds);
  if (diff < 10) return "сейчас";
  if (diff < 60) return `${diff} сек назад`;
  if (diff < 3600) return `${Math.floor(diff / 60)} мин назад`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} ч назад`;
  return `${Math.floor(diff / 86400)} дн назад`;
}

export function formatRouterTime(unixSeconds: number, offsetSeconds = 0): string {
  const date = new Date((unixSeconds + offsetSeconds) * 1000);
  return new Intl.DateTimeFormat("ru-RU", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    day: "2-digit",
    month: "2-digit",
    timeZone: "UTC",
  }).format(date);
}

export function statusTone(overall?: string): "ok" | "warn" | "down" {
  if (overall === "ok") return "ok";
  if (overall === "degraded") return "warn";
  return "down";
}

export function statusHeadline(status?: StatusSnapshot): string {
  if (!status) return "Получаю состояние";
  if (status.overall === "ok" && status.tproxy_active) return "VPN работает";
  if (status.overall === "degraded") return "VPN работает нестабильно";
  if (!status.tproxy_active) return "VPN front недоступен";
  return "VPN backend недоступен";
}

export function protocolLabel(protocol?: string): string {
  if (!protocol) return "—";
  return protocol
    .replace("vless(", "VLESS · ")
    .replace(")", "")
    .replaceAll("+", " + ")
    .replace("hysteria2", "Hysteria2")
    .replace("shadowsocks", "Shadowsocks");
}

export function filterHistory(
  samples: HistorySample[],
  hours: number,
): HistorySample[] {
  if (samples.length === 0) return [];
  const maxTs = samples[samples.length - 1].ts;
  const minTs = maxTs - hours * 3600;
  return samples.filter((sample) => sample.ts >= minTs);
}

export function downsample<T>(rows: T[], maxPoints: number): T[] {
  if (rows.length <= maxPoints) return rows;
  const step = (rows.length - 1) / (maxPoints - 1);
  const out: T[] = [];
  for (let i = 0; i < maxPoints; i += 1) {
    out.push(rows[Math.round(i * step)]);
  }
  return out;
}
