import type { StatusSnapshot } from "../types";
import {
  formatAgo,
  modeLabel,
  policyLabel,
  protocolLabel,
  statusHeadline,
  statusTone,
} from "../utils";

interface StatusOverviewProps {
  status?: StatusSnapshot;
}

export function StatusOverview({ status }: StatusOverviewProps) {
  const tone = statusTone(status?.overall);

  return (
    <>
      <section className={`hero hero-${tone}`}>
        <div className={`status-orb status-orb-${tone}`} aria-hidden="true" />
        <div className="hero-copy">
          <div className="eyebrow">Состояние маршрутизации</div>
          <h1>{statusHeadline(status)}</h1>
          <p>
            {status
              ? `${modeLabel(status.control_mode)} · ${policyLabel(status.failure_policy)} · ${status.health_count}/${status.health_total || 4} checks`
              : "Читаю состояние роутера…"}
          </p>
        </div>
        {status && (
          <div className="hero-badges">
            <span className="badge badge-strong">{status.architecture || "front"}</span>
            <span className={`badge ${status.fallback_direct ? "badge-warn" : ""}`}>
              {status.fallback_direct ? "fallback direct" : "interception active"}
            </span>
            <span className={`badge ${status.dns_healthy ? "" : "badge-warn"}`}>
              DNS {status.dns_mode || "—"}{status.dns_healthy ? "" : " · fault"}
            </span>
          </div>
        )}
      </section>

      <section className="metrics-grid" aria-label="Ключевые показатели">
        <Metric
          label="Активная нода"
          value={status?.node || "—"}
          detail={protocolLabel(status?.protocol)}
        />
        <Metric
          label="VPN egress"
          value={status?.vpn_ip || "—"}
          detail={status?.home_ip ? `Домашний: ${status.home_ip}` : "—"}
          mono
        />
        <Metric
          label="Backend"
          value={status ? `${status.health_count}/${status.health_total || 4}` : "—"}
          detail={status ? `Failures: ${status.failures}` : "—"}
        />
        <Metric
          label="Последнее переключение"
          value={formatAgo(status?.last_switch)}
          detail={
            status?.last_failed_node
              ? `Последний сбой: ${status.last_failed_node}`
              : "Сбоев не зафиксировано"
          }
        />
      </section>
    </>
  );
}

function Metric({
  label,
  value,
  detail,
  mono = false,
}: {
  label: string;
  value: string;
  detail: string;
  mono?: boolean;
}) {
  return (
    <article className="metric-card">
      <div className="metric-label">{label}</div>
      <div className={`metric-value ${mono ? "mono" : ""}`}>{value}</div>
      <div className="metric-detail">{detail}</div>
    </article>
  );
}
