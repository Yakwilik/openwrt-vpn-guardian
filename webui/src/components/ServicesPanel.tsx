import type { StatusSnapshot } from "../types";

const serviceOrder = ["front", "policy", "dns", "v2raya", "watchdog", "collector", "api"];

interface ServicesPanelProps {
  status?: StatusSnapshot;
  canManage: boolean;
  busy?: string;
  onRepair: () => void;
  onRestart: (service: "v2raya") => void;
}

export function ServicesPanel({
  status,
  canManage,
  busy,
  onRepair,
  onRestart,
}: ServicesPanelProps) {
  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>Сервисы</h2>
          <p>Runtime Guardian и backend-компоненты.</p>
        </div>
      </div>

      <div className="services-grid">
        {serviceOrder.map((name) => {
          const value = status?.services?.[name] || "unknown";
          const running = value === "running";
          const disabled = value === "disabled";
          return (
            <div className="service-card" key={name}>
              <span className={`mini-dot ${running ? "is-up" : disabled ? "" : "is-down"}`} />
              <span>{name}</span>
              <strong>{value}</strong>
            </div>
          );
        })}
      </div>

      <div className="service-actions">
        <button className="button button-ghost" disabled={!canManage || Boolean(busy)} onClick={onRepair}>
          Восстановить backend
        </button>
        <button className="button button-ghost" disabled={!canManage || Boolean(busy)} onClick={() => onRestart("v2raya")}>
          Restart v2rayA
        </button>
      </div>
    </section>
  );
}
