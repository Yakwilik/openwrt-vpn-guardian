import type { HistoryResponse } from "../types";
import { formatRouterTime } from "../utils";

export function EventsPanel({ history }: { history?: HistoryResponse }) {
  const events = [...(history?.events ?? [])].sort((a, b) => b.ts - a.ts).slice(0, 60);

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>События</h2>
          <p>Failover, деградации и восстановление VPN backend.</p>
        </div>
        <span className="panel-counter">{events.length}</span>
      </div>

      <div className="timeline">
        {events.map((event, index) => (
          <div className="timeline-item" key={`${event.ts}:${event.type}:${index}`}>
            <span className={`event-dot event-${event.type}`} />
            <div className="timeline-copy">
              <strong>{eventTitle(event.type)}</strong>
              <span>{event.message}</span>
            </div>
            <time>{formatRouterTime(event.ts, history?.router_tz_offset)}</time>
          </div>
        ))}
        {events.length === 0 && <div className="empty">Событий пока нет</div>}
      </div>
    </section>
  );
}

function eventTitle(type: string): string {
  switch (type) {
    case "switch":
      return "Переключение ноды";
    case "outage":
      return "VPN недоступен";
    case "recovery":
      return "VPN восстановлен";
    case "health":
      return "Деградация";
    default:
      return type || "Событие";
  }
}
