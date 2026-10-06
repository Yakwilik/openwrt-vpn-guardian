import { useState } from "react";
import type { HistoryResponse } from "../types";
import { formatRouterTime } from "../utils";

const collapsedEventCount = 5;
const maxEventCount = 60;

export function EventsPanel({ history }: { history?: HistoryResponse }) {
  const [expanded, setExpanded] = useState(false);
  const events = [...(history?.events ?? [])]
    .sort((a, b) => b.ts - a.ts)
    .slice(0, maxEventCount);
  const visibleEvents = expanded
    ? events
    : events.slice(0, collapsedEventCount);
  const hiddenCount = Math.max(0, events.length - visibleEvents.length);

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
        {visibleEvents.map((event, index) => (
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

      {events.length > collapsedEventCount && (
        <div className="collapse-footer">
          <span className="collapse-summary">
            {expanded
              ? `Показаны последние ${events.length}`
              : `Показаны последние ${visibleEvents.length} из ${events.length}`}
          </span>
          <button
            className="button button-quiet collapse-button"
            aria-expanded={expanded}
            onClick={() => setExpanded((value) => !value)}
          >
            {expanded ? "Свернуть" : `Показать все · +${hiddenCount}`}
          </button>
        </div>
      )}
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
