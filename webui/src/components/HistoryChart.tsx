import { useMemo, useState } from "react";
import type { HistoryResponse } from "../types";
import { downsample, filterHistory, formatRouterTime } from "../utils";

const ranges = [1, 6, 24] as const;

export function HistoryChart({ history }: { history?: HistoryResponse }) {
  const [hours, setHours] = useState<(typeof ranges)[number]>(6);
  const rangeSamples = useMemo(
    () => filterHistory(history?.samples ?? [], hours),
    [history?.samples, hours],
  );
  const samples = useMemo(
    () => downsample(rangeSamples, 180),
    [rangeSamples],
  );

  const points = samples.map((sample, index) => {
    const x = samples.length <= 1 ? 0 : (index / (samples.length - 1)) * 1000;
    const y = 200 - Math.max(0, Math.min(100, sample.availability)) * 1.7;
    return [x, y] as const;
  });
  const path = points.map(([x, y], index) => `${index ? "L" : "M"} ${x} ${y}`).join(" ");

  const latest = rangeSamples.at(-1);
  const rangeEnd = latest?.ts ?? Math.floor(Date.now() / 1000);
  const rangeStart = rangeEnd - hours * 3600;
  const switches = (history?.events ?? []).filter(
    (event) =>
      event.type === "switch" &&
      event.ts >= rangeStart &&
      event.ts <= rangeEnd,
  );

  return (
    <section className="panel">
      <div className="panel-heading history-heading">
        <div>
          <h2>Доступность VPN</h2>
          <p>История backend health без влияния на direct-трафик.</p>
        </div>
        <div className="segmented segmented-small" aria-label="Диапазон истории">
          {ranges.map((range) => (
            <button
              className={hours === range ? "active" : ""}
              key={range}
              onClick={() => setHours(range)}
            >
              {range}ч
            </button>
          ))}
        </div>
      </div>

      <div className="chart-summary">
        <span>
          Сейчас <strong>{latest ? `${latest.health}/${latest.total || 4}` : "—"}</strong>
        </span>
        <span>
          Переключений <strong>{switches.length}</strong>
        </span>
      </div>

      <div className="chart-shell">
        {samples.length < 2 ? (
          <div className="empty">Недостаточно данных для графика</div>
        ) : (
          <svg viewBox="0 0 1000 220" role="img" aria-label="Доступность VPN">
            <defs>
              <linearGradient id="availability-fill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="currentColor" stopOpacity="0.22" />
                <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
              </linearGradient>
            </defs>
            {[30, 115, 200].map((y) => (
              <line className="chart-grid" x1="0" x2="1000" y1={y} y2={y} key={y} />
            ))}
            <path
              className="chart-area"
              d={`${path} L 1000 215 L 0 215 Z`}
              fill="url(#availability-fill)"
            />
            <path className="chart-line" d={path} fill="none" />
            {switches.map((event) => {
              const firstTs = rangeSamples[0]?.ts ?? event.ts;
              const lastTs = rangeSamples.at(-1)?.ts ?? event.ts;
              const span = Math.max(1, lastTs - firstTs);
              const x = ((event.ts - firstTs) / span) * 1000;
              const nearest = rangeSamples.reduce(
                (best, sample) =>
                  Math.abs(sample.ts - event.ts) < Math.abs(best.ts - event.ts)
                    ? sample
                    : best,
                rangeSamples[0],
              );
              const availability = nearest?.availability ?? 100;
              const y = 200 - Math.max(0, Math.min(100, availability)) * 1.7;
              return <circle className="chart-switch" cx={x} cy={y} r="5" key={`${event.ts}:${event.message}`} />;
            })}
          </svg>
        )}
      </div>

      {samples.length > 1 && (
        <div className="chart-axis">
          <span>{formatRouterTime(samples[0].ts, history?.router_tz_offset)}</span>
          <span>{formatRouterTime(samples.at(-1)!.ts, history?.router_tz_offset)}</span>
        </div>
      )}
    </section>
  );
}
