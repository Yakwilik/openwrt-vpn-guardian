import { useState } from "react";
import type { QUICMode, QUICState, StatusSnapshot } from "../types";

interface QUICPanelProps {
  status?: StatusSnapshot;
  diagnostics?: QUICState;
  error: string;
  canManage: boolean;
  busy?: string;
  onMode: (mode: QUICMode) => void;
  onRefresh: () => void;
}

function modeName(mode?: QUICMode): string {
  if (!mode) return "Загрузка…";
  return mode === "allow" ? "Allow QUIC" : "TCP fallback";
}

function eventTime(ts: number): string {
  return new Date(ts * 1000).toLocaleString("ru-RU", {
    day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit",
  });
}

export function QUICPanel({
  status, diagnostics, error, canManage, busy, onMode, onRefresh,
}: QUICPanelProps) {
  const [expanded, setExpanded] = useState(false);
  const mode = diagnostics?.mode ?? status?.quic_mode;
  const events = diagnostics?.events ?? [];
  const errors = events.filter((event) => event.kind === "error");
  const shown = expanded ? events : events.slice(0, 5);

  return (
    <section className="panel quic-panel">
      <div className="panel-heading">
        <div>
          <h2>QUIC / HTTP/3</h2>
          <p>Управление транспортом клиентов LAN и диагностика проблем HTTP/3.</p>
        </div>
        <span className="panel-counter">{modeName(mode)}</span>
      </div>

      <div className="quic-settings">
        <div className="control-group">
          <div className="control-group-head">
            <span>Режим клиентского UDP/443</span>
            <strong>{modeName(mode)}</strong>
          </div>
          <div className="segmented quic-mode-selector" role="group" aria-label="Режим QUIC">
            {(["tcp-fallback", "allow"] as QUICMode[]).map((value) => (
              <button
                key={value}
                type="button"
                className={mode === value ? "active" : ""}
                aria-pressed={mode === value}
                disabled={!canManage || Boolean(busy) || !mode || mode === value}
                onClick={() => onMode(value)}
              >
                {modeName(value)}
              </button>
            ))}
          </div>
          <p className="inline-note">
            {!mode
              ? "Получаю текущий режим с роутера…"
              : mode === "tcp-fallback"
                ? "TCP fallback: публичный UDP/443 клиентов отклоняется сразу. Браузер может перейти на HTTP/2. VPN-транспорт самого роутера не затрагивается."
                : "Allow QUIC: клиентский UDP/443 разрешён и проходит обычную классификацию Xray. При проблемах с QUIC сайты могут загружаться нестабильно."}
          </p>
          {canManage && (
            <p className="inline-note">
              Изменение действует сразу, сохраняется после перезагрузки и не перезапускает VPN или DNS.
            </p>
          )}
          {!canManage && (
            <p className="inline-note">
              Чтобы изменить режим и посмотреть журнал ошибок, включите управление Guardian.
            </p>
          )}
          {diagnostics?.firewallAvailable && !diagnostics.effective && (
            <p className="quic-warning" role="alert">
              Правила nftables не соответствуют сохранённому QUIC-режиму.
            </p>
          )}
          {diagnostics && !diagnostics.firewallAvailable && (
            <p className="quic-warning" role="alert">
              Не удалось прочитать фактическое состояние nftables.
            </p>
          )}
        </div>

        <div className="control-group">
          <div className="control-group-head">
            <span>Отклонено пакетов UDP/443</span>
            <strong className="mono">
              {diagnostics?.firewallAvailable
                ? diagnostics.rejectedUDP443.toLocaleString("ru-RU")
                : "—"}
            </strong>
          </div>
          <p className="inline-note">
            Это счётчик защитного TCP fallback, а не число ошибок QUIC.
            Он обнуляется при переустановке правил nftables.
          </p>
        </div>
      </div>

      <div className="quic-log-heading">
        <div>
          <strong>Ошибки QUIC / HTTP/3</strong>
          {diagnostics && <span className="inline-note">Найдено в последних событиях: {errors.length}</span>}
        </div>
        <button type="button" className="button button-quiet" disabled={!canManage || Boolean(busy)}
          onClick={onRefresh}>Обновить журнал</button>
      </div>

      {error && canManage && <p className="quic-warning" role="alert">{error}</p>}
      {canManage && !diagnostics && !error && <p className="inline-note">Загрузка диагностики…</p>}
      {canManage && diagnostics && !diagnostics.logsAvailable && (
        <p className="quic-warning">Постоянный журнал диагностики недоступен.</p>
      )}
      {canManage && diagnostics?.logsAvailable && events.length === 0 && (
        <p className="inline-note">
          В сохранённом журнале нет ошибок QUIC/HTTP/3. Это не исключает ошибок
          внутри браузера: Guardian фиксирует только доступные ему события Xray.
        </p>
      )}

      {canManage && shown.length > 0 && (
        <div className="quic-event-list">
          {shown.map((event, i) => (
            <div className="quic-event" key={`${event.ts}:${event.kind}:${i}`}>
              <div className="quic-event-meta">
                <span className={event.kind === "error" ? "quic-error-label" : "quic-mode-label"}>
                  {event.kind === "error" ? "Ошибка" : "Изменение режима"}
                </span>
                <time dateTime={new Date(event.ts * 1000).toISOString()}>{eventTime(event.ts)}</time>
              </div>
              <code>{event.message}</code>
            </div>
          ))}
        </div>
      )}
      {canManage && events.length > 5 && (
        <div className="collapse-footer">
          <span className="collapse-summary">
            {expanded ? `Показаны все ${events.length} событий` : `Показаны 5 из ${events.length}`}
          </span>
          <button type="button" className="button button-quiet"
            aria-expanded={expanded} onClick={() => setExpanded((current) => !current)}>
            {expanded ? "Свернуть" : "Показать все"}
          </button>
        </div>
      )}
      <p className="inline-note quic-log-note">
        Источник: постоянные события Xray и Guardian. Ошибки QUIC внутри браузера
        не попадают в журнал роутера автоматически.
      </p>
    </section>
  );
}
