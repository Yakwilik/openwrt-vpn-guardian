import type { ControlResponse, StatusSnapshot, TrafficMode } from "../types";

export function TrafficModePanel({ control, status, busy, onMode }: {
  control?: ControlResponse;
  status?: StatusSnapshot;
  busy?: string;
  onMode: (mode: TrafficMode) => void;
}) {
  const mode = control?.trafficMode ?? status?.traffic_mode;
  const full = mode === "full-vpn";
  const canManage = Boolean(control?.authenticated && control.authConfigured);
  const direct = control?.control.mode === "direct";
  return (
    <section className="panel" aria-labelledby="traffic-mode-title">
      <div className="panel-heading">
        <div>
          <h2 id="traffic-mode-title">Охват VPN</h2>
          <p>Выборочная маршрутизация или весь внешний трафик устройств за GL-MT.</p>
        </div>
        <span className="panel-counter">{!mode ? "Загрузка…" : full ? "Весь трафик" : "По правилам"}</span>
      </div>
      <div className="segmented traffic-mode-selector" role="group" aria-label="Охват VPN">
        <button type="button" className={mode === "selective" ? "active" : ""}
          aria-pressed={mode === "selective"} disabled={!canManage || Boolean(busy) || !mode || mode === "selective"}
          onClick={() => onMode("selective")}>По правилам</button>
        <button type="button" className={full ? "active" : ""}
          aria-pressed={full} disabled={!canManage || Boolean(busy) || !mode || full || direct}
          onClick={() => onMode("full-vpn")}>Весь трафик через VPN</button>
      </div>
      <p className="inline-note">
        {full
          ? "Все внешние IPv4 TCP/UDP-соединения и DNS клиентов отправляются через текущую VPN-ноду. Прямого выхода при сбое VPN нет. Список доменных/IP-правил сохранён, но не ограничивает охват VPN."
          : "VPN используется только для адресов из списка маршрутов. Остальные сайты используют обычный прямой путь и сохранённые DNS-настройки."}
      </p>
      <p className="inline-note">
        Локальная сеть и админка доступны в обоих режимах. В полном режиме внешний IPv6 и протоколы,
        не поддерживаемые прокси (например, ICMP), блокируются, чтобы не обходить VPN.
        Собственный служебный трафик роутера не туннелируется. Настройка QUIC остаётся прежней.
      </p>
      {direct && <p className="quic-warning">Для включения полного VPN сначала выберите Auto или закрепите VPN-ноду.</p>}
      {!canManage && <p className="inline-note">Для переключения включите управление Guardian.</p>}
      <p className="inline-note">
        Режим сохраняется после перезагрузки. При переключении перезапускается только vpn-front:
        текущие клиентские соединения могут кратко прерваться. VPN-backend и выбранная нода не меняются.
      </p>
    </section>
  );
}
