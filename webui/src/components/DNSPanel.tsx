import { useEffect, useMemo, useState } from "react";
import type { ControlResponse, DNSMode } from "../types";

function formatResolvers(values: string[]): string {
  return values.join("\n");
}

function parseResolvers(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function normalizeMode(value?: string): DNSMode {
  if (value === "system" || value === "xray" || value === "custom") return value;
  if (value === "vpn") return "custom";
  return "custom";
}

function modeLabel(mode: DNSMode): string {
  if (mode === "system") return "System";
  if (mode === "xray") return "Xray";
  return "Custom";
}

export function DNSPanel({
  control,
  busy,
  onSave,
}: {
  control?: ControlResponse;
  busy?: string;
  onSave: (mode: DNSMode, resolvers: string[], onlyProxyDomains: boolean) => Promise<void>;
}) {
  const canManage = Boolean(control?.authenticated && control.authConfigured);
  const serverMode = normalizeMode(control?.dns?.mode);
  const serverResolvers = control?.dns?.resolvers ?? [];
  const serverOnlyProxy = control?.dns?.onlyProxyDomains ?? true;
  const [onlyProxy, setOnlyProxy] = useState(serverOnlyProxy);
  const [mode, setMode] = useState<DNSMode>(serverMode);
  const [resolverText, setResolverText] = useState(formatResolvers(serverResolvers));

  useEffect(() => {
    setMode(serverMode);
    setOnlyProxy(serverOnlyProxy);
    setResolverText(formatResolvers(serverResolvers));
  }, [serverMode, serverOnlyProxy, serverResolvers.join("|")]);

  const resolvers = useMemo(() => parseResolvers(resolverText), [resolverText]);
  const dirty =
    mode !== serverMode || onlyProxy !== serverOnlyProxy || JSON.stringify(resolvers) !== JSON.stringify(serverResolvers);
  const valid = mode !== "custom" || resolvers.length > 0;

  function reset() {
    setMode(serverMode);
    setOnlyProxy(serverOnlyProxy);
    setResolverText(formatResolvers(serverResolvers));
  }

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>DNS клиентов</h2>
          <p>dnsmasq принимает запросы LAN. Guardian — только внешний upstream.</p>
        </div>
        <span className="panel-counter">{modeLabel(serverMode)}</span>
      </div>

      <div className="dns-settings">
        <div className="control-group">
          <div className="control-group-head">
            <span>Внешний DNS</span>
            <strong>{modeLabel(mode)}</strong>
          </div>
          <div className="segmented dns-mode-selector">
            {(["system", "custom", "xray"] as DNSMode[]).map((value) => (
              <button
                type="button"
                className={mode === value ? "active" : ""}
                disabled={!canManage || Boolean(busy)}
                onClick={() => setMode(value)}
                key={value}
              >
                {modeLabel(value)}
              </button>
            ))}
          </div>
          <div className="inline-note">
            {mode === "system" &&
              "Внешние запросы идут напрямую к системным/WAN resolver-ам. Обратного запроса в dnsmasq нет."}
            {mode === "custom" &&
              "Для выбранных доменов используются заданные resolver-ы через VPN. DNS наследует VPN-only, Fail-open и Direct."}
            {mode === "xray" &&
              "A/AAAA выбранных доменов обрабатывает DNS Xray через VPN. Остальные типы передаются через VPN. Политика отказа такая же, как у Custom."}
          </div>
        </div>

        <div className="control-group">
          <div className="control-group-head">
            <span>Custom upstream resolvers</span>
            <strong>{mode === "custom" ? resolvers.length : "—"}</strong>
          </div>
          <textarea
            className="field dns-resolvers-field mono"
            value={resolverText}
            disabled={!canManage || Boolean(busy) || mode !== "custom"}
            onChange={(event) => setResolverText(event.target.value)}
            placeholder={"1.1.1.1\n9.9.9.9"}
            spellCheck={false}
          />
          <div className="inline-note">
            Используется только в Custom. По одному числовому IPv4-адресу на строку; допустим явный порт, например 1.1.1.1:53. Hostname resolver-а запрещён, чтобы не создавать bootstrap-зависимость.
          </div>
        </div>
      </div>

      <label className="check-field dns-scope-toggle">
        <input type="checkbox" role="switch" checked={onlyProxy} disabled={!canManage || Boolean(busy) || mode === "system"} onChange={event => setOnlyProxy(event.target.checked)} />
        DNS через VPN только для проксируемых доменов
      </label>
      <p className="inline-note">{onlyProxy
        ? "Включено: домены из routing (включая geosite) используют Custom/Xray, остальные — прямые системные/WAN resolver-ы. IP-only правила не определяют DNS-политику имени."
        : "Выключено: Custom/Xray используется для всех внешних доменов. Локальные имена остаются в dnsmasq."}</p>
      <div className="inline-note dns-local-note">
        Локальные зоны и DHCP-имена обслуживает сам dnsmasq — до обращения к Guardian. При остановке Guardian локальный DNS продолжает работать.
      </div>

      <p className="inline-note dns-local-note">
        VPN-only: ошибка защищённого DNS → SERVFAIL, без выхода напрямую.
        Fail-open: при отказе VPN DNS → системный upstream.
        Direct: сразу системный upstream. Локальный DNS и bootstrap роутера от VPN не зависят.
      </p>

      {canManage && (
        <div className="routing-footer">
          <span className="inline-note">
            Настройки и доменные правила DNS заменяются без перезапуска VPN, vpn-front и vpn-policy. Ошибка применения сохраняет предыдущие настройки.
          </span>
          <div className="row-actions">
            <button
              type="button"
              className="button button-quiet"
              disabled={!dirty || Boolean(busy)}
              onClick={reset}
            >
              Сбросить
            </button>
            <button
              type="button"
              className="button button-primary"
              disabled={!dirty || !valid || Boolean(busy)}
              onClick={() => void onSave(mode, resolvers, onlyProxy)}
            >
              Сохранить DNS
            </button>
          </div>
        </div>
      )}
    </section>
  );
}
