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
          <p>Внешний DNS для LAN. Локальные имена всегда остаются в dnsmasq.</p>
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
              "Внешние запросы идут в системный dnsmasq/WAN DNS. Локальные домены OpenWrt и DHCP-hostnames также обслуживает dnsmasq."}
            {mode === "custom" &&
              "Внешние запросы выбранной области идут к заданным resolver-ам через активный VPN. При отказе VPN они не отправляются в системный DNS."}
            {mode === "xray" &&
              "Внешние A/AAAA-запросы выбранной области обрабатывает отдельный DNS-процесс Xray через активный VPN. Он не меняет DNS direct-выхода; другие типы записей передаются через VPN без подмены."}
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
        ? "Включено: домены из routing (включая geosite) используют Custom/Xray, остальные — системный dnsmasq. IP-only правила не определяют DNS-политику имени."
        : "Выключено: Custom/Xray используется для всех внешних доменов. Локальные имена остаются в dnsmasq."}</p>
      <div className="inline-note dns-local-note">
        Независимо от выбранного режима запросы к *.lan, *.home.arpa, настроенному локальному домену OpenWrt, статическим dnsmasq address-записям и single-label DHCP-hostnames отправляются только в локальный dnsmasq.
      </div>

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
