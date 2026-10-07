import { useEffect, useMemo, useState } from "react";
import type { ControlResponse, RoutingRule } from "../types";

const placeholders: Record<RoutingRule["type"], string> = {
  geosite: "jetbrains",
  domain: "jetbrains.com",
  full: "download.jetbrains.com",
  regexp: "^cdn\\d+\\.example\\.com$",
  ip: "203.0.113.0/24",
  geoip: "us",
};

export function RoutingPanel({
  control,
  busy,
  onSave,
}: {
  control?: ControlResponse;
  busy?: string;
  onSave: (rules: RoutingRule[]) => Promise<void>;
}) {
  const canManage = Boolean(control?.authenticated && control.authConfigured);
  const serverRules = control?.routing?.rules ?? [];
  const options = control?.routing?.options ?? [];
  const [rules, setRules] = useState<RoutingRule[]>(serverRules);
  const [type, setType] = useState<RoutingRule["type"]>("domain");
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");

  useEffect(() => {
    setRules(serverRules);
  }, [JSON.stringify(serverRules)]);

  const dirty = useMemo(
    () => JSON.stringify(rules) !== JSON.stringify(serverRules),
    [rules, serverRules],
  );

  function addRule(event: React.FormEvent) {
    event.preventDefault();
    const normalized = value.trim();
    if (!normalized) return;
    if (rules.some((rule) => rule.type === type && rule.value === normalized)) return;
    const normalizedNote = note.trim();
    setRules((current) => [
      ...current,
      {
        type,
        value: normalized,
        ...(normalizedNote ? { note: normalizedNote } : {}),
      },
    ]);
    setValue("");
    setNote("");
  }

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>Routing через VPN</h2>
          <p>Правила, которые vpn-front отправляет в policy/VPN вместо direct.</p>
        </div>
        <span className="panel-counter">{rules.length}</span>
      </div>

      <div className="routing-list">
        {rules.map((rule, index) => (
          <div className="routing-row" key={`${rule.type}:${rule.value}:${index}`}>
            <span className="routing-type">{rule.type}</span>
            <div className="routing-copy">
              <span className="routing-value mono">{rule.value}</span>
              <span className={`routing-note ${rule.note ? "" : "routing-note-empty"}`}>
                {rule.note || "Без заметки"}
              </span>
            </div>
            {canManage && (
              <button
                className="button button-danger-quiet"
                disabled={Boolean(busy)}
                onClick={() => setRules((current) => current.filter((_, i) => i !== index))}
              >
                Удалить
              </button>
            )}
          </div>
        ))}
        {rules.length === 0 && <div className="empty">Правил нет</div>}
      </div>

      {canManage && (
        <>
          <form className="routing-add" onSubmit={addRule}>
            <select
              className="field select"
              value={type}
              onChange={(event) => setType(event.target.value as RoutingRule["type"])}
            >
              {options.map((option) => (
                <option value={option.value} key={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
            <input
              className="field mono"
              value={value}
              onChange={(event) => setValue(event.target.value)}
              placeholder={placeholders[type]}
            />
            <input
              className="field routing-note-input"
              value={note}
              maxLength={200}
              onChange={(event) => setNote(event.target.value)}
              placeholder="Заметка — зачем это правило"
            />
            <button className="button button-ghost" disabled={!value.trim() || Boolean(busy)}>
              Добавить
            </button>
          </form>

          <div className="routing-footer">
            <span className="inline-note">
              Изменения применяются к vpn-front атомарно; direct/policy/watchdog не перезапускаются.
            </span>
            <div className="row-actions">
              <button
                className="button button-quiet"
                disabled={!dirty || Boolean(busy)}
                onClick={() => setRules(serverRules)}
              >
                Сбросить
              </button>
              <button
                className="button button-primary"
                disabled={!dirty || Boolean(busy)}
                onClick={() => void onSave(rules)}
              >
                Сохранить routing
              </button>
            </div>
          </div>
        </>
      )}
    </section>
  );
}
