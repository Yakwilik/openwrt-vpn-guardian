import { useEffect, useMemo, useState } from "react";
import type { ControlResponse, SelectionState } from "../types";
import { modeLabel, policyLabel } from "../utils";

interface ControlPanelProps {
  control?: ControlResponse;
  busy?: string;
  onMode: (mode: "auto" | "direct") => void;
  onPolicy: (killswitch: boolean) => void;
  onTransports: (transports: string[]) => Promise<void>;
  onManage: () => void;
  onSetPin: (pin: string) => Promise<void>;
}

export function ControlPanel({
  control,
  busy,
  onMode,
  onPolicy,
  onTransports,
  onManage,
  onSetPin,
}: ControlPanelProps) {
  const canManage = Boolean(control?.authenticated && control.authConfigured);
  const mode = control?.control.mode ?? "auto";
  const policy = control?.control.failurePolicy ?? control?.policyMode ?? "killswitch";

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>Control plane</h2>
          <p>Режим маршрутизации, transport allowlist и поведение при отказе VPN.</p>
        </div>
        <span className={`access-badge ${control?.authenticated ? "access-on" : ""}`}>
          {canManage ? "management" : control?.authenticated ? "setup" : "read-only"}
        </span>
      </div>

      <div className="control-grid">
        <ControlGroup title="Режим" value={modeLabel(mode)}>
          <div className="segmented">
            <button className={mode === "auto" ? "active" : ""} disabled={!canManage || Boolean(busy)} onClick={() => onMode("auto")}>Auto</button>
            <button className={mode === "direct" ? "active" : ""} disabled={!canManage || Boolean(busy)} onClick={() => onMode("direct")}>Direct</button>
          </div>
          {mode === "pinned" && <div className="inline-note">Pinned: <strong>{control?.control.pinName || "выбранная нода"}</strong></div>}
        </ControlGroup>

        <ControlGroup title="При сбое VPN" value={policyLabel(policy)}>
          <div className="segmented">
            <button className={policy === "killswitch" ? "active" : ""} disabled={!canManage || Boolean(busy)} onClick={() => onPolicy(true)}>VPN-only</button>
            <button className={policy === "failopen" ? "active" : ""} disabled={!canManage || Boolean(busy)} onClick={() => onPolicy(false)}>Fail-open</button>
          </div>
          <div className="inline-note">
            {policy === "killswitch"
              ? "Proxy-класс не уйдёт в direct при отказе backend."
              : "Proxy-класс может временно перейти в direct."}
          </div>
        </ControlGroup>

        <TransportSelector
          selection={control?.selection}
          canManage={canManage}
          busy={Boolean(busy)}
          onSave={onTransports}
        />
      </div>

      <div className="control-footer">
        <div className="control-runtime">
          <span className={`mini-dot ${control?.frontEnabled ? "is-up" : "is-down"}`} />
          Front {control?.frontEnabled ? "активен" : "остановлен"}
          {control?.hardKillSwitch && <span className="badge badge-warn">hard block</span>}
        </div>
        <button className="button button-primary" onClick={onManage}>
          {canManage ? "Сессия управления" : "Включить управление"}
        </button>
      </div>

      {control?.authenticated && !control.authConfigured && <PinSetup busy={Boolean(busy)} onSetPin={onSetPin} />}
    </section>
  );
}

function TransportSelector({
  selection,
  canManage,
  busy,
  onSave,
}: {
  selection?: SelectionState;
  canManage: boolean;
  busy: boolean;
  onSave: (transports: string[]) => Promise<void>;
}) {
  const allowed = selection?.allowedTransports ?? [];
  const options = selection?.options ?? [];
  const [selected, setSelected] = useState<string[]>(allowed);

  useEffect(() => {
    setSelected(allowed);
  }, [allowed.join("|")]);

  const dirty = useMemo(() => {
    if (selected.length !== allowed.length) return true;
    return selected.some((value) => !allowed.includes(value));
  }, [allowed, selected]);

  function toggle(value: string) {
    if (!canManage || busy) return;
    setSelected((current) =>
      current.includes(value)
        ? current.filter((item) => item !== value)
        : [...current, value],
    );
  }

  return (
    <div className="control-group">
      <div className="control-group-head">
        <span>Разрешённые транспорты</span>
        <strong>{allowed.length}/{options.length}</strong>
      </div>
      <div className="transport-options">
        {options.map((option) => {
          const active = selected.includes(option.value);
          return (
            <button
              type="button"
              className={`transport-toggle ${active ? "active" : ""}`}
              disabled={!canManage || busy}
              onClick={() => toggle(option.value)}
              key={option.value}
            >
              <span className="transport-check">{active ? "✓" : ""}</span>
              <span>{option.label}</span>
            </button>
          );
        })}
      </div>
      <div className="transport-footer">
        <div className="inline-note">
          Watchdog использует только выбранные транспорты. Если отключить транспорт pinned-ноды, режим автоматически станет Auto.
        </div>
        {canManage && (
          <button
            type="button"
            className="button button-quiet"
            disabled={busy || !dirty || selected.length === 0}
            onClick={() => void onSave(selected)}
          >
            {selected.length === 0 ? "Нужен хотя бы один" : "Сохранить"}
          </button>
        )}
      </div>
    </div>
  );
}

function ControlGroup({ title, value, children }: { title: string; value: string; children: React.ReactNode }) {
  return (
    <div className="control-group">
      <div className="control-group-head"><span>{title}</span><strong>{value}</strong></div>
      {children}
    </div>
  );
}

function PinSetup({ busy, onSetPin }: { busy: boolean; onSetPin: (pin: string) => Promise<void> }) {
  async function submit(form: React.FormEvent<HTMLFormElement>) {
    form.preventDefault();
    const data = new FormData(form.currentTarget);
    const pin = String(data.get("pin") || "");
    if (pin.length < 6) return;
    await onSetPin(pin);
    form.currentTarget.reset();
  }

  return (
    <form className="pin-setup" onSubmit={submit}>
      <div>
        <strong>Защитить управление PIN</strong>
        <p>Первичная LAN-сессия активна. Следующие входы будут только по PIN.</p>
      </div>
      <div className="inline-form">
        <input className="field" name="pin" type="password" inputMode="numeric" minLength={6} placeholder="PIN, минимум 6 знаков" required />
        <button className="button button-primary" disabled={busy}>Установить PIN</button>
      </div>
    </form>
  );
}
