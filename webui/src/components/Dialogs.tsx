import { useEffect, useState } from "react";
import type { ControlResponse, SubscriptionInfo } from "../types";

export function ManageDialog({
  open,
  control,
  busy,
  onClose,
  onLogin,
  onLogout,
}: {
  open: boolean;
  control?: ControlResponse;
  busy?: string;
  onClose: () => void;
  onLogin: (pin: string) => Promise<void>;
  onLogout: () => Promise<void>;
}) {
  const [pin, setPin] = useState("");

  useEffect(() => {
    if (!open) setPin("");
  }, [open]);

  if (!open) return null;

  const authenticated = Boolean(control?.authenticated);
  const configured = Boolean(control?.authConfigured);

  return (
    <Dialog title="Режим управления" onClose={onClose}>
      {authenticated ? (
        <>
          <p className="dialog-copy">
            Сессия управления активна. Изменения защищены CSRF-токеном и доступны только в этой сессии.
          </p>
          <div className="dialog-actions">
            <button className="button button-danger" disabled={Boolean(busy)} onClick={() => void onLogout()}>
              Выйти из управления
            </button>
            <button className="button button-ghost" onClick={onClose}>Закрыть</button>
          </div>
        </>
      ) : (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void onLogin(pin);
          }}
        >
          <p className="dialog-copy">
            {configured
              ? "Введите PIN управления."
              : "Первичная разблокировка доступна только из LAN. После входа задайте PIN."}
          </p>
          {configured && (
            <input
              className="field dialog-field"
              autoFocus
              type="password"
              inputMode="numeric"
              value={pin}
              onChange={(event) => setPin(event.target.value)}
              placeholder="PIN"
              required
            />
          )}
          <div className="dialog-actions">
            <button className="button button-primary" disabled={Boolean(busy)}>
              {busy === "login" ? "Вхожу…" : configured ? "Войти" : "Включить управление"}
            </button>
            <button className="button button-ghost" type="button" onClick={onClose}>Отмена</button>
          </div>
        </form>
      )}
    </Dialog>
  );
}

export function SubscriptionDialog({
  subscription,
  busy,
  onClose,
  onSave,
}: {
  subscription?: SubscriptionInfo;
  busy?: string;
  onClose: () => void;
  onSave: (value: {
    id: number;
    url: string;
    remarks: string;
    autoSelect: boolean;
  }) => Promise<void>;
}) {
  const [url, setURL] = useState("");
  const [remarks, setRemarks] = useState("");
  const [autoSelect, setAutoSelect] = useState(false);

  useEffect(() => {
    setURL(subscription?.address || "");
    setRemarks(subscription?.remarks || "");
    setAutoSelect(Boolean(subscription?.autoSelect));
  }, [subscription]);

  if (!subscription) return null;

  return (
    <Dialog title="Изменить подписку" onClose={onClose}>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void onSave({
            id: subscription.id,
            url: url.trim(),
            remarks: remarks.trim(),
            autoSelect,
          });
        }}
      >
        <label className="field-label">
          URL
          <input
            className="field mono"
            type="url"
            value={url}
            onChange={(event) => setURL(event.target.value)}
            required
          />
        </label>
        <label className="field-label">
          Название
          <input
            className="field"
            value={remarks}
            onChange={(event) => setRemarks(event.target.value)}
            placeholder={subscription.host}
          />
        </label>
        <label className="check-field">
          <input
            type="checkbox"
            checked={autoSelect}
            onChange={(event) => setAutoSelect(event.target.checked)}
          />
          Auto-select в v2rayA
        </label>
        <div className="dialog-actions">
          <button className="button button-primary" disabled={Boolean(busy) || !url.trim()}>
            Сохранить
          </button>
          <button className="button button-ghost" type="button" onClick={onClose}>Отмена</button>
        </div>
      </form>
    </Dialog>
  );
}

export function ConfirmDialog({
  title,
  description,
  confirmLabel,
  danger = false,
  open,
  busy,
  onClose,
  onConfirm,
}: {
  title: string;
  description: string;
  confirmLabel: string;
  danger?: boolean;
  open: boolean;
  busy?: boolean;
  onClose: () => void;
  onConfirm: () => void;
}) {
  if (!open) return null;

  return (
    <Dialog title={title} onClose={onClose}>
      <p className="dialog-copy">{description}</p>
      <div className="dialog-actions">
        <button
          className={`button ${danger ? "button-danger" : "button-primary"}`}
          disabled={busy}
          onClick={onConfirm}
        >
          {confirmLabel}
        </button>
        <button className="button button-ghost" disabled={busy} onClick={onClose}>Отмена</button>
      </div>
    </Dialog>
  );
}

function Dialog({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  return (
    <div
      className="dialog-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="dialog" role="dialog" aria-modal="true" aria-label={title}>
        <div className="dialog-head">
          <h2>{title}</h2>
          <button className="icon-button" onClick={onClose} aria-label="Закрыть">×</button>
        </div>
        {children}
      </div>
    </div>
  );
}
