import { useState } from "react";
import type { ControlResponse, SubscriptionInfo } from "../types";

interface SubscriptionsPanelProps {
  control?: ControlResponse;
  busy?: string;
  onAdd: (url: string) => Promise<void>;
  onUpdate: (subscription: SubscriptionInfo) => void;
  onEdit: (subscription: SubscriptionInfo) => void;
  onDelete: (subscription: SubscriptionInfo) => void;
}

export function SubscriptionsPanel({
  control,
  busy,
  onAdd,
  onUpdate,
  onEdit,
  onDelete,
}: SubscriptionsPanelProps) {
  const [url, setURL] = useState("");
  const canManage = Boolean(control?.authenticated && control.authConfigured);
  const subscriptions = control?.subscriptions ?? [];

  async function add(event: React.FormEvent) {
    event.preventDefault();
    const value = url.trim();
    if (!value) return;
    await onAdd(value);
    setURL("");
  }

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>Подписки</h2>
          <p>Источники нод в v2rayA. URL видны только в management-сессии.</p>
        </div>
        <span className="panel-counter">{subscriptions.length}</span>
      </div>

      <div className="subscription-grid">
        {subscriptions.map((subscription) => (
          <article className="subscription-card" key={subscription.id}>
            <div className="subscription-head">
              <div>
                <div className="subscription-name">{subscription.name}</div>
                <div className="subscription-host">{subscription.host || "—"}</div>
              </div>
              <span className="badge">#{subscription.id}</span>
            </div>
            <div className="subscription-info">
              {subscription.info || "Нет информации о лимитах"}
            </div>
            <div className="subscription-meta">
              <span>{subscription.nodeCount} нод</span>
              <span>auto-select {subscription.autoSelect ? "on" : "off"}</span>
            </div>
            {canManage && (
              <div className="row-actions subscription-actions">
                <button className="button button-quiet" disabled={Boolean(busy)} onClick={() => onUpdate(subscription)}>
                  Обновить
                </button>
                <button className="button button-quiet" disabled={Boolean(busy)} onClick={() => onEdit(subscription)}>
                  Изменить
                </button>
                <button className="button button-danger-quiet" disabled={Boolean(busy)} onClick={() => onDelete(subscription)}>
                  Удалить
                </button>
              </div>
            )}
          </article>
        ))}
      </div>

      {subscriptions.length === 0 && <div className="empty">Подписок нет</div>}

      {canManage && (
        <form className="subscription-add" onSubmit={add}>
          <input
            className="field mono"
            type="url"
            value={url}
            onChange={(event) => setURL(event.target.value)}
            placeholder="https://… URL подписки"
            required
          />
          <button className="button button-primary" disabled={Boolean(busy)}>
            {busy === "sub_add" ? "Импортирую…" : "Добавить"}
          </button>
        </form>
      )}
    </section>
  );
}
