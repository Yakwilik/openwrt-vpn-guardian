import { useState } from "react";
import { ControlPanel } from "./components/ControlPanel";
import { DNSPanel } from "./components/DNSPanel";
import { ConfirmDialog, ManageDialog, SubscriptionDialog } from "./components/Dialogs";
import { EventsPanel } from "./components/EventsPanel";
import { HeaderBar } from "./components/HeaderBar";
import { HealthGrid } from "./components/HealthGrid";
import { HistoryChart } from "./components/HistoryChart";
import { NodesPanel } from "./components/NodesPanel";
import { RoutingPanel } from "./components/RoutingPanel";
import { ServicesPanel } from "./components/ServicesPanel";
import { StatusOverview } from "./components/StatusOverview";
import { SubscriptionsPanel } from "./components/SubscriptionsPanel";
import { TrafficPath } from "./components/TrafficPath";
import { useControlActions } from "./hooks/useControlActions";
import { useDashboardData } from "./hooks/useDashboardData";
import type { DNSMode, NodeInfo, RoutingRule, SubscriptionInfo } from "./types";

interface ConfirmState {
  title: string;
  description: string;
  confirmLabel: string;
  danger?: boolean;
  run: () => Promise<void>;
}

export default function App() {
  const dashboard = useDashboardData();
  const actions = useControlActions({
    control: dashboard.control,
    setControl: dashboard.setControl,
    loadStatus: dashboard.loadStatus,
  });

  const [manageOpen, setManageOpen] = useState(false);
  const [editingSubscription, setEditingSubscription] = useState<SubscriptionInfo>();
  const [confirm, setConfirm] = useState<ConfirmState>();

  const canManage = Boolean(
    dashboard.control?.authenticated && dashboard.control.authConfigured,
  );

  async function login(pin: string) {
    if (await actions.login(pin)) {
      setManageOpen(false);
    }
  }

  async function logout() {
    if (await actions.logout()) {
      setManageOpen(false);
    }
  }

  function changeMode(mode: "auto" | "direct") {
    if (mode === "auto") {
      void actions.controlAction("auto", {}, "Auto mode включён");
      return;
    }

    ask({
      title: "Перейти в Direct?",
      description:
        "Proxy-класс временно перестанет использовать VPN. vpn-front останется частью пути трафика.",
      confirmLabel: "Включить Direct",
      run: async () => {
        await actions.controlAction("direct", {}, "Direct mode включён");
      },
    });
  }

  function changePolicy(killswitch: boolean) {
    if (killswitch) {
      void actions.controlAction(
        "killswitch",
        { enabled: true },
        "VPN-only включён",
      );
      return;
    }

    ask({
      title: "Включить Fail-open?",
      description:
        "При полном отказе VPN proxy-класс сможет временно выйти напрямую. Direct-класс не меняется.",
      confirmLabel: "Включить Fail-open",
      run: async () => {
        await actions.controlAction(
          "killswitch",
          { enabled: false },
          "Fail-open включён",
        );
      },
    });
  }

  async function switchNode(node: NodeInfo) {
    await actions.controlAction(
      "switch",
      { id: node.id, sub: node.sub, nodeKey: node.key },
      `Активна нода: ${node.name}`,
    );
  }

  async function pinNode(node: NodeInfo) {
    await actions.controlAction(
      "pin",
      { id: node.id, sub: node.sub, nodeKey: node.key },
      `Pinned: ${node.name}`,
    );
  }

  async function addSubscription(url: string) {
    await actions.controlAction("sub_add", { url }, "Подписка добавлена");
  }

  function updateSubscription(subscription: SubscriptionInfo) {
    ask({
      title: "Обновить подписку?",
      description: subscription.name,
      confirmLabel: "Обновить",
      run: async () => {
        await actions.controlAction(
          "sub_update",
          { id: subscription.id },
          "Подписка обновлена",
        );
      },
    });
  }

  async function saveSubscription(value: {
    id: number;
    url: string;
    remarks: string;
    autoSelect: boolean;
  }) {
    const next = await actions.controlAction(
      "sub_edit",
      value,
      "Подписка изменена",
    );
    if (next) {
      setEditingSubscription(undefined);
    }
  }

  function deleteSubscription(subscription: SubscriptionInfo) {
    ask({
      title: "Удалить подписку?",
      description:
        `${subscription.name}. Если она активна, Guardian сначала защитит трафик от некорректного удаления.`,
      confirmLabel: "Удалить",
      danger: true,
      run: async () => {
        await actions.controlAction(
          "sub_delete",
          { id: subscription.id, confirm: "DELETE" },
          "Подписка удалена",
        );
      },
    });
  }

  async function updateTransports(transports: string[]) {
    await actions.controlAction(
      "selection",
      { transports },
      "Разрешённые транспорты обновлены",
    );
  }

  async function updateRouting(rules: RoutingRule[]) {
    await actions.controlAction(
      "routing",
      { rules },
      "Routing обновлён",
    );
  }

  async function updateDNS(mode: DNSMode, resolvers: string[], onlyProxyDomains: boolean) {
    await actions.controlAction(
      "dns",
      { dnsMode: mode, dnsResolvers: resolvers, dnsOnlyProxyDomains: onlyProxyDomains },
      "DNS-настройки обновлены",
    );
  }

  function restartService(service: "v2raya") {
    ask({
      title: `Перезапустить ${service}?`,
      description: "На время перезапуска VPN backend может быть недоступен.",
      confirmLabel: "Перезапустить",
      run: async () => {
        await actions.controlAction(
          "restart",
          { service },
          `${service} перезапущен`,
        );
      },
    });
  }

  function ask(value: ConfirmState) {
    setConfirm({
      ...value,
      run: async () => {
        await value.run();
        setConfirm(undefined);
      },
    });
  }

  return (
    <div className="app-shell">
      <HeaderBar
        management={canManage}
        lastRefresh={dashboard.lastRefresh}
        busy={actions.busy === "refresh"}
        onRefresh={() =>
          void actions.runAction(
            "refresh",
            dashboard.refreshAll,
            "Данные обновлены",
          )
        }
        onManage={() => setManageOpen(true)}
      />

      {dashboard.error && (
        <div className="error-banner" role="alert">
          <strong>Не удалось обновить часть данных.</strong>
          <span>{dashboard.error}</span>
        </div>
      )}

      <StatusOverview status={dashboard.status} />

      <div className="dashboard-layout">
        <div className="dashboard-main">
          <TrafficPath status={dashboard.status} />
          <HistoryChart history={dashboard.history} />
          <NodesPanel
            control={dashboard.control}
            latency={actions.latency}
            busy={actions.busy}
            onLatency={() => void actions.testLatency()}
 onReselect={() => void actions.controlAction("reselect", {}, "Подобрана другая подходящая нода")}
            onSwitch={(node) => void switchNode(node)}
            onPin={(node) => void pinNode(node)}
          />
          <RoutingPanel
            control={dashboard.control}
            busy={actions.busy}
            onSave={updateRouting}
          />
          <DNSPanel
            control={dashboard.control}
            busy={actions.busy}
            onSave={updateDNS}
          />
        </div>

        <aside className="dashboard-side">
          <HealthGrid status={dashboard.status} />
          <ControlPanel
            control={dashboard.control}
            busy={actions.busy}
            onMode={changeMode}
            onPolicy={changePolicy}
            onTransports={updateTransports}
            onManage={() => setManageOpen(true)}
            onSetPin={actions.setPin}
          />
          <SubscriptionsPanel
            control={dashboard.control}
            busy={actions.busy}
            onAdd={addSubscription}
            onUpdate={updateSubscription}
            onEdit={setEditingSubscription}
            onDelete={deleteSubscription}
          />
          <ServicesPanel
            status={dashboard.status}
            canManage={canManage}
            busy={actions.busy}
            onRepair={() =>
              void actions.controlAction("repair", {}, "Backend восстановлен")
            }
            onRestart={restartService}
          />
          <EventsPanel history={dashboard.history} />
        </aside>
      </div>

      <ManageDialog
        open={manageOpen}
        control={dashboard.control}
        busy={actions.busy}
        onClose={() => setManageOpen(false)}
        onLogin={login}
        onLogout={logout}
      />
      <SubscriptionDialog
        subscription={editingSubscription}
        busy={actions.busy}
        onClose={() => setEditingSubscription(undefined)}
        onSave={saveSubscription}
      />
      <ConfirmDialog
        open={Boolean(confirm)}
        title={confirm?.title || ""}
        description={confirm?.description || ""}
        confirmLabel={confirm?.confirmLabel || "Продолжить"}
        danger={confirm?.danger}
        busy={Boolean(actions.busy)}
        onClose={() => setConfirm(undefined)}
        onConfirm={() => void confirm?.run()}
      />

      {actions.toast && (
        <div
          className={`toast ${actions.toastError ? "toast-error" : ""}`}
          role="status"
        >
          {actions.toast}
        </div>
      )}
    </div>
  );
}
