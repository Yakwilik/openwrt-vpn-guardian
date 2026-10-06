interface HeaderBarProps {
  management: boolean;
  lastRefresh?: number;
  busy: boolean;
  onRefresh: () => void;
  onManage: () => void;
}

export function HeaderBar({
  management,
  lastRefresh,
  busy,
  onRefresh,
  onManage,
}: HeaderBarProps) {
  return (
    <header className="topbar">
      <div className="brand">
        <div className="brand-mark">VG</div>
        <div>
          <div className="brand-title">VPN Guardian</div>
          <div className="brand-subtitle">OpenWrt selective routing</div>
        </div>
      </div>

      <div className="topbar-actions">
        <span className="updated">
          {lastRefresh
            ? `обновлено ${new Date(lastRefresh).toLocaleTimeString("ru-RU", {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
              })}`
            : "загрузка…"}
        </span>
        <button className="button button-ghost" onClick={onRefresh} disabled={busy}>
          {busy ? "Обновляю…" : "Обновить"}
        </button>
        <button className="button button-primary" onClick={onManage}>
          {management ? "Управление" : "Войти"}
        </button>
      </div>
    </header>
  );
}
