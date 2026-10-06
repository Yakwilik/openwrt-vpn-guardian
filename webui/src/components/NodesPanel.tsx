import { useMemo, useState } from "react";
import type { ControlResponse, NodeInfo } from "../types";
import { protocolLabel } from "../utils";

const collapsedNodeCount = 5;

interface NodesPanelProps {
  control?: ControlResponse;
  latency: Record<string, string>;
  busy?: string;
  onLatency: () => void;
  onSwitch: (node: NodeInfo) => void;
  onPin: (node: NodeInfo) => void;
}

export function NodesPanel({
  control,
  latency,
  busy,
  onLatency,
  onSwitch,
  onPin,
}: NodesPanelProps) {
  const [query, setQuery] = useState("");
  const [protocol, setProtocol] = useState("all");
  const [expanded, setExpanded] = useState(false);
  const canManage = Boolean(control?.authenticated && control.authConfigured);
  const nodes = control?.nodes ?? [];

  const protocols = useMemo(
    () => Array.from(new Set(nodes.map((node) => node.net))).sort(),
    [nodes],
  );

  const filtered = useMemo(() => {
    const normalized = query.trim().toLocaleLowerCase("ru-RU");
    return [...nodes]
      .filter((node) => protocol === "all" || node.net === protocol)
      .filter((node) => {
        if (!normalized) return true;
        return [node.name, node.net, node.address]
          .join(" ")
          .toLocaleLowerCase("ru-RU")
          .includes(normalized);
      })
      .sort(
        (a, b) =>
          Number(b.active) - Number(a.active) ||
          Number(b.pinned) - Number(a.pinned) ||
          a.name.localeCompare(b.name),
      );
  }, [nodes, protocol, query]);

  const visibleNodes = expanded
    ? filtered
    : filtered.slice(0, collapsedNodeCount);
  const hiddenCount = Math.max(0, filtered.length - visibleNodes.length);

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>Ноды</h2>
          <p>Доступные кандидаты после фильтрации transport allowlist.</p>
        </div>
        <div className="heading-actions">
          <span className="panel-counter">{filtered.length}/{nodes.length}</span>
          <button className="button button-ghost" disabled={!canManage || Boolean(busy)} onClick={onLatency}>
            {busy === "latency" ? "Проверяю…" : "Latency"}
          </button>
        </div>
      </div>

      <div className="node-toolbar">
        <input
          className="field"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Страна, название или endpoint"
        />
        <select className="field select" value={protocol} onChange={(event) => setProtocol(event.target.value)}>
          <option value="all">Все протоколы</option>
          {protocols.map((value) => (
            <option value={value} key={value}>{protocolLabel(value)}</option>
          ))}
        </select>
      </div>

      <div className="node-table" role="table" aria-label="VPN ноды">
        <div className="node-row node-table-head" role="row">
          <span>Нода</span>
          <span>Протокол</span>
          <span>Endpoint</span>
          <span>Latency</span>
          <span />
        </div>
        {visibleNodes.map((node) => {
          const key = `${node.sub}:${node.id}`;
          return (
            <div className={`node-row ${node.active ? "node-active" : ""}`} role="row" key={key}>
              <div className="node-primary">
                <span className={`mini-dot ${node.active ? "is-up" : ""}`} />
                <div>
                  <strong>{node.name}</strong>
                  <div className="node-tags">
                    {node.active && <span className="badge badge-ok">ACTIVE</span>}
                    {node.pinned && <span className="badge">PINNED</span>}
                    <span className="muted">#{node.subscriptionId}</span>
                  </div>
                </div>
              </div>
              <span>{protocolLabel(node.net)}</span>
              <span className="mono node-endpoint">{node.address || "—"}</span>
              <span className="mono">{latency[key] || node.pingLatency || "—"}</span>
              <div className="row-actions">
                <button className="button button-quiet" disabled={!canManage || Boolean(busy) || node.active} onClick={() => onSwitch(node)}>
                  Использовать
                </button>
                <button className={`button button-quiet ${node.pinned ? "is-selected" : ""}`} disabled={!canManage || Boolean(busy)} onClick={() => onPin(node)}>
                  {node.pinned ? "Закреплено" : "Pin"}
                </button>
              </div>
            </div>
          );
        })}
        {filtered.length === 0 && <div className="empty">Ноды не найдены</div>}
      </div>

      {filtered.length > collapsedNodeCount && (
        <div className="collapse-footer">
          <span className="collapse-summary">
            {expanded
              ? `Показаны все ${filtered.length}`
              : `Показаны ${visibleNodes.length} из ${filtered.length}`}
          </span>
          <button
            className="button button-quiet collapse-button"
            aria-expanded={expanded}
            onClick={() => setExpanded((value) => !value)}
          >
            {expanded ? "Свернуть" : `Показать все · +${hiddenCount}`}
          </button>
        </div>
      )}
    </section>
  );
}
