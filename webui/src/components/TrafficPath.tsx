import type { StatusSnapshot } from "../types";

interface TrafficPathProps {
  status?: StatusSnapshot;
}

export function TrafficPath({ status }: TrafficPathProps) {
  const frontReady = Boolean(status?.tproxy_active && status?.tproxy?.front_port);
  const backendReady = Boolean(status?.tproxy?.backend_socks && status?.health_count);
  const directReady = status?.services?.front === "running";

  return (
    <section className="panel">
      <PanelHeading
        title="Путь трафика"
        description="Direct-трафик и VPN-класс разделены до backend."
      />

      <div className="routes">
        <Route
          label="Direct"
          healthy={directReady}
          steps={["LAN", "vpn-front", "freedom", "Internet"]}
        />
        <Route
          label="Proxy"
          healthy={frontReady && backendReady}
          steps={["LAN", "vpn-front", "vpn-policy", "v2rayA", "VPN node"]}
        />
        <Route
          label="DNS"
          healthy={Boolean(status?.dns_healthy)}
          steps={
            status?.dns_mode === "system"
              ? ["LAN", "vpn-guardian-dns", "dnsmasq", "WAN resolver"]
              : status?.dns_mode === "xray"
                ? ["LAN", "DNS dispatcher", "Xray DNS", "VPN backend"]
                : ["LAN", "DNS dispatcher", "VPN backend", "custom resolver"]
          }
        />
      </div>

      <div className="technical-strip">
        <State label="TPROXY" ok={Boolean(status?.tproxy?.nft)} />
        <State label="Policy route" ok={Boolean(status?.tproxy?.policy)} />
        <State label="Route table" ok={Boolean(status?.tproxy?.route)} />
        <State label="Front listener" ok={Boolean(status?.tproxy?.front_port)} />
        <State label="Backend SOCKS" ok={Boolean(status?.tproxy?.backend_socks)} />
        <State
          label={`DNS ${status?.dns_mode || "—"}`}
          ok={Boolean(status?.dns_healthy)}
        />
      </div>
    </section>
  );
}

function PanelHeading({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div className="panel-heading">
      <div>
        <h2>{title}</h2>
        <p>{description}</p>
      </div>
    </div>
  );
}

function Route({
  label,
  healthy,
  steps,
}: {
  label: string;
  healthy: boolean;
  steps: string[];
}) {
  return (
    <div className="route-row">
      <div className="route-label">
        <span className={`mini-dot ${healthy ? "is-up" : "is-down"}`} />
        {label}
      </div>
      <div className="route-flow">
        {steps.map((step, index) => (
          <div className="route-step-wrap" key={step}>
            <span className="route-step">{step}</span>
            {index < steps.length - 1 && <span className="route-arrow">→</span>}
          </div>
        ))}
      </div>
    </div>
  );
}

function State({ label, ok }: { label: string; ok: boolean }) {
  return (
    <span className={`technical-state ${ok ? "technical-ok" : "technical-bad"}`}>
      <span className="mini-dot" />
      {label}
    </span>
  );
}
