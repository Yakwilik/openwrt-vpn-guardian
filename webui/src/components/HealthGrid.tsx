import type { StatusSnapshot } from "../types";

interface HealthGridProps {
  status?: StatusSnapshot;
}

export function HealthGrid({ status }: HealthGridProps) {
  const checks = Object.entries(status?.health ?? {});

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>VPN backend health</h2>
          <p>Независимые проверки внешней доступности через VPN.</p>
        </div>
        <span className="panel-counter">{status?.health_count ?? 0}/4</span>
      </div>

      <div className="health-grid">
        {checks.length === 0 && <div className="empty">Проверки ещё не загружены</div>}
        {checks.map(([name, check]) => {
          const ok = probeHealthy(name, check.code);
          return (
            <article className="health-card" key={name}>
              <div className="health-name">
                <span className={`mini-dot ${ok ? "is-up" : "is-down"}`} />
                {name}
              </div>
              <div className="health-value">{check.ms} ms</div>
              <div className="health-code">HTTP {check.code || "—"}</div>
            </article>
          );
        })}
      </div>
    </section>
  );
}

const expectedHealthCodes: Record<string, number[]> = {
  google: [204],
  cloudflare: [204],
  telegram: [401],
  openai: [401],
};

function probeHealthy(name: string, code: number): boolean {
  const expected = expectedHealthCodes[name];
  return expected ? expected.includes(code) : code > 0 && code < 500;
}
