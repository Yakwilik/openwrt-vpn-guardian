import type { ControlPayload, ControlResponse, DashboardMode } from "./types";

type ModeRequest = (
  action: string,
  payload: ControlPayload,
  options: { csrf?: string },
) => Promise<ControlResponse>;

// The UI has one mode selector, while the API stores traffic coverage and
// backend selection separately. Reuse the validated operations in a safe
// order and publish only server-confirmed states, including partial failure.
export async function applyDashboardMode(
  initial: ControlResponse,
  mode: DashboardMode,
  request: ModeRequest,
  onApplied: (value: ControlResponse) => void,
): Promise<ControlResponse> {
  let current = initial;
  async function apply(action: string, payload: ControlPayload = {}) {
    const next = await request(action, payload, { csrf: current.csrf });
    if (!next.ok) throw new Error(next.error || next.message || "Не удалось изменить режим");
    current = next;
    onApplied(next);
  }

  if (mode === "full-vpn") {
    if (current.trafficMode === "full-vpn") return current;
    // Full VPN requires an active Auto/pinned backend, not Direct mode.
    if (current.control.mode !== "auto" && current.control.mode !== "pinned") {
      await apply("auto");
    }
    await apply("traffic_mode", { trafficMode: "full-vpn" });
  } else {
    // The API deliberately rejects Direct while full-VPN protection is on.
    // Leaving Full VPN first also restores the saved selective DNS policy.
    if (current.trafficMode === "full-vpn") {
      await apply("traffic_mode", { trafficMode: "selective" });
    }
    if (current.control.mode !== mode) await apply(mode);
  }
  return current;
}
