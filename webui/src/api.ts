import type {
  ControlPayload,
  ControlResponse,
  HistoryResponse,
  StatusSnapshot,
} from "./types";

async function readJSON<T>(response: Response): Promise<T> {
  const body = (await response.json()) as T & { error?: string; message?: string };
  if (!response.ok) {
    throw new Error(body.error || body.message || `HTTP ${response.status}`);
  }
  return body;
}

export async function fetchStatus(signal?: AbortSignal): Promise<StatusSnapshot> {
  return readJSON<StatusSnapshot>(
    await fetch("/api/status", { cache: "no-store", signal }),
  );
}

export async function fetchHistory(signal?: AbortSignal): Promise<HistoryResponse> {
  return readJSON<HistoryResponse>(
    await fetch("/api/history", { cache: "no-store", signal }),
  );
}

export async function fetchControl(signal?: AbortSignal): Promise<ControlResponse> {
  return readJSON<ControlResponse>(
    await fetch("/api/control", {
      cache: "no-store",
      credentials: "same-origin",
      signal,
    }),
  );
}

export async function postControl(
  action: string,
  payload: ControlPayload = {},
  options: { csrf?: string; unlock?: boolean } = {},
): Promise<ControlResponse> {
  const headers = new Headers({ "Content-Type": "application/json" });
  if (options.csrf) {
    headers.set("X-VPN-CSRF", options.csrf);
  }
  if (options.unlock) {
    headers.set("X-VPN-Unlock", "1");
  }

  return readJSON<ControlResponse>(
    await fetch("/api/control", {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers,
      body: JSON.stringify({ action, ...payload }),
    }),
  );
}
