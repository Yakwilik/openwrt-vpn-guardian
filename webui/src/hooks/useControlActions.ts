import { useState } from "react";
import { postControl } from "../api";
import type { ControlPayload, ControlResponse } from "../types";

interface ControlActionsOptions {
  control?: ControlResponse;
  setControl: (value: ControlResponse) => void;
  loadStatus: () => Promise<void>;
}

export function useControlActions({
  control,
  setControl,
  loadStatus,
}: ControlActionsOptions) {
  const [busy, setBusy] = useState("");
  const [toast, setToast] = useState("");
  const [toastError, setToastError] = useState(false);
  const [latency, setLatency] = useState<Record<string, string>>({});

  async function runAction<T>(
    name: string,
    work: () => Promise<T>,
    success: string,
  ): Promise<T | undefined> {
    setBusy(name);
    try {
      const value = await work();
      notify(success);
      return value;
    } catch (err) {
      notify(err instanceof Error ? err.message : "Операция не выполнена", true);
      return undefined;
    } finally {
      setBusy("");
    }
  }

  async function controlAction(
    action: string,
    payload: ControlPayload = {},
    success = "Готово",
  ): Promise<ControlResponse | undefined> {
    const next = await runAction(
      action,
      () =>
        postControl(action, payload, {
          csrf: control?.csrf,
        }),
      success,
    );
    if (!next) return undefined;

    setControl(next);
    await loadStatus();
    return next;
  }

  async function login(pin: string): Promise<boolean> {
    const next = await runAction(
      "login",
      () =>
        postControl(
          "login",
          control?.authConfigured ? { pin } : {},
          { unlock: !control?.authConfigured },
        ),
      "Управление включено",
    );
    if (!next) return false;

    setControl(next);
    return true;
  }

  async function logout(): Promise<boolean> {
    const next = await runAction(
      "logout",
      () => postControl("logout"),
      "Управление выключено",
    );
    if (!next) return false;

    setControl(next);
    return true;
  }

  async function setPin(pin: string): Promise<void> {
    await controlAction("change_pin", { pin }, "PIN установлен");
  }

  async function testLatency(): Promise<void> {
    const next = await controlAction("latency", {}, "Latency обновлена");
    if (!next?.result) return;

    try {
      const result = JSON.parse(next.result) as {
        whiches?: Array<{ id: number; sub: number; pingLatency?: string }>;
      };
      const values: Record<string, string> = {};
      for (const row of result.whiches ?? []) {
        values[`${row.sub}:${row.id}`] = row.pingLatency || "—";
      }
      setLatency(values);
    } catch {
      notify("Latency получена, но ответ не удалось отобразить", true);
    }
  }

  function notify(message: string, error = false) {
    setToast(message);
    setToastError(error);
    window.setTimeout(() => {
      setToast((current) => (current === message ? "" : current));
    }, 4_000);
  }

  return {
    busy,
    latency,
    toast,
    toastError,
    runAction,
    controlAction,
    login,
    logout,
    setPin,
    testLatency,
  };
}
