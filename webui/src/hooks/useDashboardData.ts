import { useCallback, useEffect, useRef, useState } from "react";
import { fetchControl, fetchHistory, fetchStatus } from "../api";
import type { ControlResponse, HistoryResponse, StatusSnapshot } from "../types";

export function useDashboardData() {
  const [status, setStatus] = useState<StatusSnapshot>();
  const [history, setHistory] = useState<HistoryResponse>();
  const [control, setControlState] = useState<ControlResponse>();
  // A GET started before a successful POST must never roll its result back.
  const controlGeneration = useRef(0);
  const setControl = useCallback((value: ControlResponse) => {
    controlGeneration.current += 1;
    setControlState(value);
  }, []);
  const [lastRefresh, setLastRefresh] = useState<number>();
  const [error, setError] = useState("");

  const loadStatus = useCallback(async () => {
    try {
      const value = await fetchStatus();
      setStatus(value);
      setLastRefresh(Date.now());
      setError("");
    } catch (err) {
      setError(errorMessage(err));
    }
  }, []);

  const loadHistory = useCallback(async () => {
    try {
      setHistory(await fetchHistory());
      setError("");
    } catch (err) {
      setError(errorMessage(err));
    }
  }, []);

  const loadControl = useCallback(async () => {
    const generation = ++controlGeneration.current;
    try {
      const value = await fetchControl();
      if (generation === controlGeneration.current) {
        setControlState(value);
        setError("");
      }
    } catch (err) {
      if (generation === controlGeneration.current) {
        setError(errorMessage(err));
      }
    }
  }, []);

  const refreshAll = useCallback(async () => {
    await Promise.allSettled([loadStatus(), loadHistory(), loadControl()]);
  }, [loadControl, loadHistory, loadStatus]);

  useEffect(() => {
    void refreshAll();
    const statusTimer = window.setInterval(() => void loadStatus(), 5_000);
    const historyTimer = window.setInterval(() => void loadHistory(), 15_000);
    const controlTimer = window.setInterval(() => void loadControl(), 60_000);

    return () => {
      window.clearInterval(statusTimer);
      window.clearInterval(historyTimer);
      window.clearInterval(controlTimer);
    };
  }, [loadControl, loadHistory, loadStatus, refreshAll]);

  return {
    status,
    history,
    control,
    setControl,
    lastRefresh,
    error,
    loadStatus,
    loadHistory,
    loadControl,
    refreshAll,
  };
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : "Не удалось обновить данные";
}
