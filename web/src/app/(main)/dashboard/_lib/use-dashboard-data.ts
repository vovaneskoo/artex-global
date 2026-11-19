"use client";

import * as React from "react";

import { api } from "@/lib/api";
import type {
  Activity,
  ConvTokenSummary,
  Finding,
  InterceptPending,
  LLMProfile,
  Settings,
  Stats,
  Task,
  UsageStats,
} from "@/lib/types";

const FAST_POLL_MS = 5_000;
const SLOW_POLL_MS = 15_000;
const ACTIVITY_LIMIT = 30;
// The token chart offers at most 90 days, so never fetch more ledger history than that.
export const MAX_TOKEN_DAYS = 90;

interface PollState<T> {
  data: T | null;
  failed: boolean;
}

/**
 * Polls `load` on an interval. Skips overlapping requests, keeps the last good
 * data on failure (and reports `failed`), and only re-renders when the payload changes.
 */
function usePolling<T>(load: () => Promise<T>, intervalMs: number): PollState<T> {
  const [state, setState] = React.useState<PollState<T>>({ data: null, failed: false });

  // `load` must be referentially stable (module-level loaders below).
  React.useEffect(() => {
    let alive = true;
    let inFlight = false;
    let signature = "";
    const tick = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const data = await load();
        if (!alive) return;
        const next = JSON.stringify(data);
        if (next !== signature) {
          signature = next;
          setState({ data, failed: false });
        } else {
          setState((prev) => (prev.failed ? { ...prev, failed: false } : prev));
        }
      } catch (err: unknown) {
        if (!alive) return;
        console.warn("[dashboard] poll failed, keeping last data", err);
        setState((prev) => (prev.failed ? prev : { ...prev, failed: true }));
      } finally {
        inFlight = false;
      }
    };
    void tick();
    const timer = setInterval(tick, intervalMs);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [load, intervalMs]);

  return state;
}

interface LiveData {
  findings: Finding[];
  stats: Stats;
  settings: Settings;
  pending: InterceptPending[];
  activity: Activity[];
  convTokens: ConvTokenSummary[];
}

interface SlowData {
  assetCounts: Record<string, number>;
  llmProfiles: LLMProfile[];
  usage: UsageStats;
}

export interface DashboardData {
  tasks: Task[];
  findings: Finding[];
  stats: Stats | null;
  settings: Settings | null;
  pending: InterceptPending[];
  activity: Activity[];
  convTokens: ConvTokenSummary[];
  assetCounts: Record<string, number>;
  llmProfiles: LLMProfile[];
  usage: UsageStats | null;
  /** True until the first task + live payloads have arrived. */
  isLoading: boolean;
  /** True while the latest poll of any source failed (stale data is still shown). */
  isStale: boolean;
}

const loadTasks = () => api.tasks().then((r) => r.tasks);

const loadLive = async (): Promise<LiveData> => {
  const [findings, stats, settings, pending, activity, convTokens] = await Promise.all([
    api.findings(),
    api.stats(),
    api.settings(),
    api.interceptPending(),
    api.activity(undefined, { limit: ACTIVITY_LIMIT }),
    api.conversationTokens(),
  ]);
  return { findings, stats, settings, pending, activity: activity.items, convTokens };
};

const loadSlow = async (): Promise<SlowData> => {
  const [assetCounts, llmProfiles, usage] = await Promise.all([
    api.assetCounts(),
    api.llmProfiles(),
    api.usageStats(MAX_TOKEN_DAYS),
  ]);
  return { assetCounts: assetCounts ?? {}, llmProfiles, usage };
};

export function useDashboardData(): DashboardData {
  // Tasks are the most expensive source, so they poll on their own and a large
  // history cannot hold back the other panels.
  const tasks = usePolling(loadTasks, FAST_POLL_MS);
  const live = usePolling(loadLive, FAST_POLL_MS);
  const slow = usePolling(loadSlow, SLOW_POLL_MS);

  return {
    tasks: tasks.data ?? [],
    findings: live.data?.findings ?? [],
    stats: live.data?.stats ?? null,
    settings: live.data?.settings ?? null,
    pending: live.data?.pending ?? [],
    activity: live.data?.activity ?? [],
    convTokens: live.data?.convTokens ?? [],
    assetCounts: slow.data?.assetCounts ?? {},
    llmProfiles: slow.data?.llmProfiles ?? [],
    usage: slow.data?.usage ?? null,
    isLoading: (tasks.data === null && !tasks.failed) || (live.data === null && !live.failed),
    isStale: tasks.failed || live.failed || slow.failed,
  };
}
