import type { ConvTokenSummary, Finding, Severity, Task, UsageStats } from "@/lib/types";

// Pure aggregation helpers for the dashboard. Nothing here touches React or the
// network, so every number the page shows can be unit-tested in isolation.

export type ProfileKey = number | null;
export type ProfileFilter = ProfileKey | "all";

export interface TokenBucket {
  input: number; // includes cache reads
  output: number;
  cacheRead: number;
  cacheWrite: number;
  taskCount: number;
}

export interface DailyPoint {
  date: string; // MM-DD
  input: number;
  output: number;
  cacheRead: number;
}

export type SeverityCounts = Record<"critical" | "high" | "medium" | "low", number>;

export const EMPTY_BUCKET: TokenBucket = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, taskCount: 0 };

const MS_PER_DAY = 86_400_000;

export function addBuckets(a: TokenBucket, b: TokenBucket): TokenBucket {
  return {
    input: a.input + b.input,
    output: a.output + b.output,
    cacheRead: a.cacheRead + b.cacheRead,
    cacheWrite: a.cacheWrite + b.cacheWrite,
    taskCount: a.taskCount + b.taskCount,
  };
}

function foldInto(m: Map<ProfileKey, TokenBucket>, key: ProfileKey, add: TokenBucket): void {
  m.set(key, addBuckets(m.get(key) ?? EMPTY_BUCKET, add));
}

/** Token buckets per LLM profile from task + conversation totals (covers all history). */
export function bucketsFromActivity(
  tasks: readonly Task[],
  convTokens: readonly ConvTokenSummary[],
  defaultProfileId: ProfileKey,
): Map<ProfileKey, TokenBucket> {
  const m = new Map<ProfileKey, TokenBucket>();
  for (const t of tasks) {
    foldInto(m, t.llm_profile_id ?? defaultProfileId, {
      input: t.tokens?.input_tokens ?? 0,
      output: t.tokens?.output_tokens ?? 0,
      cacheRead: t.tokens?.cache_read_tokens ?? 0,
      cacheWrite: t.tokens?.cache_write_tokens ?? 0,
      taskCount: 1,
    });
  }
  for (const c of convTokens) {
    foldInto(m, c.llm_profile_id ?? defaultProfileId, {
      input: c.input_tokens,
      output: c.output_tokens,
      cacheRead: c.cache_read_tokens,
      cacheWrite: c.cache_write_tokens,
      taskCount: 0,
    });
  }
  return m;
}

/** Token buckets per LLM profile from the llm_usage metering ledger (exact per call). */
export function bucketsFromLedger(
  usage: UsageStats | null,
  profileIdByName: ReadonlyMap<string, number>,
  defaultProfileId: ProfileKey,
): Map<ProfileKey, TokenBucket> {
  const m = new Map<ProfileKey, TokenBucket>();
  for (const p of usage?.by_profile ?? []) {
    // Renamed/deleted profiles fall back to the default bucket so "all" stays complete.
    foldInto(m, profileIdByName.get(p.profile_name) ?? defaultProfileId, {
      input: p.input_tokens,
      output: p.output_tokens,
      cacheRead: p.cache_read_tokens,
      cacheWrite: p.cache_write_tokens,
      taskCount: p.tasks,
    });
  }
  return m;
}

/** The ledger is exact but only exists once metering was enabled; prefer it when it has data. */
export function hasLedgerData(usage: UsageStats | null): boolean {
  return (usage?.by_profile ?? []).some((p) => p.input_tokens + p.output_tokens > 0);
}

export function selectBucket(buckets: ReadonlyMap<ProfileKey, TokenBucket>, filter: ProfileFilter): TokenBucket {
  if (filter !== "all") return buckets.get(filter) ?? EMPTY_BUCKET;
  let total = EMPTY_BUCKET;
  for (const b of buckets.values()) total = addBuckets(total, b);
  return total;
}

/** Share of input tokens served from cache, 0–100. Input already includes cache reads. */
export function cacheHitPct(b: TokenBucket): number {
  return b.input > 0 ? Math.round((b.cacheRead / b.input) * 100) : 0;
}

function isoDay(d: Date): string {
  return d.toISOString().slice(0, 10);
}

/** Every day in the window (oldest first), so gaps render as empty bars instead of disappearing. */
export function dayRange(days: number, now: Date): string[] {
  return Array.from({ length: days }, (_, i) => isoDay(new Date(now.getTime() - (days - 1 - i) * MS_PER_DAY)));
}

interface DayRow {
  date: string; // YYYY-MM-DD
  profile: ProfileKey;
  input: number;
  output: number;
  cacheRead: number;
}

function toDailySeries(rows: readonly DayRow[], days: number, filter: ProfileFilter, now: Date): DailyPoint[] {
  const range = dayRange(days, now);
  const totals = new Map(range.map((d) => [d, { input: 0, output: 0, cacheRead: 0 }]));
  for (const r of rows) {
    const prev = totals.get(r.date);
    if (!prev || (filter !== "all" && r.profile !== filter)) continue;
    totals.set(r.date, {
      input: prev.input + r.input,
      output: prev.output + r.output,
      cacheRead: prev.cacheRead + r.cacheRead,
    });
  }
  return range.map((d) => ({ date: d.slice(5), ...(totals.get(d) ?? { input: 0, output: 0, cacheRead: 0 }) }));
}

/** Daily series from task/conversation totals, bucketed by creation day (approximate). */
export function dailyFromActivity(
  tasks: readonly Task[],
  convTokens: readonly ConvTokenSummary[],
  opts: { days: number; filter: ProfileFilter; defaultProfileId: ProfileKey; now: Date },
): DailyPoint[] {
  const rows: DayRow[] = [
    ...tasks.map((t) => ({
      date: t.created_at.slice(0, 10),
      profile: t.llm_profile_id ?? opts.defaultProfileId,
      input: t.tokens?.input_tokens ?? 0,
      output: t.tokens?.output_tokens ?? 0,
      cacheRead: t.tokens?.cache_read_tokens ?? 0,
    })),
    ...convTokens.map((c) => ({
      date: c.created_at.slice(0, 10),
      profile: c.llm_profile_id ?? opts.defaultProfileId,
      input: c.input_tokens,
      output: c.output_tokens,
      cacheRead: c.cache_read_tokens,
    })),
  ];
  return toDailySeries(rows, opts.days, opts.filter, opts.now);
}

/** Daily series from the metering ledger (real per-call timestamps). */
export function dailyFromLedger(
  usage: UsageStats | null,
  opts: {
    days: number;
    filter: ProfileFilter;
    profileIdByName: ReadonlyMap<string, number>;
    defaultProfileId: ProfileKey;
    now: Date;
  },
): DailyPoint[] {
  const rows: DayRow[] = (usage?.daily ?? []).map((d) => ({
    date: d.date,
    profile: opts.profileIdByName.get(d.profile_name) ?? opts.defaultProfileId,
    input: d.input_tokens,
    output: d.output_tokens,
    cacheRead: d.cache_read_tokens,
  }));
  return toDailySeries(rows, opts.days, opts.filter, opts.now);
}

export function severityCounts(findings: readonly Finding[]): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    if (f.severity in counts) counts[f.severity as keyof SeverityCounts] += 1;
  }
  return counts;
}

export function countBy<T>(items: readonly T[], key: (item: T) => string): Record<string, number> {
  const m: Record<string, number> = {};
  for (const it of items) {
    const k = key(it);
    m[k] = (m[k] ?? 0) + 1;
  }
  return m;
}

export function latestTasks(tasks: readonly Task[], limit: number): Task[] {
  const at = (t: Task) => t.last_activity_unix ?? t.created_unix ?? 0;
  return [...tasks].sort((a, b) => at(b) - at(a)).slice(0, limit);
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

/** Newest first; within the same second, the more severe finding wins. */
export function latestFindings(findings: readonly Finding[], limit: number): Finding[] {
  return [...findings]
    .sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts) || SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity])
    .slice(0, limit);
}

export function fmtTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(n);
}

/** Compact relative time ("5m"), or null when there is no timestamp. Unix seconds or ISO string. */
export function fmtRel(ts: string | number | undefined, now: number = Date.now()): string | null {
  if (!ts) return null;
  const ms = now - (typeof ts === "number" ? ts * 1000 : Date.parse(ts));
  if (Number.isNaN(ms)) return null;
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  return `${Math.floor(h / 24)}d`;
}
