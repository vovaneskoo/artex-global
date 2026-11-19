import { describe, expect, it } from "vitest";

import type { ConvTokenSummary, Finding, Task, UsageStats } from "@/lib/types";

import {
  bucketsFromActivity,
  bucketsFromLedger,
  cacheHitPct,
  dailyFromActivity,
  dailyFromLedger,
  dayRange,
  fmtRel,
  fmtTokens,
  hasLedgerData,
  latestFindings,
  latestTasks,
  selectBucket,
  severityCounts,
} from "./metrics";

const NOW = new Date("2026-11-19T12:00:00Z");

function task(over: Partial<Task>): Task {
  return { id: "1", description: "t", status: "done", created_at: "2026-11-18T10:00:00Z", ...over } as Task;
}

function tok(input: number, output: number, cacheRead = 0): Task["tokens"] {
  return { input_tokens: input, output_tokens: output, cache_read_tokens: cacheRead, cache_write_tokens: 0 };
}

function finding(over: Partial<Finding>): Finding {
  return {
    id: "f",
    vulnclass: "SQLi",
    severity: "low",
    status: "confirmed",
    summary: "",
    evidence: "",
    ts: "",
    ...over,
  } as Finding;
}

const conv: ConvTokenSummary = {
  llm_profile_id: 2,
  created_at: "2026-11-19T08:00:00Z",
  input_tokens: 50,
  output_tokens: 5,
  cache_read_tokens: 10,
  cache_write_tokens: 0,
};

const ledger: UsageStats = {
  by_profile: [
    {
      profile_name: "venice",
      calls: 3,
      tasks: 2,
      input_tokens: 1000,
      output_tokens: 100,
      cache_read_tokens: 600,
      cache_write_tokens: 0,
    },
    {
      profile_name: "deleted",
      calls: 1,
      tasks: 1,
      input_tokens: 10,
      output_tokens: 1,
      cache_read_tokens: 0,
      cache_write_tokens: 0,
    },
  ],
  daily: [
    { profile_name: "venice", date: "2026-11-19", input_tokens: 700, output_tokens: 70, cache_read_tokens: 400 },
    { profile_name: "venice", date: "2026-11-01", input_tokens: 300, output_tokens: 30, cache_read_tokens: 200 },
  ],
};

describe("token buckets", () => {
  it("groups task and conversation tokens by profile, defaulting missing profile ids", () => {
    // Arrange
    const tasks = [task({ tokens: tok(100, 10, 40) }), task({ llm_profile_id: 2, tokens: tok(20, 2) })];

    // Act
    const m = bucketsFromActivity(tasks, [conv], 1);

    // Assert
    expect(m.get(1)).toEqual({ input: 100, output: 10, cacheRead: 40, cacheWrite: 0, taskCount: 1 });
    expect(m.get(2)).toEqual({ input: 70, output: 7, cacheRead: 10, cacheWrite: 0, taskCount: 1 });
  });

  it("maps ledger rows to profile ids and folds unknown names into the default bucket", () => {
    const m = bucketsFromLedger(ledger, new Map([["venice", 3]]), 1);

    expect(m.get(3)?.input).toBe(1000);
    expect(m.get(1)?.input).toBe(10);
    expect(selectBucket(m, "all").input).toBe(1010);
  });

  it("returns an empty bucket for a profile without data", () => {
    expect(selectBucket(new Map(), 7)).toEqual({ input: 0, output: 0, cacheRead: 0, cacheWrite: 0, taskCount: 0 });
  });

  it("prefers the ledger only when it carries tokens", () => {
    expect(hasLedgerData(ledger)).toBe(true);
    expect(hasLedgerData({ by_profile: [], daily: [] })).toBe(false);
    expect(hasLedgerData(null)).toBe(false);
  });

  it("computes cache hit rate against total input and handles zero input", () => {
    expect(cacheHitPct({ input: 200, output: 0, cacheRead: 98, cacheWrite: 0, taskCount: 0 })).toBe(49);
    expect(cacheHitPct({ input: 0, output: 0, cacheRead: 0, cacheWrite: 0, taskCount: 0 })).toBe(0);
  });
});

describe("daily series", () => {
  it("covers every day of the window so idle days are visible", () => {
    expect(dayRange(3, NOW)).toEqual(["2026-11-17", "2026-11-18", "2026-11-19"]);
  });

  it("drops rows outside the window and keeps zero days", () => {
    const series = dailyFromLedger(ledger, {
      days: 7,
      filter: "all",
      profileIdByName: new Map([["venice", 3]]),
      defaultProfileId: 1,
      now: NOW,
    });

    expect(series).toHaveLength(7);
    expect(series.at(-1)).toEqual({ date: "11-19", input: 700, output: 70, cacheRead: 400 });
    expect(series.slice(0, -1).every((p) => p.input === 0)).toBe(true);
  });

  it("filters activity-derived days by profile", () => {
    const tasks = [task({ tokens: tok(100, 10) })];

    const onlyConv = dailyFromActivity(tasks, [conv], { days: 2, filter: 2, defaultProfileId: 1, now: NOW });

    expect(onlyConv).toEqual([
      { date: "11-18", input: 0, output: 0, cacheRead: 0 },
      { date: "11-19", input: 50, output: 5, cacheRead: 10 },
    ]);
  });
});

describe("lists and counters", () => {
  it("counts findings by severity", () => {
    const counts = severityCounts([
      finding({ severity: "critical" }),
      finding({ severity: "low" }),
      finding({ severity: "low" }),
    ]);

    expect(counts).toEqual({ critical: 1, high: 0, medium: 0, low: 2 });
  });

  it("orders tasks by last activity, falling back to creation time", () => {
    const tasks = [
      task({ id: "a", created_unix: 10 }),
      task({ id: "b", last_activity_unix: 30 }),
      task({ id: "c", created_unix: 20 }),
    ];

    expect(latestTasks(tasks, 2).map((t) => t.id)).toEqual(["b", "c"]);
  });

  it("orders findings newest first and breaks ties by severity", () => {
    const ts = "2026-11-19T10:00:00Z";
    const list = [
      finding({ id: "old", ts: "2026-11-01T00:00:00Z", severity: "critical" }),
      finding({ id: "low", ts, severity: "low" }),
      finding({ id: "crit", ts, severity: "critical" }),
    ];

    expect(latestFindings(list, 3).map((f) => f.id)).toEqual(["crit", "low", "old"]);
  });
});

describe("formatting", () => {
  it("abbreviates token counts", () => {
    expect(fmtTokens(950)).toBe("950");
    expect(fmtTokens(190_300)).toBe("190.3k");
    expect(fmtTokens(3_900_000)).toBe("3.9M");
  });

  it("formats relative time from unix seconds or ISO strings", () => {
    const now = NOW.getTime();
    expect(fmtRel(undefined, now)).toBeNull();
    expect(fmtRel("not a date", now)).toBeNull();
    expect(fmtRel(now / 1000 - 30, now)).toBe("30s");
    expect(fmtRel("2026-11-19T11:47:00Z", now)).toBe("13m");
    expect(fmtRel("2026-11-08T12:00:00Z", now)).toBe("11d");
  });
});
