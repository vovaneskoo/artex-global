"use client";

import * as React from "react";

import type { ConvTokenSummary, LLMProfile, Task, UsageStats } from "@/lib/types";

import { bucketsFromActivity, bucketsFromLedger, hasLedgerData, type ProfileKey, type TokenBucket } from "./metrics";

export interface TokenModel {
  buckets: ReadonlyMap<ProfileKey, TokenBucket>;
  /** "ledger" = exact llm_usage metering; "activity" = task/conversation totals (history fallback). */
  source: "ledger" | "activity";
  profileIdByName: ReadonlyMap<string, number>;
  defaultProfileId: ProfileKey;
}

/**
 * One token model for the whole page. The exact metering ledger wins whenever it
 * has data; older installs without it fall back to activity totals, so the
 * operator never has to pick a "data source".
 */
export function useTokenModel(
  tasks: readonly Task[],
  convTokens: readonly ConvTokenSummary[],
  usage: UsageStats | null,
  profiles: readonly LLMProfile[],
): TokenModel {
  return React.useMemo(() => {
    const active = profiles.find((p) => p.is_default);
    const defaultProfileId = active ? Number(active.id) : null;
    const profileIdByName = new Map(profiles.map((p) => [p.name, Number(p.id)]));
    if (hasLedgerData(usage)) {
      return {
        buckets: bucketsFromLedger(usage, profileIdByName, defaultProfileId),
        source: "ledger",
        profileIdByName,
        defaultProfileId,
      };
    }
    return {
      buckets: bucketsFromActivity(tasks, convTokens, defaultProfileId),
      source: "activity",
      profileIdByName,
      defaultProfileId,
    };
  }, [tasks, convTokens, usage, profiles]);
}
