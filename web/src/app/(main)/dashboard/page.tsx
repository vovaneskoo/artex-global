"use client";

import * as React from "react";

import Link from "next/link";

import { PlusIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Button } from "@/components/ui/button";

import { ActivityCard } from "./_components/activity-card";
import { AttentionBanner } from "./_components/attention-banner";
import { FindingsCard } from "./_components/findings-card";
import { KpiCards } from "./_components/kpi-cards";
import { SystemCard } from "./_components/system-card";
import { TasksCard } from "./_components/tasks-card";
import { TokenUsageCard } from "./_components/token-usage-card";
import { cacheHitPct, countBy, latestFindings, latestTasks, selectBucket, severityCounts } from "./_lib/metrics";
import { useDashboardData } from "./_lib/use-dashboard-data";
import { useTokenModel } from "./_lib/use-token-model";

const RECENT_TASKS = 6;
const RECENT_FINDINGS = 6;

// Layout, top to bottom: what needs me now → what is running → what it found → what it cost.
export default function DashboardPage() {
  const t = useTranslations("dashboard");
  const d = useDashboardData();
  const tokenModel = useTokenModel(d.tasks, d.convTokens, d.usage, d.llmProfiles);

  const tasksByStatus = React.useMemo(() => countBy(d.tasks, (task) => task.status), [d.tasks]);
  const recentTasks = React.useMemo(() => latestTasks(d.tasks, RECENT_TASKS), [d.tasks]);
  const severity = React.useMemo(() => severityCounts(d.findings), [d.findings]);
  const recentFindings = React.useMemo(() => latestFindings(d.findings, RECENT_FINDINGS), [d.findings]);
  const assets = React.useMemo(
    () =>
      Object.entries(d.assetCounts)
        .filter(([, n]) => n > 0)
        .sort(([, a], [, b]) => b - a),
    [d.assetCounts],
  );
  const assetTotal = assets.reduce((sum, [, n]) => sum + n, 0);
  const allTokens = selectBucket(tokenModel.buckets, "all");
  const activeModel = d.llmProfiles.find((p) => p.is_default)?.model;

  return (
    <div className="flex flex-1 flex-col gap-4 pb-8">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">{t("title")}</h1>
          <p className="text-sm text-muted-foreground">{t("subtitle")}</p>
        </div>
        <Button asChild>
          <Link href="/operator">
            <PlusIcon aria-hidden /> {t("newMission")}
          </Link>
        </Button>
      </header>

      <AttentionBanner
        pendingApprovals={d.pending.length}
        isLlmMissing={d.stats !== null && !d.stats.llm_configured}
        isStale={d.isStale}
      />

      <KpiCards
        isLoading={d.isLoading}
        tasksByStatus={tasksByStatus}
        taskTotal={d.tasks.length}
        severity={severity}
        findingTotal={d.findings.length}
        topAssets={assets}
        assetTotal={assetTotal}
        tokenTotal={allTokens.input + allTokens.output}
        cacheHit={cacheHitPct(allTokens)}
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <TasksCard className="xl:col-span-2" tasks={recentTasks} isLoading={d.isLoading} />
        <ActivityCard activity={d.activity} isLoading={d.isLoading} />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <FindingsCard className="xl:col-span-2" findings={recentFindings} isLoading={d.isLoading} />
        <SystemCard
          isLlmConfigured={d.stats?.llm_configured}
          activeModel={activeModel}
          isCapturing={d.settings?.traffic_capture}
          pendingApprovals={d.pending.length}
          assets={assets}
        />
      </div>

      <TokenUsageCard
        model={tokenModel}
        tasks={d.tasks}
        convTokens={d.convTokens}
        usage={d.usage}
        profiles={d.llmProfiles}
      />
    </div>
  );
}
