"use client";

import type * as React from "react";

import Link from "next/link";

import { BugIcon, NetworkIcon, TargetIcon, ZapIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

import { fmtTokens, type SeverityCounts } from "../_lib/metrics";
import { SEVERITY_BAR, SEVERITY_ORDER } from "./shared";

interface KpiCardProps {
  href: string;
  icon: React.ElementType;
  label: string;
  value: React.ReactNode;
  isLoading: boolean;
  children?: React.ReactNode;
}

function KpiCard({ href, icon: Icon, label, value, isLoading, children }: KpiCardProps) {
  return (
    <Link
      href={href}
      className="group flex flex-col gap-3 rounded-xl bg-card p-4 ring-1 ring-foreground/10 transition-shadow hover:ring-foreground/25 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span className="flex items-center gap-1.5">
          <Icon className="size-3.5" aria-hidden />
          {label}
        </span>
      </div>
      {isLoading ? (
        <Skeleton className="h-8 w-20" />
      ) : (
        <div className="text-3xl font-semibold tracking-tight tabular-nums">{value}</div>
      )}
      <div className="min-h-5 text-xs text-muted-foreground">{!isLoading && children}</div>
    </Link>
  );
}

export interface KpiCardsProps {
  isLoading: boolean;
  tasksByStatus: Record<string, number>;
  taskTotal: number;
  severity: SeverityCounts;
  findingTotal: number;
  topAssets: readonly (readonly [string, number])[];
  assetTotal: number;
  tokenTotal: number;
  cacheHit: number;
}

export function KpiCards(p: KpiCardsProps) {
  const t = useTranslations("dashboard");
  const tStatus = useTranslations("status");
  const running = p.tasksByStatus.running ?? 0;
  const assetLabel = (type: string) => (t.has(`assetType.${type}`) ? t(`assetType.${type}`) : type);

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <KpiCard
        href="/function/tasks"
        icon={TargetIcon}
        label={t("activeTasks")}
        isLoading={p.isLoading}
        value={
          <>
            {running}
            <span className="ml-1 text-base font-normal text-muted-foreground">/ {p.taskTotal}</span>
          </>
        }
      >
        <span className="flex flex-wrap gap-x-3">
          {running > 0 && (
            <span className="text-blue-500">
              {t("statExplore")} {running}
            </span>
          )}
          {(p.tasksByStatus.paused ?? 0) > 0 && (
            <span className="text-amber-500">
              {t("statPaused")} {p.tasksByStatus.paused}
            </span>
          )}
          <span>
            {t("statDone")} {p.tasksByStatus.done ?? 0}
          </span>
        </span>
      </KpiCard>

      <KpiCard
        href="/function/findings"
        icon={BugIcon}
        label={t("confirmedFindings")}
        isLoading={p.isLoading}
        value={p.findingTotal}
      >
        <SeverityBar counts={p.severity} total={p.findingTotal} />
        <span className="mt-1.5 flex flex-wrap gap-x-3">
          {SEVERITY_ORDER.filter((s) => p.severity[s] > 0).map((s) => (
            <span key={s} className="flex items-center gap-1">
              <span className={cn("size-2 rounded-full", SEVERITY_BAR[s])} aria-hidden />
              {tStatus(`severity.${s}`)} {p.severity[s]}
            </span>
          ))}
        </span>
      </KpiCard>

      <KpiCard
        href="/function/assets"
        icon={NetworkIcon}
        label={t("assetNodes")}
        isLoading={p.isLoading}
        value={p.assetTotal}
      >
        <span className="line-clamp-1">
          {p.topAssets
            .slice(0, 3)
            .map(([type, n]) => `${assetLabel(type)} ${n}`)
            .join(" · ") || "—"}
        </span>
      </KpiCard>

      <KpiCard
        href="/function/llm-records"
        icon={ZapIcon}
        label={t("tokenUsage")}
        isLoading={p.isLoading}
        value={p.tokenTotal > 0 ? fmtTokens(p.tokenTotal) : "—"}
      >
        {p.tokenTotal > 0 && (
          <span>
            {t("cacheHitRate")} <span className="font-medium text-foreground tabular-nums">{p.cacheHit}%</span>
          </span>
        )}
      </KpiCard>
    </div>
  );
}

function SeverityBar({ counts, total }: { counts: SeverityCounts; total: number }) {
  if (total === 0) return <div className="h-1.5 rounded-full bg-muted" />;
  return (
    <div className="flex h-1.5 gap-0.5 overflow-hidden rounded-full" role="img" aria-hidden>
      {SEVERITY_ORDER.filter((s) => counts[s] > 0).map((s) => (
        <div key={s} className={SEVERITY_BAR[s]} style={{ width: `${(counts[s] / total) * 100}%` }} />
      ))}
    </div>
  );
}
