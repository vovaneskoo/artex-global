"use client";

import type * as React from "react";

import Link from "next/link";

import { ShieldCheckIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

import { PanelHeader } from "./shared";

const ASSET_COLORS: Record<string, string> = {
  root_domain: "bg-blue-500",
  ip: "bg-indigo-400",
  subdomain: "bg-violet-500",
  app: "bg-orange-400",
  endpoint: "bg-emerald-500",
  service: "bg-cyan-500",
};

type Tone = "ok" | "bad" | "neutral";

const TONE_DOT: Record<Tone, string> = {
  ok: "bg-emerald-500",
  bad: "bg-red-500",
  neutral: "bg-muted-foreground/40",
};

function StatusRow({ label, value, tone, href }: { label: string; value: React.ReactNode; tone: Tone; href: string }) {
  return (
    <Link
      href={href}
      className="-mx-2 flex items-center justify-between gap-3 rounded-md px-2 py-2 text-sm transition-colors hover:bg-muted/50"
    >
      <span className="text-muted-foreground">{label}</span>
      <span className="flex min-w-0 items-center gap-2 font-medium">
        <span className="truncate">{value}</span>
        <span className={cn("size-2 shrink-0 rounded-full", TONE_DOT[tone])} aria-hidden />
      </span>
    </Link>
  );
}

export interface SystemCardProps {
  isLlmConfigured: boolean | undefined;
  activeModel?: string;
  isCapturing: boolean | undefined;
  pendingApprovals: number;
  assets: readonly (readonly [string, number])[];
  className?: string;
}

export function SystemCard(p: SystemCardProps) {
  const t = useTranslations("dashboard");
  const assetMax = p.assets[0]?.[1] ?? 1;
  const assetLabel = (type: string) => (t.has(`assetType.${type}`) ? t(`assetType.${type}`) : type);

  return (
    <Card className={p.className}>
      <PanelHeader icon={ShieldCheckIcon} title={t("systemStatus")} />
      <CardContent className="flex flex-col gap-5">
        <div className="flex flex-col">
          <StatusRow
            href="/system/llm"
            label={p.activeModel ? t("activeModel") : t("llmConfig")}
            value={p.activeModel ?? (p.isLlmConfigured ? t("configured") : t("notConfigured"))}
            tone={p.isLlmConfigured === undefined ? "neutral" : p.isLlmConfigured ? "ok" : "bad"}
          />
          <StatusRow
            href="/function/traffic"
            label={t("trafficCapture")}
            value={p.isCapturing ? t("recording") : t("off")}
            tone={p.isCapturing ? "ok" : "neutral"}
          />
          <StatusRow
            href="/system/intercept/approvals"
            label={t("approvals")}
            value={p.pendingApprovals > 0 ? t("pendingApprovals", { count: p.pendingApprovals }) : t("none")}
            tone={p.pendingApprovals > 0 ? "bad" : "ok"}
          />
        </div>

        <div>
          <div className="mb-3 text-xs font-medium text-muted-foreground">{t("assetDistribution")}</div>
          {p.assets.length === 0 ? (
            <div className="text-sm text-muted-foreground">{t("noAssetData")}</div>
          ) : (
            <div className="flex flex-col gap-2">
              {p.assets.map(([type, count]) => (
                <div key={type} className="grid grid-cols-[7rem_1fr_2.5rem] items-center gap-2 text-xs">
                  <span className="truncate text-muted-foreground" title={assetLabel(type)}>
                    {assetLabel(type)}
                  </span>
                  <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                    <div
                      className={cn("h-full rounded-full", ASSET_COLORS[type] ?? "bg-slate-400")}
                      style={{ width: `${(count / assetMax) * 100}%` }}
                    />
                  </div>
                  <span className="text-right font-medium tabular-nums">{count}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
