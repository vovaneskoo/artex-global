"use client";

import { BugIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { StatusBadge } from "@/components/status-badge";
import { Card } from "@/components/ui/card";
import type { Finding } from "@/lib/types";

import { PanelBody, PanelHeader, useRelativeTime } from "./shared";

export interface FindingsCardProps {
  findings: readonly Finding[];
  isLoading: boolean;
  className?: string;
}

export function FindingsCard({ findings, isLoading, className }: FindingsCardProps) {
  const t = useTranslations("dashboard");
  const rel = useRelativeTime();

  return (
    <Card className={className}>
      <PanelHeader icon={BugIcon} title={t("findings")} href="/function/findings" />
      <PanelBody
        isLoading={isLoading}
        isEmpty={findings.length === 0}
        skeletonRows={3}
        skeletonClassName="h-12"
        empty={t("noFindings")}
      >
        <ul className="-mt-2 flex flex-col px-4">
          {findings.map((f) => (
            <li key={f.id} className="flex items-start gap-3 border-b py-3 last:border-0">
              <StatusBadge domain="severity" value={f.severity} className="mt-0.5 w-24 shrink-0 justify-center" />
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium">{f.name || f.vulnclass}</div>
                <div className="line-clamp-1 text-xs text-muted-foreground" title={f.summary}>
                  {f.task_description ? `${f.task_description} — ` : ""}
                  {f.summary}
                </div>
              </div>
              <span className="shrink-0 text-xs text-muted-foreground tabular-nums">{rel(f.ts)}</span>
            </li>
          ))}
        </ul>
      </PanelBody>
    </Card>
  );
}
