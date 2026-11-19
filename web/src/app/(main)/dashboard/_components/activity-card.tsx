"use client";

import { ActivityIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Card } from "@/components/ui/card";
import type { Activity } from "@/lib/types";
import { cn } from "@/lib/utils";

import { PanelBody, PanelHeader, useRelativeTime } from "./shared";

const MAX_ROWS = 7;

function workerTone(worker: string): string {
  if (worker === "planner") return "bg-violet-500/10 text-violet-600 dark:text-violet-300";
  if (worker === "mainagent") return "bg-cyan-500/10 text-cyan-700 dark:text-cyan-300";
  return "bg-blue-500/10 text-blue-600 dark:text-blue-300";
}

/** A tool call reads best as the tool's name; everything else as its kind. */
function activityTitle(a: Activity): string {
  return a.kind === "tool_use" ? (a.tool ?? a.kind) : a.kind;
}

export interface ActivityCardProps {
  activity: readonly Activity[];
  isLoading: boolean;
  className?: string;
}

export function ActivityCard({ activity, isLoading, className }: ActivityCardProps) {
  const t = useTranslations("dashboard");
  const rel = useRelativeTime();
  const rows = activity
    .filter((a) => a.kind !== "usage")
    .sort((a, b) => b.seq - a.seq) // filter() already returned a copy
    .slice(0, MAX_ROWS);

  return (
    <Card className={className}>
      <PanelHeader icon={ActivityIcon} title={t("activityStream")} href="/function/tasks" />
      <PanelBody
        isLoading={isLoading}
        isEmpty={rows.length === 0}
        skeletonRows={4}
        skeletonClassName="h-9"
        empty={t("noActivity")}
      >
        <ul className="-mt-2 flex flex-col px-4">
          {rows.map((a) => (
            <li key={a.seq} className="flex items-start gap-3 border-b py-2.5 last:border-0">
              <span className={cn("mt-0.5 shrink-0 rounded px-1.5 py-0.5 font-mono text-[11px]", workerTone(a.worker))}>
                {a.worker}
              </span>
              <div className="min-w-0 flex-1">
                <div className={cn("text-sm font-medium", a.is_error && "text-red-600 dark:text-red-400")}>
                  {activityTitle(a)}
                </div>
                <div className="truncate text-xs text-muted-foreground" title={a.summary}>
                  {a.summary}
                </div>
              </div>
              <span className="shrink-0 text-xs text-muted-foreground tabular-nums">{rel(a.ts)}</span>
            </li>
          ))}
        </ul>
      </PanelBody>
    </Card>
  );
}
