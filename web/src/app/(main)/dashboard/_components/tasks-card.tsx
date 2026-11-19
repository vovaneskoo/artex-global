"use client";

import Link from "next/link";

import { ClockIcon, PlusIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import type { Task } from "@/lib/types";

import { PanelBody, PanelHeader, useRelativeTime } from "./shared";

export interface TasksCardProps {
  tasks: readonly Task[];
  isLoading: boolean;
  className?: string;
}

export function TasksCard({ tasks, isLoading, className }: TasksCardProps) {
  const t = useTranslations("dashboard");
  const rel = useRelativeTime();

  return (
    <Card className={className}>
      <PanelHeader icon={ClockIcon} title={t("tasks")} href="/function/tasks" />
      <PanelBody
        isLoading={isLoading}
        isEmpty={tasks.length === 0}
        skeletonRows={3}
        skeletonClassName="h-10"
        empty={
          <>
            {t("noTasks")}
            <Button asChild size="sm">
              <Link href="/operator">
                <PlusIcon aria-hidden /> {t("newMission")}
              </Link>
            </Button>
          </>
        }
      >
        <div className="-mt-4 overflow-x-auto">
          <table className="w-full min-w-[560px] text-sm">
            <thead>
              <tr className="border-b text-left text-muted-foreground text-xs [&>th]:whitespace-nowrap">
                <th className="px-4 py-2.5 font-medium">{t("colTask")}</th>
                <th className="px-4 py-2.5 font-medium">{t("colStatus")}</th>
                <th className="px-4 py-2.5 font-medium">{t("colGoalProgress")}</th>
                <th className="px-4 py-2.5 text-right font-medium">{t("colLastActivity")}</th>
              </tr>
            </thead>
            <tbody>
              {tasks.map((task) => (
                <TaskRow key={task.id} task={task} lastActivity={rel(task.last_activity_unix ?? task.created_unix)} />
              ))}
            </tbody>
          </table>
        </div>
      </PanelBody>
    </Card>
  );
}

function TaskRow({ task, lastActivity }: { task: Task; lastActivity: string }) {
  const t = useTranslations("dashboard");
  const goalsMet = task.goals_met ?? 0;
  const goalsPct = task.goals_total ? Math.round((goalsMet / task.goals_total) * 100) : null;
  const inFlight = task.in_flight ?? 0;

  return (
    <tr className="border-b transition-colors last:border-0 hover:bg-muted/40">
      <td className="w-full max-w-0 px-4 py-3">
        <Link href={`/function/tasks/detail?id=${task.id}`} className="group block min-w-0">
          <span className="block truncate font-medium group-hover:underline" title={task.description}>
            {task.description}
          </span>
          <span className="font-mono text-xs text-muted-foreground">#{task.id}</span>
        </Link>
      </td>
      <td className="px-4 py-3 whitespace-nowrap">
        <StatusBadge domain="task" value={task.status} dot />
        {inFlight > 0 && (
          <span className="ml-2 text-xs text-muted-foreground tabular-nums" title={t("colInFlight")}>
            {t("inFlightCount", { count: inFlight })}
          </span>
        )}
      </td>
      <td className="px-4 py-3">
        {goalsPct === null ? (
          <span className="text-muted-foreground">—</span>
        ) : (
          <div className="flex items-center gap-2">
            <Progress value={goalsPct} className="h-1.5 w-16" aria-label={t("colGoalProgress")} />
            <span className="text-xs text-muted-foreground tabular-nums">
              {goalsMet}/{task.goals_total}
            </span>
          </div>
        )}
      </td>
      <td className="px-4 py-3 text-right text-xs whitespace-nowrap text-muted-foreground tabular-nums">
        {lastActivity}
      </td>
    </tr>
  );
}
