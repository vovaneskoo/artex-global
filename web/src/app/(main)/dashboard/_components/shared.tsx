"use client";

import type * as React from "react";

import Link from "next/link";

import { ArrowRightIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { CardAction, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

import { fmtRel, type SeverityCounts } from "../_lib/metrics";

export const SEVERITY_ORDER: readonly (keyof SeverityCounts)[] = ["critical", "high", "medium", "low"];

export const SEVERITY_BAR: Record<keyof SeverityCounts, string> = {
  critical: "bg-rose-600",
  high: "bg-orange-500",
  medium: "bg-amber-400",
  low: "bg-slate-400",
};

/** Localized "5m ago", or an em dash when there is no timestamp. */
export function useRelativeTime(): (ts?: string | number) => string {
  const t = useTranslations("dashboard");
  return (ts) => {
    const v = fmtRel(ts);
    return v === null ? "—" : t("ago", { value: v });
  };
}

interface PanelHeaderProps {
  icon: React.ElementType;
  title: React.ReactNode;
  href?: string;
  action?: React.ReactNode;
}

/** Card header with an icon title and either a custom action or a "View all" link. */
export function PanelHeader({ icon: Icon, title, href, action }: PanelHeaderProps) {
  const t = useTranslations("dashboard");
  return (
    <CardHeader className="border-b">
      <CardTitle className="flex items-center gap-2 text-sm font-semibold">
        <Icon className="size-4 text-muted-foreground" aria-hidden />
        {title}
      </CardTitle>
      {(action ?? href) && (
        <CardAction className="self-center">
          {action ?? (
            <Link
              href={href as string}
              className="inline-flex items-center gap-1 rounded-md text-xs text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              {t("all")}
              <ArrowRightIcon className="size-3.5" aria-hidden />
            </Link>
          )}
        </CardAction>
      )}
    </CardHeader>
  );
}

export function EmptyState({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div
      className={cn("flex flex-col items-center justify-center gap-3 py-10 text-sm text-muted-foreground", className)}
    >
      {children}
    </div>
  );
}

interface PanelBodyProps {
  isLoading: boolean;
  isEmpty: boolean;
  empty: React.ReactNode;
  skeletonRows?: number;
  skeletonClassName?: string;
  children: React.ReactNode;
}

/** Loading skeleton → empty state → content, so every panel handles all three the same way. */
export function PanelBody({
  isLoading,
  isEmpty,
  empty,
  skeletonRows = 3,
  skeletonClassName = "h-10",
  children,
}: PanelBodyProps) {
  if (isLoading) {
    return (
      <div className="flex flex-col gap-3 px-4">
        {Array.from({ length: skeletonRows }, (_, i) => (
          <Skeleton key={i} className={cn("w-full", skeletonClassName)} />
        ))}
      </div>
    );
  }
  if (isEmpty) return <EmptyState>{empty}</EmptyState>;
  return <>{children}</>;
}
