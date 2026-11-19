"use client";

import type * as React from "react";

import Link from "next/link";

import { CloudOffIcon, KeyRoundIcon, ShieldAlertIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

type Tone = "warning" | "danger" | "muted";

const TONE: Record<Tone, string> = {
  warning: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  danger: "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300",
  muted: "border-border bg-muted/40 text-muted-foreground",
};

interface NoticeProps {
  tone: Tone;
  icon: React.ElementType;
  text: string;
  action?: { href: string; label: string };
}

function Notice({ tone, icon: Icon, text, action }: NoticeProps) {
  return (
    <div role="status" className={cn("flex items-center gap-3 rounded-xl border px-4 py-3 text-sm", TONE[tone])}>
      <Icon className="size-4 shrink-0" aria-hidden />
      <span className="flex-1 font-medium">{text}</span>
      {action && (
        <Button asChild size="sm" variant="outline" className="bg-background">
          <Link href={action.href}>{action.label}</Link>
        </Button>
      )}
    </div>
  );
}

export interface AttentionBannerProps {
  pendingApprovals: number;
  isLlmMissing: boolean;
  isStale: boolean;
}

/** Things that need the operator now. Renders nothing when all is well. */
export function AttentionBanner({ pendingApprovals, isLlmMissing, isStale }: AttentionBannerProps) {
  const t = useTranslations("dashboard");
  if (pendingApprovals === 0 && !isLlmMissing && !isStale) return null;

  return (
    <div className="flex flex-col gap-2">
      {isStale && <Notice tone="muted" icon={CloudOffIcon} text={t("connectionLost")} />}
      {isLlmMissing && (
        <Notice
          tone="danger"
          icon={KeyRoundIcon}
          text={t("llmMissing")}
          action={{ href: "/system/llm", label: t("configure") }}
        />
      )}
      {pendingApprovals > 0 && (
        <Notice
          tone="warning"
          icon={ShieldAlertIcon}
          text={t("approvalsWaiting", { count: pendingApprovals })}
          action={{ href: "/system/intercept/approvals", label: t("review") }}
        />
      )}
    </div>
  );
}
