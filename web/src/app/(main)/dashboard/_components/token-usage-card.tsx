"use client";

import * as React from "react";

import { ZapIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from "recharts";

import { Card, CardContent } from "@/components/ui/card";
import { type ChartConfig, ChartContainer, ChartTooltip, ChartTooltipContent } from "@/components/ui/chart";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import type { ConvTokenSummary, LLMProfile, Task, UsageStats } from "@/lib/types";

import {
  cacheHitPct,
  type DailyPoint,
  dailyFromActivity,
  dailyFromLedger,
  fmtTokens,
  type ProfileFilter,
  selectBucket,
  type TokenBucket,
} from "../_lib/metrics";
import type { TokenModel } from "../_lib/use-token-model";
import { PanelHeader } from "./shared";

const RANGES = [7, 30, 90] as const;
type RangeDays = (typeof RANGES)[number];
const ALL = "all";

const COLORS = {
  input: "hsl(217 91% 60%)",
  cacheRead: "hsl(160 60% 45%)",
  output: "hsl(263 70% 60%)",
} as const;

export interface TokenUsageCardProps {
  model: TokenModel;
  tasks: readonly Task[];
  convTokens: readonly ConvTokenSummary[];
  usage: UsageStats | null;
  profiles: readonly LLMProfile[];
  className?: string;
}

export function TokenUsageCard({ model, tasks, convTokens, usage, profiles, className }: TokenUsageCardProps) {
  const t = useTranslations("dashboard");
  const [filter, setFilter] = React.useState<ProfileFilter>(ALL);
  const [days, setDays] = React.useState<RangeDays>(30);

  const chartConfig = React.useMemo(
    () =>
      ({
        input: { label: t("chartInput"), color: COLORS.input },
        output: { label: t("chartOutput"), color: COLORS.output },
        cacheRead: { label: t("chartCacheRead"), color: COLORS.cacheRead },
      }) satisfies ChartConfig,
    [t],
  );

  // Only profiles that actually spent tokens are worth filtering by.
  const profileOptions = profiles.filter((p) => model.buckets.has(Number(p.id)));
  const bucket = selectBucket(model.buckets, filter);

  const daily = React.useMemo<DailyPoint[]>(() => {
    const now = new Date();
    return model.source === "ledger"
      ? dailyFromLedger(usage, {
          days,
          filter,
          profileIdByName: model.profileIdByName,
          defaultProfileId: model.defaultProfileId,
          now,
        })
      : dailyFromActivity(tasks, convTokens, { days, filter, defaultProfileId: model.defaultProfileId, now });
  }, [model, usage, tasks, convTokens, days, filter]);
  const hasDaily = daily.some((d) => d.input + d.output > 0);

  const controls = (
    <div className="flex flex-wrap items-center gap-2">
      {profileOptions.length > 1 && (
        <Select value={String(filter)} onValueChange={(v) => setFilter(v === ALL ? ALL : Number(v))}>
          <SelectTrigger size="sm" className="max-w-48" aria-label={t("allProfiles")}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>{t("allProfiles")}</SelectItem>
            {profileOptions.map((p) => (
              <SelectItem key={p.id} value={String(Number(p.id))}>
                {p.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
      <ToggleGroup
        type="single"
        size="sm"
        variant="outline"
        spacing={0}
        aria-label={t("tokenConsumption")}
        value={String(days)}
        onValueChange={(v) => v && setDays(Number(v) as RangeDays)}
      >
        {RANGES.map((d) => (
          <ToggleGroupItem key={d} value={String(d)} className="px-2.5 text-xs">
            {t(`range${d}`)}
          </ToggleGroupItem>
        ))}
      </ToggleGroup>
    </div>
  );

  return (
    <Card className={className}>
      <PanelHeader icon={ZapIcon} title={t("tokenConsumption")} action={controls} />
      <CardContent className="grid grid-cols-1 gap-6 lg:grid-cols-[240px_1fr]">
        <TokenBreakdown bucket={bucket} />
        {hasDaily ? (
          <ChartContainer config={chartConfig} className="h-[220px] w-full">
            <BarChart data={daily} margin={{ top: 4, right: 4, bottom: 0, left: 0 }} maxBarSize={32}>
              <CartesianGrid vertical={false} />
              <XAxis
                dataKey="date"
                tickLine={false}
                axisLine={false}
                tick={{ fontSize: 11 }}
                tickMargin={6}
                minTickGap={24}
              />
              <YAxis
                tickFormatter={(v) => fmtTokens(Number(v))}
                tickLine={false}
                axisLine={false}
                tick={{ fontSize: 11 }}
                width={44}
              />
              <ChartTooltip
                cursor={{ fillOpacity: 0.06 }}
                content={
                  <ChartTooltipContent
                    indicator="dot"
                    formatter={(value, name) => (
                      <div className="flex w-full items-center justify-between gap-4">
                        <span>{chartConfig[name as keyof typeof chartConfig]?.label ?? String(name)}</span>
                        <span className="font-mono font-semibold tabular-nums">{fmtTokens(Number(value))}</span>
                      </div>
                    )}
                  />
                }
              />
              <Bar dataKey="input" stackId="1" fill="var(--color-input)" />
              <Bar dataKey="output" stackId="1" fill="var(--color-output)" />
              <Bar dataKey="cacheRead" stackId="1" fill="var(--color-cacheRead)" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ChartContainer>
        ) : (
          <div className="flex min-h-[220px] items-center justify-center rounded-lg border border-dashed text-sm text-muted-foreground">
            {t("noData")}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function TokenBreakdown({ bucket }: { bucket: TokenBucket }) {
  const t = useTranslations("dashboard");
  const total = bucket.input + bucket.output;
  // Input already includes cache reads; split into three non-overlapping parts that sum to the total.
  const parts = [
    { label: t("inputUncached"), value: bucket.input - bucket.cacheRead, color: COLORS.input },
    { label: t("cacheHit"), value: bucket.cacheRead, color: COLORS.cacheRead },
    { label: t("output"), value: bucket.output, color: COLORS.output },
  ];

  return (
    <div className="flex flex-col gap-4">
      <div>
        <div className="text-xs text-muted-foreground">{t("totalInOut")}</div>
        <div className="mt-1 text-3xl font-semibold tracking-tight tabular-nums">
          {total > 0 ? fmtTokens(total) : "—"}
        </div>
        <div className="mt-1 text-xs text-muted-foreground">
          {t("taskCount", { count: bucket.taskCount })} · {t("cacheHitRate")} {cacheHitPct(bucket)}%
        </div>
      </div>
      <div className="flex flex-col gap-3">
        {parts.map(({ label, value, color }) => (
          <div key={label}>
            <div className="mb-1 flex items-center justify-between text-xs">
              <span className="flex items-center gap-1.5 text-muted-foreground">
                <span className="size-2 rounded-sm" style={{ background: color }} aria-hidden />
                {label}
              </span>
              <span className="font-medium tabular-nums">{fmtTokens(value)}</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-muted">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{ width: `${total > 0 ? (value / total) * 100 : 0}%`, background: color }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
