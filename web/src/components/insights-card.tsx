"use client";

import * as React from "react";

import { LightbulbIcon, RefreshCwIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { getDateLocale } from "@/i18n/datetime";
import { http } from "@/lib/api";

// Optional backend contract — GET /api/tasks/{id}/insights may not exist yet
// (404/500) or answer with {error: …}. The card degrades to a "not available"
// state with a manual refresh; every click re-GETs because the server caches
// insights for ~60s (polling would be pointless).
// Expected body:
//   coverage?:    { enabled?: boolean; pct?: number | null }  // pct = 0..1, like /tasks/{id}/coverage
//   untested?:    string[]                                    // also accepted under coverage
//   suggestions?: string[]                                    // empty ⇒ treated as unavailable
//   generated_at?: string                                     // RFC3339
//   error?:       string
interface TaskInsightsResponse {
  coverage?: { enabled?: boolean; pct?: number | null; untested?: string[] | null };
  untested?: string[] | null;
  suggestions?: string[] | null;
  generated_at?: string;
  error?: string;
}

interface TaskInsights {
  coverageEnabled: boolean;
  coveragePct: number | null; // 0..1 or null when not computed
  untested: string[];
  suggestions: string[];
  generatedAt: string | null;
}

function normalizeInsights(body: TaskInsightsResponse): TaskInsights {
  const covUntested = body.coverage?.untested;
  return {
    coverageEnabled: !!body.coverage?.enabled,
    coveragePct: typeof body.coverage?.pct === "number" ? body.coverage.pct : null,
    untested: Array.isArray(body.untested) ? body.untested : Array.isArray(covUntested) ? covUntested : [],
    suggestions: Array.isArray(body.suggestions)
      ? body.suggestions.filter((s) => typeof s === "string" && s.trim())
      : [],
    generatedAt: body.generated_at ?? null,
  };
}

// Keep the compact detail-page card from being flooded by a long untested list.
const UNTESTED_CHIP_LIMIT = 12;

export function InsightsCard({ taskId, compact = false }: { taskId: string; compact?: boolean }) {
  const t = useTranslations("insightsCard");
  const [insights, setInsights] = React.useState<TaskInsights | null>(null);
  const [unavailable, setUnavailable] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const requestSeq = React.useRef(0);

  const load = React.useCallback(async () => {
    const seq = ++requestSeq.current;
    setBusy(true);
    try {
      const body = await http<TaskInsightsResponse>(`/tasks/${encodeURIComponent(taskId)}/insights`);
      if (seq !== requestSeq.current) return;
      // A fetch error, an error in the body or empty suggestions all mean
      // "nothing to show yet" — same degraded state with a retry.
      if (body?.error || !Array.isArray(body?.suggestions) || body.suggestions.length === 0) {
        setInsights(null);
        setUnavailable(true);
        return;
      }
      setInsights(normalizeInsights(body));
      setUnavailable(false);
    } catch {
      if (seq !== requestSeq.current) return;
      setInsights(null);
      setUnavailable(true);
    } finally {
      if (seq === requestSeq.current) setBusy(false);
    }
  }, [taskId]);

  React.useEffect(() => {
    setInsights(null); // taskId change → skeleton, not stale content
    setUnavailable(false);
    void load();
    return () => {
      requestSeq.current++;
    };
  }, [load]);

  const coveragePct = insights?.coveragePct != null ? Math.round(insights.coveragePct * 100) : null;
  const generatedTs = insights?.generatedAt ? Date.parse(insights.generatedAt) : NaN;
  const untestedRest = insights ? Math.max(0, insights.untested.length - UNTESTED_CHIP_LIMIT) : 0;

  return (
    <Card size={compact ? "sm" : "default"}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <LightbulbIcon className="size-4 text-amber-500" /> {t("title")}
        </CardTitle>
        {insights ? (
          <CardAction>
            <Button
              variant="ghost"
              size="icon-sm"
              onClick={() => void load()}
              disabled={busy}
              title={t("refresh")}
              aria-label={t("refresh")}
            >
              {busy ? <Spinner className="size-3.5" /> : <RefreshCwIcon />}
            </Button>
          </CardAction>
        ) : null}
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {!insights && !unavailable ? (
          <div className="flex flex-col gap-2">
            <Skeleton className="h-5 w-2/3" />
            <Skeleton className="h-5 w-1/2" />
          </div>
        ) : null}
        {unavailable ? (
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-muted-foreground text-sm">{t("unavailable")}</span>
            <Button variant="outline" size="xs" onClick={() => void load()} disabled={busy}>
              {busy ? <Spinner data-icon="inline-start" className="size-3" /> : null}
              {t("refresh")}
            </Button>
          </div>
        ) : null}
        {insights ? (
          <>
            {insights.coverageEnabled ? (
              <div className="flex flex-col gap-1.5">
                <span className="text-muted-foreground text-xs">{t("coverage")}</span>
                <div className="flex items-center gap-3">
                  <span
                    className={`${compact ? "text-lg" : "text-2xl"} font-semibold tabular-nums`}
                  >
                    {coveragePct != null ? `${coveragePct}%` : "—"}
                  </span>
                  {coveragePct != null ? <Progress className="flex-1" value={coveragePct} /> : null}
                </div>
              </div>
            ) : null}
            {insights.untested.length > 0 ? (
              <div className="flex flex-col gap-1.5">
                <span className="text-muted-foreground text-xs">{t("untested")}</span>
                <div className="flex flex-wrap gap-1.5 text-xs">
                  {insights.untested.slice(0, UNTESTED_CHIP_LIMIT).map((item, i) => (
                    <span key={`${i}:${item}`} className="bg-muted break-all rounded px-1.5 py-0.5">
                      {item}
                    </span>
                  ))}
                  {untestedRest > 0 ? (
                    <span className="text-muted-foreground px-1.5 py-0.5">+{untestedRest}</span>
                  ) : null}
                </div>
              </div>
            ) : null}
            <div className="flex flex-col gap-1.5">
              <span className="text-muted-foreground text-xs">{t("suggestions")}</span>
              <ul className="text-muted-foreground ml-4 list-disc text-sm">
                {insights.suggestions.map((s, i) => (
                  <li key={i} className="text-foreground break-words">
                    {s}
                  </li>
                ))}
              </ul>
            </div>
            {!Number.isNaN(generatedTs) ? (
              <p className="text-muted-foreground text-xs">
                {t("generatedAt", { time: new Date(generatedTs).toLocaleString(getDateLocale()) })}
              </p>
            ) : null}
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}
