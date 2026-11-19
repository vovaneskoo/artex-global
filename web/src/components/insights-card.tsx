"use client";

import * as React from "react";

import { ArrowRightIcon, LightbulbIcon, RefreshCwIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { getDateLocale } from "@/i18n/datetime";
import { http } from "@/lib/api";
import type { Task } from "@/lib/types";

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
  const untestedSource = Array.isArray(body.untested) ? body.untested : covUntested;
  return {
    coverageEnabled: !!body.coverage?.enabled,
    coveragePct: typeof body.coverage?.pct === "number" ? body.coverage.pct : null,
    untested: Array.isArray(untestedSource) ? untestedSource : [],
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
  // Index of the suggestion whose mission launch is in flight (null = none).
  // While set, all launch buttons are disabled — one launch at a time.
  const [launchingIdx, setLaunchingIdx] = React.useState<number | null>(null);
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

  // Launch one suggestion as a follow-up mission: POST /api/tasks via http()
  // like the operator form (snake_case body, server normalizes the rest).
  // The card has no company_ids in its props (none sent — no extra lookup)
  // and no timeout (the server default 2h budget applies on its own).
  // While one launch is in flight, ALL buttons show disabled (the guard blocks
  // every click anyway — visible state must not promise what is blocked).
  // HTTP 401 is handled inside http() (token cleanup + /login redirect);
  // every other failure degrades to a toast, the card itself stays intact.
  const launchSuggestion = async (suggestion: string, idx: number) => {
    if (launchingIdx !== null) return; // guard against double-submit
    setLaunchingIdx(idx);
    try {
      const goal = `Follow-up миссия по задаче #${taskId}:\n${suggestion}`;
      // Array.from: slice by code points, never splitting a surrogate pair.
      const short = Array.from(suggestion).slice(0, 40).join("");
      const created = await http<Task>("/tasks", {
        method: "POST",
        body: JSON.stringify({
          name: `insight: ${short}`,
          description: "Запущена из подсказки инсайтов",
          goal,
          seed_first_intent: true,
        }),
      });
      toast.success(t("launched", { id: created.id }));
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setLaunchingIdx(null);
    }
  };

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
                  <span className={`${compact ? "text-lg" : "text-2xl"} font-semibold tabular-nums`}>
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
                  {insights.untested.slice(0, UNTESTED_CHIP_LIMIT).map((item) => (
                    <span key={item} className="break-all rounded bg-muted px-1.5 py-0.5">
                      {item}
                    </span>
                  ))}
                  {untestedRest > 0 ? (
                    <span className="px-1.5 py-0.5 text-muted-foreground">+{untestedRest}</span>
                  ) : null}
                </div>
              </div>
            ) : null}
            <div className="flex flex-col gap-1.5">
              <span className="text-muted-foreground text-xs">{t("suggestions")}</span>
              <ul className="ml-4 list-disc text-muted-foreground text-sm">
                {insights.suggestions.map((s, idx) => (
                  <li key={s} className="text-foreground">
                    {/* Inner flex keeps the list marker: display:flex on the li
                        itself would drop the disc. */}
                    <div className="flex items-start justify-between gap-2">
                      <span className="min-w-0 break-words">{s}</span>
                      <Button
                        variant="outline"
                        size={compact ? "icon-xs" : "xs"}
                        className="shrink-0"
                        onClick={() => void launchSuggestion(s, idx)}
                        disabled={launchingIdx !== null}
                        title={t("launch")}
                        aria-label={t("launch")}
                      >
                        {launchingIdx === idx ? <Spinner className="size-3" /> : <ArrowRightIcon />}
                        {compact
                          ? null // icon-only with title/aria-label — fits the sm card
                          : launchingIdx === idx
                            ? t("launching")
                            : t("launch")}
                      </Button>
                    </div>
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
