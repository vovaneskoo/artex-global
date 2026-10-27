"use client";

import * as React from "react";

import Link from "next/link";

import { ActivityIcon, ArrowUpRightIcon, BugIcon, RocketIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { DEFAULT_POWER_SELECTION, type PowerSelection, PowerSelector } from "@/components/power-selector";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Combobox,
  ComboboxChip,
  ComboboxChips,
  ComboboxChipsInput,
  ComboboxContent,
  ComboboxEmpty,
  ComboboxItem,
  ComboboxList,
  ComboboxValue,
} from "@/components/ui/combobox";
import { Label } from "@/components/ui/label";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import { api, http } from "@/lib/api";
import type { Company, Finding, Task } from "@/lib/types";

// Operator page — the minimal "one goal → one mission" launcher plus two live
// blocks (active missions / recent findings). Deliberately small: no filters,
// no pagination; everything else lives on the tasks/findings pages.

// Terminal task statuses (same set as PAUSABLE/ARCHIVABLE on the tasks page
// and db.IsTerminal on the backend): a mission stays "active" until one of these.
const TERMINAL_STATUSES = new Set<Task["status"]>(["done", "failed", "timeout"]);

const POLL_MS = 5000;

type Translator = ReturnType<typeof useTranslations>;

// Compact relative time ("2h"), wrapped by the caller into a localized suffix.
// Same shape as the dashboard helper.
function fmtRel(ts?: string | number): string | null {
  if (!ts) return null;
  const ms = Date.now() - (typeof ts === "number" ? ts * 1000 : Date.parse(ts as string));
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  return `${Math.floor(h / 24)}d`;
}

// ── company picker (pattern copied from tasks/page.tsx; not extracted into a
// shared component on purpose — it stays page-local there and here). Reuses the
// existing tasksPage.companyPicker.* message keys: IP/CIDR/ICP stay identifiers,
// domain/keyword labels come from the catalog. ────────────────────────────────

const COMPANY_SCOPE_LABELS: Record<string, string> = {
  ip: "IP",
  cidr: "CIDR",
  icp: "ICP",
};

function companyScopeLabel(t: Translator, kind: string): string {
  if (kind === "domain") return t("companyPicker.scopeDomain");
  if (kind === "keyword") return t("companyPicker.scopeKeyword");
  return COMPANY_SCOPE_LABELS[kind] ?? kind;
}

function companyScopeSummary(t: Translator, company: Company): string {
  const rows = company.scope ?? [];
  if (rows.length === 0) return t("companyPicker.scopeNone");
  const preview = rows.slice(0, 3).map((row) => {
    const value = row.raw || row.value || row.domain || row.net || "";
    return t("companyPicker.scopeEntry", { label: companyScopeLabel(t, row.kind), value });
  });
  const base = preview.join(" · ");
  if (rows.length > preview.length) {
    return `${base} · ${t("companyPicker.scopeMore", { count: rows.length - preview.length })}`;
  }
  return base;
}

function CompanyPicker({
  companies,
  value,
  onValueChange,
}: {
  companies: Company[];
  value: number[];
  onValueChange: (value: number[]) => void;
}) {
  const t = useTranslations("tasksPage");
  const companiesByID = React.useMemo(
    () => new Map(companies.map((company) => [String(company.id), company])),
    [companies],
  );
  const companyIDs = React.useMemo(() => companies.map((company) => String(company.id)), [companies]);
  const selectedIDs = React.useMemo(() => value.map(String), [value]);

  return (
    <Combobox
      items={companyIDs}
      itemToStringValue={(companyID) => {
        const company = companiesByID.get(companyID);
        return company ? `${company.name} ${companyScopeSummary(t, company)}` : companyID;
      }}
      multiple
      value={selectedIDs}
      onValueChange={(next) => onValueChange(next.map(Number).filter(Number.isFinite))}
    >
      <ComboboxChips>
        <ComboboxValue>
          {selectedIDs.map((companyID) => (
            <ComboboxChip key={companyID}>
              {companiesByID.get(companyID)?.name ?? t("companyPicker.fallback", { id: companyID })}
            </ComboboxChip>
          ))}
        </ComboboxValue>
        <ComboboxChipsInput id="mission-companies" placeholder={t("companyPicker.placeholder")} />
      </ComboboxChips>
      <ComboboxContent>
        <ComboboxEmpty>{t("companyPicker.empty")}</ComboboxEmpty>
        <ComboboxList>
          {(companyID) => {
            const company = companiesByID.get(companyID);
            return (
              <ComboboxItem key={companyID} value={companyID}>
                <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="min-w-0 flex-1 truncate font-medium">
                      {company?.name ?? t("companyPicker.fallback", { id: companyID })}
                    </span>
                    <span className="shrink-0 text-muted-foreground text-xs tabular-nums">
                      {t("companyPicker.assetCount", { count: company?.asset_count ?? 0 })}
                    </span>
                  </div>
                  {company && (
                    <span className="truncate text-muted-foreground text-xs" title={companyScopeSummary(t, company)}>
                      {companyScopeSummary(t, company)}
                    </span>
                  )}
                </div>
              </ComboboxItem>
            );
          }}
        </ComboboxList>
      </ComboboxContent>
    </Combobox>
  );
}

// ── page ─────────────────────────────────────────────────────────────────────

export default function OperatorPage() {
  const t = useTranslations("operatorPage");
  const rel = (ts?: string | number) => {
    const v = fmtRel(ts);
    return v === null ? "—" : t("timeAgo", { value: v });
  };

  // new-mission form
  const [goal, setGoal] = React.useState("");
  const [companyIDs, setCompanyIDs] = React.useState<number[]>([]);
  const [power, setPower] = React.useState<PowerSelection>(DEFAULT_POWER_SELECTION);
  const [companies, setCompanies] = React.useState<Company[]>([]);
  const [launching, setLaunching] = React.useState(false);
  // Bumped after a successful launch so the poll effect restarts and refetches
  // the active list immediately instead of waiting for the next 5s tick.
  const [reloadToken, setReloadToken] = React.useState(0);

  React.useEffect(() => {
    api
      .companies()
      .then(setCompanies)
      .catch(() => setCompanies([]));
  }, []);

  async function launchMission() {
    if (!goal.trim()) {
      toast.error(t("validateGoal"));
      return;
    }
    setLaunching(true);
    try {
      // Body follows the /tasks POST conventions of api.createTask (snake_case,
      // timeout in seconds) but goes through the exported http() directly: the
      // optional skills_mode/allowed_skills fields are being added to
      // api.createTask in parallel, and this page must not depend on that
      // landing. skills_mode mirrors the power mode (recon|standard|full|custom,
      // validated by db.normalizeTaskSkillsMode); allowed_skills only rides
      // along for custom — the backend ignores it otherwise. A missing/empty
      // description is normalized server-side, so the minimal body is safe.
      const body: Record<string, unknown> = {
        goal: goal.trim(),
        company_ids: companyIDs,
        timeout_seconds: Math.max(1, Math.floor(power.minutes)) * 60,
        skills_mode: power.mode,
        seed_first_intent: true,
      };
      if (power.mode === "custom") body.allowed_skills = power.allowedSkills;
      await http<Task>("/tasks", { method: "POST", body: JSON.stringify(body) });
      toast.success(t("createdToast"));
      setGoal("");
      setCompanyIDs([]);
      setPower(DEFAULT_POWER_SELECTION);
      setReloadToken((n) => n + 1);
    } catch (e) {
      toast.error(t("createFailed", { msg: (e as Error).message }));
    } finally {
      setLaunching(false);
    }
  }

  // Active missions + recent findings share one 5s poll (single render per tick)
  // with the dashboard's in-flight guard and signature dedup.
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [findings, setFindings] = React.useState<Finding[]>([]);

  // biome-ignore lint/correctness/useExhaustiveDependencies(reloadToken): intentional — a successful launch bumps reloadToken to restart this effect so both lists refetch immediately instead of waiting for the next tick; the token itself is not read inside.
  React.useEffect(() => {
    let alive = true;
    let loading = false; // in-flight guard: a new tick never starts while one flies
    let tasksSig = "";
    let findingsSig = "";
    const load = async () => {
      if (loading) return;
      loading = true;
      try {
        const [taskResp, findingRows] = await Promise.all([api.tasks(), api.findings()]);
        if (!alive) return;
        const nextTasksSig = JSON.stringify(taskResp.tasks);
        if (nextTasksSig !== tasksSig) {
          tasksSig = nextTasksSig;
          setTasks(taskResp.tasks);
        }
        const nextFindingsSig = JSON.stringify(findingRows);
        if (nextFindingsSig !== findingsSig) {
          findingsSig = nextFindingsSig;
          setFindings(findingRows);
        }
      } catch {
        /* transient errors — next poll retries */
      } finally {
        loading = false;
      }
    };
    void load();
    const timer = setInterval(load, POLL_MS);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [reloadToken]);

  const activeMissions = React.useMemo(
    () =>
      [...tasks]
        .filter((task) => !TERMINAL_STATUSES.has(task.status))
        .sort((a, b) => (b.last_activity_unix ?? b.created_unix ?? 0) - (a.last_activity_unix ?? a.created_unix ?? 0)),
    [tasks],
  );

  const recentFindings = React.useMemo(
    () => [...findings].sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts)).slice(0, 5),
    [findings],
  );

  return (
    <div className="mx-auto flex w-full max-w-4xl flex-col gap-4 p-4 md:p-6">
      {/* ── hero: new mission ── */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <RocketIcon className="size-4 text-muted-foreground" />
            {t("newMission")}
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-5">
          <div className="grid gap-2">
            <Label htmlFor="mission-goal">{t("goalLabel")}</Label>
            <Textarea
              id="mission-goal"
              className="min-h-24"
              placeholder={t("goalPlaceholder")}
              value={goal}
              onChange={(e) => setGoal(e.target.value)}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="mission-companies">{t("targetLabel")}</Label>
            <CompanyPicker companies={companies} value={companyIDs} onValueChange={setCompanyIDs} />
            <p className="text-muted-foreground text-xs">{t("targetHint")}</p>
          </div>
          <PowerSelector value={power} onChange={setPower} disabled={launching} />
          <div className="flex justify-end">
            <Button onClick={launchMission} disabled={launching}>
              {launching && <Spinner data-icon="inline-start" />}
              {launching ? t("launching") : t("launch")}
            </Button>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* ── active missions ── */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ActivityIcon className="size-4 text-muted-foreground" />
              {t("activeMissions")}
            </CardTitle>
            <CardAction>
              <Link
                href="/function/tasks"
                className="flex items-center gap-0.5 text-[10px] text-muted-foreground hover:text-foreground"
              >
                {t("allTasks")} <ArrowUpRightIcon className="size-3" />
              </Link>
            </CardAction>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="divide-y">
              {activeMissions.length === 0 ? (
                <div className="py-4 text-center text-muted-foreground text-xs">{t("noActiveMissions")}</div>
              ) : (
                activeMissions.map((task) => (
                  <Link
                    key={task.id}
                    href={`/function/tasks/detail?id=${encodeURIComponent(task.id)}`}
                    className="-mx-2 flex items-start gap-2 rounded px-2 py-2 transition-colors hover:bg-muted/30"
                  >
                    <StatusBadge
                      domain="task"
                      value={task.status}
                      dot
                      className="mt-0.5 shrink-0 px-1.5 py-0 text-[10px]"
                    />
                    <div className="min-w-0 flex-1">
                      <div className="truncate font-medium text-xs">
                        {task.name?.trim() || task.description || task.goal}
                      </div>
                      <div className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground">{task.id}</div>
                    </div>
                    <span className="shrink-0 text-[9px] text-muted-foreground tabular-nums">
                      {rel(task.last_activity_unix ?? task.created_unix)}
                    </span>
                  </Link>
                ))
              )}
            </div>
          </CardContent>
        </Card>

        {/* ── recent findings ── */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <BugIcon className="size-4 text-muted-foreground" />
              {t("recentFindings")}
            </CardTitle>
            <CardAction>
              <Link
                href="/function/findings"
                className="flex items-center gap-0.5 text-[10px] text-muted-foreground hover:text-foreground"
              >
                {t("allFindings")} <ArrowUpRightIcon className="size-3" />
              </Link>
            </CardAction>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="divide-y">
              {recentFindings.length === 0 ? (
                <div className="py-4 text-center text-muted-foreground text-xs">{t("noFindings")}</div>
              ) : (
                recentFindings.map((finding) => (
                  <div key={finding.id} className="flex items-start gap-2 py-2">
                    <StatusBadge
                      domain="severity"
                      value={finding.severity}
                      className="mt-0.5 shrink-0 px-1.5 py-0 text-[10px]"
                    />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="font-semibold text-[11px]">{finding.vulnclass}</span>
                        {finding.task_description && (
                          <span className="truncate text-[10px] text-muted-foreground">{finding.task_description}</span>
                        )}
                      </div>
                      <div className="mt-0.5 line-clamp-2 text-[10px] text-muted-foreground leading-snug">
                        {finding.summary}
                      </div>
                    </div>
                    <span className="shrink-0 text-[9px] text-muted-foreground tabular-nums">{rel(finding.ts)}</span>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
