"use client";

import * as React from "react";

import { ChevronDownIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Skeleton } from "@/components/ui/skeleton";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { api } from "@/lib/api";

// Mission "power": preset budget modes plus an explicit skill whitelist for custom.
// Fully controlled — the selection lives in the parent state (value/onChange);
// kept internally are only the popover open flag and the lazily fetched skill
// names (names are LLM-facing keys, shown as-is and never translated).
export type PowerMode = "recon" | "standard" | "full" | "custom";

export interface PowerSelection {
  mode: PowerMode;
  minutes: number; // budget minutes, always >= 1, freely editable
  allowedSkills: string[]; // skill names; only meaningful for mode === "custom"
}

// Picking a preset resets the budget to that mode's default (see setMode below).
export const POWER_MODE_MINUTES: Record<Exclude<PowerMode, "custom">, number> = {
  recon: 15,
  standard: 30,
  full: 45,
};

export const DEFAULT_POWER_SELECTION: PowerSelection = {
  mode: "standard",
  minutes: POWER_MODE_MINUTES.standard,
  allowedSkills: [],
};

const POWER_MODES: PowerMode[] = ["recon", "standard", "full", "custom"];

export function PowerSelector({
  value,
  onChange,
  disabled = false,
}: {
  value: PowerSelection;
  onChange: (next: PowerSelection) => void;
  disabled?: boolean;
}) {
  const t = useTranslations("powerSelector");
  const minutesId = React.useId();
  const skillsListId = React.useId();
  const [skillsOpen, setSkillsOpen] = React.useState(false);
  // Lazy skill list: fetched on the first open of the custom picker. A load
  // failure is contained inside the popover (message + retry) and never
  // blocks the surrounding form.
  const [skills, setSkills] = React.useState<string[] | null>(null);
  const [skillsLoading, setSkillsLoading] = React.useState(false);
  const [skillsError, setSkillsError] = React.useState(false);
  const requestSeq = React.useRef(0);

  const loadSkills = React.useCallback(async () => {
    const seq = ++requestSeq.current;
    setSkillsLoading(true);
    setSkillsError(false);
    try {
      const rows = await api.skills();
      if (seq !== requestSeq.current) return;
      setSkills(rows.map((s) => s.name).sort((a, b) => a.localeCompare(b)));
    } catch {
      if (seq === requestSeq.current) setSkillsError(true);
    } finally {
      if (seq === requestSeq.current) setSkillsLoading(false);
    }
  }, []);

  React.useEffect(() => {
    if (skillsOpen && skills === null && !skillsLoading && !skillsError) void loadSkills();
  }, [skillsOpen, skills, skillsLoading, skillsError, loadSkills]);

  const setMode = (mode: PowerMode) => {
    if (mode === "custom") onChange({ ...value, mode });
    else onChange({ ...value, mode, minutes: POWER_MODE_MINUTES[mode] });
  };

  const setMinutes = (raw: string) => {
    // Cleared/invalid input collapses to the minimum instead of NaN/0.
    onChange({ ...value, minutes: Math.max(1, Math.floor(Number(raw) || 0)) });
  };

  const toggleSkill = (name: string, checked: boolean) => {
    const has = value.allowedSkills.includes(name);
    if (checked === has) return;
    const next = checked ? [...value.allowedSkills, name] : value.allowedSkills.filter((s) => s !== name);
    onChange({ ...value, allowedSkills: next });
  };

  const selectedCount = value.allowedSkills.length;

  const renderSkillsBody = () => {
    if (skillsError) {
      return (
        <div className="flex flex-col items-start gap-1.5 p-1">
          <p className="text-destructive text-xs">{t("skillsError")}</p>
          <Button type="button" variant="outline" size="xs" onClick={() => void loadSkills()}>
            {t("skillsRetry")}
          </Button>
        </div>
      );
    }
    if (skillsLoading) {
      return (
        <div className="flex flex-col gap-1.5 p-1">
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-4/5" />
          <Skeleton className="h-4 w-3/5" />
        </div>
      );
    }
    if (skills && skills.length === 0) {
      return <p className="px-1 py-1 text-muted-foreground text-xs">{t("skillsEmpty")}</p>;
    }
    return (
      <div className="flex flex-col gap-0.5">
        {(skills ?? []).map((name, i) => (
          <label
            key={name}
            htmlFor={`${skillsListId}-${i}`}
            className="flex cursor-pointer items-start gap-2 rounded px-1 py-0.5 text-sm hover:bg-muted/50"
          >
            <Checkbox
              id={`${skillsListId}-${i}`}
              checked={value.allowedSkills.includes(name)}
              onCheckedChange={(v) => toggleSkill(name, !!v)}
              className="mt-0.5"
            />
            <span className="min-w-0 break-all leading-snug">{name}</span>
          </label>
        ))}
      </div>
    );
  };

  return (
    <div className="grid gap-2">
      <Label>{t("label")}</Label>
      <ToggleGroup
        type="single"
        value={value.mode}
        onValueChange={(mode) => mode && setMode(mode as PowerMode)}
        variant="outline"
        size="sm"
        spacing={0}
        aria-label={t("modeAria")}
        disabled={disabled}
      >
        {POWER_MODES.map((mode) => (
          <ToggleGroupItem key={mode} value={mode}>
            {t(`mode.${mode}`)}
          </ToggleGroupItem>
        ))}
      </ToggleGroup>
      <div className="grid gap-2">
        <Label htmlFor={minutesId}>{t("minutesLabel")}</Label>
        <Input
          id={minutesId}
          type="number"
          min={1}
          className="w-24"
          value={value.minutes}
          onChange={(e) => setMinutes(e.target.value)}
          disabled={disabled}
        />
        <p className="text-muted-foreground text-xs">{t("minutesHint")}</p>
      </div>
      {value.mode === "custom" && (
        <div className="grid gap-2">
          <Label>{t("skillsLabel")}</Label>
          <Popover open={skillsOpen} onOpenChange={setSkillsOpen}>
            <PopoverTrigger asChild>
              <Button type="button" variant="outline" size="sm" className="w-fit" disabled={disabled}>
                {selectedCount > 0 ? t("skillsCount", { count: selectedCount }) : t("skillsTrigger")}
                <ChevronDownIcon data-icon="inline-end" />
              </Button>
            </PopoverTrigger>
            <PopoverContent align="start" className="max-h-72 w-72 overflow-auto p-2">
              <p className="px-1 pb-1 font-medium text-[11px] text-muted-foreground">{t("skillsLabel")}</p>
              {renderSkillsBody()}
            </PopoverContent>
          </Popover>
          <p className="text-muted-foreground text-xs">{t("skillsHint")}</p>
        </div>
      )}
    </div>
  );
}
