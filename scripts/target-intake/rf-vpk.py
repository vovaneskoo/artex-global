#!/usr/bin/env python3
"""Convert the rf-vpk research JSON array into mission-ready target files.

Input : JSON array as produced from docs/target-research-rf-vpk.md
        (array can also be wrapped as {"items": [...]}).
Output: <out>/targets.txt        - hostnames, one per line, deduped
        <out>/goal.md            - goal text for the task (description/goal fields)
        <out>/scope.json         - [{kind, value}] for add_task_scope calls
        <out>/orgs.md            - org -> domain table for the report appendix

Usage: python3 rf-vpk.py research.json -o outdir [--max-orgs 40] [--all]
Default keeps only confidence confirmed|probable; --all includes unverified.
"""
import argparse
import json
import os
import re

DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def load(path):
    data = json.load(open(path))
    if isinstance(data, dict):
        data = data.get("items") or data.get("orgs") or []
    return data


def clean(host):
    h = (host or "").strip().lower()
    h = re.sub(r"^https?://", "", h).split("/")[0].split(":")[0]
    h = h.rstrip(".")
    return h if DOMAIN_RE.match(h) else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--max-orgs", type=int, default=40)
    ap.add_argument("--all", action="store_true")
    a = ap.parse_args()

    orgs = load(a.input)
    keep = {"confirmed", "probable"} if not a.all else {"confirmed", "probable", "unverified"}
    orgs = [o for o in orgs if (o.get("confidence") or "unverified") in keep]
    orgs = orgs[: a.max_orgs]
    if not orgs:
        raise SystemExit("nothing left after the confidence filter")

    os.makedirs(a.out, exist_ok=True)
    hosts, scope, rows = [], [], []
    for o in orgs:
        for d in o.get("domains") or []:
            d = clean(d)
            if d and d not in hosts:
                hosts.append(d)
                scope.append({"kind": "domain", "value": d})
        for s in o.get("published_subdomains") or []:
            h = clean(s.get("host") if isinstance(s, dict) else s)
            if h and h not in hosts:
                hosts.append(h)
                scope.append({"kind": "subdomain", "value": h})
        rows.append(f'| {o.get("id","")} | {o.get("name","")} | {o.get("parent","")} | '
                    f'{o.get("role","")} | {o.get("city","")} | '
                    f'{", ".join(o.get("domains") or [])} | {o.get("confidence","")} |')

    open(os.path.join(a.out, "targets.txt"), "w").write("\n".join(hosts) + "\n")
    open(os.path.join(a.out, "scope.json"), "w").write(json.dumps(scope, ensure_ascii=False, indent=2))
    open(os.path.join(a.out, "orgs.md"), "w").write(
        "| id | организация | холдинг | роль | город | домены | уверенность |\n"
        "|---|---|---|---|---|---|---|\n" + "\n".join(rows) + "\n")

    goal = [
        "Открытый реестр внешнего контура ВПК РФ, деск-ресёрч без атак.",
        f"Организаций: {len(orgs)}, хостов: {len(hosts)}.",
        "Инвентаризировать домены из targets.txt: подтвердить официальность,",
        "описать публичный контур (поддомены, MX, ASN, хостинг), отметить",
        "пробелы и спорное. Целевые сервисы не зондируются глубже заголовков.",
        "Результат: реестр + отчёт с уверенностью по каждому домену.",
    ]
    open(os.path.join(a.out, "goal.md"), "w").write("\n".join(goal) + "\n")
    print(f"orgs {len(orgs)} hosts {len(hosts)} -> {a.out}")


if __name__ == "__main__":
    main()
