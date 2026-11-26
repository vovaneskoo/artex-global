---
name: engagement-workspace
description: Engagement workspace setup in the first minutes - directory tree and scope files, pre-flight tool and wordlist verification, and sandbox DNS and proxy diagnosis. Use at the start of any engagement before touching the target.
---
SCOPE: authorized engagements only (lab / CTF / explicitly authorized targets). Follow the mission ROE and scope allow-list at all times.

---

Set the workspace up in the first minutes of any engagement; a structured tree
plus a pre-flight check prevents most wasted actions later.

## Workspace layout (distilled from many engagements)

```
/work/<engagement>/
  scope.md        # in-scope CIDRs/domains/accounts, ROE flags, authorization reference
  report.md       # created at minute one with the FULL section skeleton, every value "pending"
  actions.log     # append-only, one structured line per action (ts | host | action | result | artifact)
  artifacts/      # raw request/response captures, deterministic file names
  loot/           # raw secrets ONLY, mode 600 (directories 700)
  tools-notes.md  # tool versions, wordlists, install gaps
```

Echo the engagement budget (time, action or request cap, hop limit if any)
into the report header at creation - pacing math needs the baseline on record.

## Pre-flight before any target traffic

- Tool check: for every tool the plan needs (curl, ffuf, gobuster, feroxbuster,
  whatweb, httpx, nmap, jq, ...) verify presence AND version in one batched
  command; record gaps in tools-notes.md instead of discovering them mid-run.
- Wordlist check: confirm wordlists exist at their paths (SecLists raft/api,
  dirb common/big) before the first scan; inventory once, note fallbacks.
- Output dirs: create artifacts/ and loot/ with correct modes (700/600) BEFORE
  the first write.
- Reachability: ONE non-intrusive request to the in-scope target (status +
  timing) to confirm egress and scope correctness before any scanning.

## Sandbox/container diagnosis (distilled lessons)

- DNS resolution failure from a sandboxed container: query a control hostname
  first; if controls fail too it is sandbox DNS/egress filtering, not the
  target. Separate NXDOMAIN (target genuinely gone) from resolver artifacts
  before drawing conclusions.
- Proxy environment variables often do NOT load in non-interactive shells:
  source or export them explicitly per session; after configuring a recording
  proxy, verify with one test request that it actually captures your traffic
  before relying on it.
- Missing tools: install with pip3 inside a venv when needed (e.g. wafw00f,
  JWT libraries); watch the console-script vs `python3 -m` invocation gotcha;
  re-verify pre-existing tools after installing anything new.

## Budget accounting pattern

If the engagement has an action or request cap, count every request through
one incrementing counter (a helper script or strict log discipline), store each
artifact under a deterministic collision-free path, and stop at the cap - the
cap is a hard invariant, not a suggestion.

(distilled from engagement bootstrap, pre-flight, toolchain and sandbox
diagnosis lessons)
