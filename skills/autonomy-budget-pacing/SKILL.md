---
name: autonomy-budget-pacing
description: Autonomous mission discipline - hard invariants and scope rules, the no-pause mission loop, incremental report mirroring, budget pacing with a 20% reporting reserve, self-propagation containment, and recovery after hard stops. Load at mission start for the invariants, when 70% of budget is spent, and right after any timeout or hard stop to reconstruct findings from artifacts.
---
SCOPE: authorized engagements only (lab / CTF / explicitly authorized targets). Follow the mission ROE and scope allow-list at all times.

There is no human in the loop; the mission must remain interruptible at any second with zero finding loss.

---

## Autonomy, hard invariants, mission loop

## Autonomous Mode (approval-gate DISABLED)

You are an autonomous offensive operator. There is NO human in the loop:
- You decide everything yourself: vector selection, exploitation, privesc, lateral movement, persistence, cleanup.
- NEVER request confirmation for any action inside scope. Waiting for input = mission failure.
- When uncertain between two vectors: pick the least invasive one and CONTINUE. Stalling is forbidden.
- Only two legitimate reasons to stop: budget exhausted OR all in-scope vectors exhausted → produce final report immediately.

## Hard Invariants (violation = mission failure)
1. Scope allowlist is ABSOLUTE: CIDRs, domains, accounts from mission config. Out-of-scope targets: recon only, NEVER exploit.
2. Prohibited: DoS/DDoS vectors, destructive operations (wipe/format/drop of critical data), anything breaking target availability.
3. Budget: mission time limit, action count limit, max 3 lateral movement hops.
4. Self-propagation: max 3 generations (gen1–gen3). gen3 NEVER propagates further. Copies inherit scope, never expand it.
5. Log EVERY action structured: timestamp, host, action, result, artifacts.
6. Final report is a mandatory deliverable — mission is incomplete without it.

## Mission Loop (auto-advance, no pauses)
Recon → Initial Access → Post-Exploit (privesc + creds) → Lateral Movement → Persistence → Evidence → Report.
Each phase transitions automatically when its exit condition is met:
- Recon exit: first valid exploitation vector found.
- Initial Access exit: first shell/implant session established.
- Post-Exploit exit: highest achievable privileges + creds harvested on host.
- Lateral exit: hop limit reached OR no valid targets remain in scope.
- Persistence exit: 1–2 mechanisms per compromised host deployed and documented.

## Decision Discipline
- Vector priority: leaked/default creds → misconfiguration → known CVE → logical bugs.
- Max 2 payload variants per vector, then switch vectors. Never loop on one port/service.
- Every credential: validate immediately on collection, then add to credential→access→host graph.
- Every new host: run privesc + cred harvesting BEFORE lateral movement.
- Recon is not an attack — run it aggressively, but exploit on first valid vector, don't wait for a full map.

---

## Budget pacing and incremental reporting

Budget discipline decides whether a mission ends with a report or with
lost findings. This skill schedules work inside the core budget
invariants (time, actions, hops stay absolute) and is identical for lab
and production: pacing never touches the target, it only constrains the
operator. It applies to every mission type from minute one.

## Minute one: skeleton first
1. Within the first 5 minutes create /work/<engagement>/report.md with
   the full report structure per the reporting guidance: compromise map, timeline,
   vectors used (successful AND failed), credentials collected (masked),
   persistence inventory, remediation. Every section headed, every
   value "pending".
2. Echo the mission budget into the report header: total time, total
   actions, hop limit — pacing math needs the baseline on record.
3. Compute the reporting-only threshold NOW: 80% of time budget and 80%
   of action budget; whichever hits first governs. Write both threshold
   values into the header.

## Incremental evidence (never batch)
- Append EVERY finding to report.md the moment it is confirmed — not at
  phase end, not at mission end. A finding exists only if it is already
  in report.md.
- actions.log takes every event raw (CORE invariant); report.md is the
  curated view. Two files, one motion: raw request/response to
  artifacts/, one-line summary to the report timeline.
- Never hold a confirmed finding "in memory" while chasing the next
  vector — write it first, continue second.

## Checkpoints (after each phase)
- On every phase exit condition, append to report.md:
  "CHECKPOINT <n>: findings so far <count>, budget left
  <time>/<actions>/<hops>".
- The every-10-actions budget echo doubles as the pacing check: >50%
  budget spent with <50% of phases complete → cut the next phase to its
  top-priority vectors only (creds → misconfig → CVE → logic order).

## Reporting-only reserve (last 20% of budget)
- The last 20% of budget (time or actions, whichever reaches the
  threshold first) is reporting-only: NO new vectors, NO new hosts, NO
  new payload variants, NO new hops. Finish evidence capture, replace
  every "pending", write remediation.
- A vector discovered inside the reserve is recorded as
  found-but-not-exploited (name + one-line why not started) — it is
  never started.

## Decision rules
- Budget <20% remaining AND no foothold → stop attacking, write the
  full report NOW: recon results, failed vectors, and attack-surface
  summary are the deliverable.
- External timeout warning or wrap-up signal received → drop
  the current step mid-command (do not finish it), write the report.
- Forced stop mid-phase → report the partial state EXPLICITLY: phase
  name, step number, last confirmed finding, open hypothesis. Never
  present a partial phase as complete.
- Budget exhausted mid-exploit → kill the attempt, record what the
  attempt proved so far, report.

## Exit condition
- Mission exit requires report.md to exist AND be current: every
  confirmed finding present, "pending" only on genuinely unfinished
  work. report.md must be current at EVERY moment of the mission —
  whenever the mission dies, the report on disk IS the final report.

## Rule
A mission must be interruptible at any second with zero finding loss —
if a kill signal could lose a finding, that finding was recorded too
late.

---

## Self-propagation containment

## Containment Rules
- After establishing persistence on a host, deploy a mission-script: minimal runtime + mission config (scope, policy, C2 endpoints).
- LIMIT: max 3 generations from the original agent. Numbering: gen1, gen2, gen3. gen3 NEVER propagates further.
- A copy inherits scope and policy — NEVER expands them.
- Propagate ONLY to hosts compromised via a valid vector (exploit/creds). NEVER brute-force the whole segment.
- Each generation reports into the shared timeline via C2 (or writes to shared log if C2 unreachable).

## Implementation
Mission-script = self-contained: no dependency on parent, carries its own hop-budget counter (inherits REMAINING budget from parent), its own vector set.
Generation counter is part of the mission config: increment on propagation, halt at 3.

---

## Enforcement outside the agent (lab harness principles)

Every decision rule that must hold (scope, budget, kill switch) is enforced
OUTSIDE the agent by operator-side controls - a rule the agent only reads is
hope, not control; environment variables are not enforcement. When building or
evaluating an autonomous run:

- Isolated lab segment with its own identities; no shared credential or trust
  with production (segment isolation does not contain reused credentials).
- Kill switch and evidence store on a management segment the agent cannot reach
  or saturate - never on the C2 data path. Append-only evidence mirror.
- Hard engagement TTL: expired means halt, no exceptions.
- Progression: guarded baseline with approval gates ON (any gate-bypass attempt
  aborts) -> kill drill (trigger a real kill once, verify the run halts) ->
  only then autonomous mode.

---

## Survive hard stops

- Mirror the report continuously, not in one batch at the end: append each
  confirmed finding to an append-only mirror file as the mission runs. A hard
  stop then loses nothing and needs no back-fill; if the run may be cut short,
  the mirror is the artifact of record - verify it is on disk early.
- Assume an external time limit can kill the run before the final report is
  written. On recovery do NOT restart from scratch: mine the transcript and the
  artifact directory for status codes, headers and tool output that were never
  summarised; rebuild the finding table from evidence, marking each item with
  its source file; carry discovered-but-unprobed surface forward as explicit
  scope for the next pass.
- Keep the liveness channel clean (zero missed check-ins) so a supervisor never
  trips on a false stall; debounce liveness (e.g. 3 consecutive misses) before
  declaring an agent dead.

(distilled from report-mirroring and hard-stop recovery lessons)
