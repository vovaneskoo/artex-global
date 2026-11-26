---
name: mission-distill
description: Self-improvement loop - at mission close, replay the evidence against the skills that were loaded, extract one reusable technique per working chain and one correction per dead end, and emit review-ready addendum notes into the distill queue. Use at the wrap-up phase of every full-assault-mission, right before the final report, and after any surprising hit or unexpected block.
---

SCOPE: authorized engagements only (lab / CTF / explicitly authorized targets). Follow the mission ROE and scope allow-list at all times.

A mission is worth two artifacts: the report for the client and the lesson for the next worker.

---

## What this is (and is not)

Distillation at close time, from OUR evidence only - no web research (that is
exploit-radar's job). It converts what actually happened into skill text, so the
platform gets better with each mission instead of re-deriving the same
knowledge. It is not a mission summary: the report already exists; this reads
it and writes *deltas*.

Trigger points: mandatory at wrap-up (before the report), and opportunistically
right after a hit or a block so the context is still live.

## a) Evidence replay (bounded)

1. Read `actions.log` and `work/chain.md`; list every confirmed node and every
   DEAD edge.
2. Pick at most **3** items: the top chain (highest payoff that reached an
   instance) and up to 2 dead ends that consumed real budget.
3. For each loaded skill touched by those items, ask one question: *did the
   skill predict this, or did the worker have to figure it out?* "Had to
   figure out" = candidate lesson.

## b) Lesson gate (what qualifies)

A lesson is emitted only if ALL hold, else it is dropped with a one-line why:

- Reproducible: the exact request/command is in `artifacts/`, not reconstructed
  from memory.
- Generic: applies to a product class or tool, not just this one hostname.
- Not already in the skill verbatim (grep the skill first; a duplicate is noise).
- Actionable: states a check, a request shape, a gate or a cleanup - not a
  verbosity like "be careful".
- Cost-aware: says how many requests it saves or costs.

Two lesson kinds, both wanted:

| kind | from | shape |
|---|---|---|
| technique | a `hit` edge | fingerprint + request shape + gate + cleanup |
| correction | a `dead` edge | "skill says X, reality was Y, do Z instead" |

Also emit an *unlock row* when a new primitive→unlock edge was proven - it
belongs in exploit-chaining, and the addendum says exactly where.

## c) Output contract (one file per lesson)

Write to the mission work dir, then queue:

`work/distill/<date>-<skill>-<slug>.md`

```
---
skill: <target skill name>
kind: technique|correction|unlock
evidence: <artifact path + one verbatim line>
cost: <requests saved / spent>
confidence: mission-proven|single-observation
---

## <skill> addendum - <date>

<3-8 lines, concrete: fingerprint, request shape, gate, pitfall, cleanup>

## Evidence
<artifact path(s)> / <the verbatim command or request line>
```

Then push the whole `work/distill/` into the platform distill queue for human
review (`<data-dir>/distill/queue`); the queue, not the live skill, is the
destination - a human merges. Mark `single-observation` on anything seen once so
the reviewer knows it is not yet a rule.

## d) Anti-patterns (checked before queueing)

- Do not emit if the item was already in the skill and the worker just ignored
  it - that is a routing/attention problem, note it in one line but do not
  duplicate text.
- No secrets in the note; mask per the canonical mask format.
- One lesson per file; never bundle three lessons into one note.
- Cap at 3 notes per mission - a 15-note dump gets rubber-stamped and ignored.

## Rule
Cap 3, evidence-backed, generic, non-duplicate - a lesson the reviewer cannot falsify in 30 seconds is a lesson not queued.
