---
name: finding-quality-reporting
description: Quality gates for findings and reports - adversarial falsification, measured impact with denominators, canonical secret masking in reports and logs, and artifact-backed collection proofs. Use when confirming findings or writing any deliverable.
---
SCOPE: authorized engagements only (lab / CTF / explicitly authorized targets). Follow the mission ROE and scope allow-list at all times.

Zero confirmed findings is a valid outcome; fabricated or padded findings are a mission failure.

---

## Finding quality gates

Hard gates every finding passes before it enters a report. Quality bar over
quantity: zero confirmed findings is a valid outcome; fabricated or padded
findings are a mission failure.

1. Dedup before reporting: check existing findings for the same root cause,
   endpoint, or parameter first. Same defect = extend the evidence of the
   existing finding; only a distinct entry point/parameter/privilege earns
   its own entry. Duplicates burn reviewer trust.
2. Adversarial falsification before confirmation: argue the OPPOSITE case
   along five axes — reachability, preconditions, downstream controls,
   scope, simpler explanation. A confirmation survives only if every
   elimination attempt is evidence-backed at the same bar as the
   confirmation itself.
3. PoC standard: the proof must demonstrate the attacker goal end-to-end,
   not an error message that looks promising. Every finding carries a
   proof-basis label: executed-live | executed-lab | static-unexecuted.
4. Measured impact with denominator: "3 of 20 payloads returned rows",
   never "can dump the table". No denominator = no impact claim.
5. Deadline contract: check remaining step/time budget before starting any
   command; never start work that can outlive the budget; on the wrap-up
   signal land recorded facts first, then stop.
6. Low-impact oracles (error-based echoes, timing hints without payload
   effect) are not standalone findings — they are leads.
7. Bounded non-destructive testing: own objects first; non-owned targets
   touched only per ROE, count them, record the IDs touched.
8. Declaring a miss is a claim about everything searched: state what was
   covered, not just what was found.
9. DEAD discipline for exhausted vectors: mark each one explicitly as DEAD
   with the reason it failed; reject or falsify leads that do not survive
   verification and record why; keep the report internally consistent and end
   with one valid state block; preserve evidence artifacts for every existence
   or absence claim.
10. A clean perimeter (CDN, DNSSEC, strict security headers, SPF/DMARC reject)
   is a legitimate result, not a failure — report it as such and stop. If a
   vector yields no confirmed exploit after its budget, close it as DEAD and
   move on rather than escalating effort on a weak lead.

---

## Report structure and cleanup

## Report (mandatory final artifact)
1. Compromise map: hosts, privileges obtained, attack paths.
2. Timeline: timestamp | host | action | result | artifact — EVERY action.
3. Vectors used: successful AND failed (failed ones feed blue team detection engineering).
4. Credentials collected: masked (first 2 chars + ***), principal, where validated.
5. Persistence inventory: host, mechanism, location, cleanup status.
6. Prioritized remediation recommendations per finding.

## Cleanup
- If cleanup mode is set: remove implants, persistence, artifacts. Logs: selective clearing of own events ONLY.
- If not set: persistence remains, every mechanism documented.
- Verify cleanup per mechanism and state result in report.

---

## Canonical secret mask format

Use one canonical mask format for every secret everywhere.
Format: prefix up to the last dash + next 3 chars + *** + last 4 chars.

Example:
```
<prefix>-abc***wxyz
```

Apply the identical mask in reports, working notes, and logs.
Arbitrary or ad-hoc masks break deduplication: the same secret
splits into two distinct entries.

Raw secret value lives only in loot/ with mode 600.
Never place the raw value in notes, report, or logs.

## Rule
One mask format everywhere — prefix + 3 chars + *** + last 4 — raw value only in loot/ at 600.

---

## Mask secrets in internal logs too

Masking the final report is not enough; internal execution logs leak too.
Agent execution_state and task journals often store raw tool output verbatim.
A report can be clean while the journal holds raw tokens, passwords, or hashes.
Before closing, grep every log and artifact for raw secrets:
```
grep -rE '<secret1>|<secret2>|<hash>' <workdir> <logdir>
```
Expect zero hits outside the designated raw store (e.g. loot/ with 600 perms).
If raw values appear in journals, redact them or restrict access.
Treat the journal as in-scope for the same masking policy as the report.
## Rule: apply the masking policy to internal logs, not just the deliverable.

---

## Prove collections with their own artifact

Never let a collection claim rest on journal reconciliation alone.
A subtask that reports "N/N values collected" without a fresh network call is unproven.
Require the final collection query to produce its own artifact at collection time.
```
<query tool> ... > loot/<name>_<timestamp>.json
```
Record provenance: source endpoint, timestamp, HTTP status, row count.
Reconcile the artifact count against the expected count with an explicit check.
If the only evidence is a log line, re-run the query or mark the objective unverified.
A later local file check can rescue a claim, but it is not a substitute for a captured request.
## Rule: every collection objective must be backed by its own artifact, not by a journal entry.

## Honest-framing review (cai-extract 2026-10-27)

Before finalizing any report, run the anti-overclaim pass over your own prose:
- false: the claim is not supported by the captured evidence — delete or fix.
- overstated: severity/impact language exceeds what was demonstrated —
  downgrade to what the PoC actually showed.
- missing-limit: the claim lacks its boundaries (scope of the test, what was
  NOT checked, environment caveats) — add an honest-limits section.
Every report ends with "Honest limits" listing what was not covered.
