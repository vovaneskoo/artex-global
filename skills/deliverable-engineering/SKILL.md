---
name: deliverable-engineering
description: Deliverable engineering lessons from engagement post-mortems - offline contract verification before declaring done, compact ASCII artifacts, append-only action logs, masking and permission audits, and surgical edits to frozen reports.
---
SCOPE: authorized engagements only (lab / CTF / explicitly authorized targets). Follow the mission ROE and scope allow-list at all times.

---

Lessons distilled from engagement post-mortems. Core theme: a deliverable is
done only when a LOCAL, offline check proves it matches its contract - never
declare completion from intention.

## Verify before declaring done

- Verify deliverables OFFLINE (local file reads, no network) against their
  written contract before declaring a task complete: structure (all sections
  present, no leftover placeholders), termination (the file ends with exactly
  the required final block and nothing after it), parseability (embedded JSON
  actually parses).
- Keep one small validation harness per deliverable contract and re-run it
  after EVERY edit; checking only at the end hides intermediate breakage.
- Evidence bundles: recompute hashes and sizes of captured response files and
  cross-check them against the recorded manifest; inventory the evidence
  directory and confirm every claim's source file exists.

## Compact, self-contained artifacts

- Condensed reports are ASCII-only, short, structured (verdict + attack
  surface + technology fingerprint per asset); back up the long draft before
  condensing so the provenance of the superseded version is preserved.
- A final deliverable is self-contained: metadata header (target, engagement
  type, authorization, date, budget), every section filled, every finding with
  its evidence pointer - no references to files the reader does not have.
- Pin the method constraints (read-only, budget) in a header block so the
  contract is visible to any verifier.

## Append-only action log

- One JSON object per line (JSON Lines) appended per action with a fixed field
  set (timestamp, host, action, result, artifact path) - trivially greppable
  and replayable; never rewrite history in the action log.

## Masking and permission audits

- Before closing, grep every log and artifact for RAW secrets (passwords, JWT
  `eyJ` prefixes, private key headers) - expect zero hits outside loot/ (600).
  Audit filesystem modes: directories 700, files 600.
- Remediate deviations surgically: mask the exact secret in place (keep JSON
  valid), fix the mode, re-baseline hashes, and re-run the audit until clean.

## Frozen reports and surgical edits

- Freezing means: capture before-state (hash, size, section count), back up,
  then minimal in-place edits only - never regenerate a frozen report from
  scratch.
- Replace exactly one section's body without touching other sections, heading
  lines, or trailing machine-readable blocks; re-synchronise mirror copies and
  verify byte-identity after the edit.
- When two working trees diverge (stale vs completed), reconcile explicitly:
  diff, keep the completed content, normalize machine-readable block shapes,
  and record which version won.

## JSON artifact discipline

- Write JSON artifacts atomically and validate after the write: parses, exact
  key set, UTF-8 without BOM, required fields non-empty. A strict contract
  catches silent truncation and partial writes.

## Budgeted sweep scripts

- Single-invocation recon sweep scripts enforce their own request cap with an
  incrementing counter (fixed probes first, then a bounded loop), write every
  response to a deterministic path, and print a one-line verdict - the sweep
  can never silently overrun its budget.

(distilled from deliverable finalization, verification and audit lessons)
