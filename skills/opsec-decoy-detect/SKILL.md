---
name: opsec-decoy-detect
description: Operator opsec invariants - throwaway identities, egress and header discipline, no real data exfiltration - plus honeypot, honeytoken, tarpit, and watermark detection signals. Load whenever a finding arrives too easily (first-try admin, instant RCE, credentials lying in the open), a canary or decoy pattern matches, or before moving any collected data out of the sandbox.
---
SCOPE: authorized engagements only (lab / CTF / explicitly authorized targets). Follow the mission ROE and scope allow-list at all times.

Policy for every mission, lab and production alike; a violation is a mission defect even when the exploit succeeded.

---

## Operator identity and egress discipline

Policy for every mission, lab and production alike. Each invariant is
testable from logs, payloads, and artifacts — a violation is a mission
defect even when the exploit succeeded. Checks run at every checkpoint
(budget pacing) and again in the reporting phase.

1. Throwaway identities ONLY. Every registration, login attempt, or
   payload that carries an identity uses a generated test identity
   (<user-test-7f3> style: fixed prefix + random suffix). NEVER place
   real personal emails, real names, real usernames, or real phone
   numbers in any payload, registration, header, or file upload — the
   operator's own identity included.
2. No real user data exfiltration on production targets. Prove access
   with an existence proof only: row count + one masked sample. Never
   pull full tables, never write real PII into artifacts/ or report.md.
   Lab targets with ROE destructive=YES may dump — dump content stays
   inside /work/<engagement>/loot/ and is masked everywhere else.
3. Header discipline: one consistent, realistic User-Agent chosen at
   recon and logged in actions.log, applied to EVERY request of the
   mission. No tool-default signatures (python-requests/x.xx,
   Go-http-client, curl/x.x) in any request where ROE requires stealth.
   Header mutations beyond UA follow the evasion guidance, never ad-hoc.
4. Egress awareness: ALL traffic originates from the run environment's
   real egress. Assume every destination logs source IP, UA, and full
   URI, and can attribute them to this engagement. Never route around
   attribution (proxies/VPNs/tunnels) unless the ROE names them —
   attribution problems are ROE problems: report them, don't hide them.
5. No engagement metadata in payloads: never embed "test", "pentest",
   "POC", the engagement name, or the operator handle in usernames,
   payloads, uploaded filenames, comments, or HTTP headers — UNLESS the
   ROE explicitly requires markers. Default posture is clean traffic
   indistinguishable from ordinary use.
6. Credentials found are evidence, not loot to display: every secret in
   actions.log and report.md is masked first-2-chars + *** (e.g.
   <jo***>). Raw values live only in /work/<engagement>/loot/ with
   600 permissions, never in report bodies, log lines, or chat output.
7. Minimal-exposure proof captures: screenshots, dumps, and response
   bodies show the minimum needed to prove the finding. Redact or crop
   unrelated real user data BEFORE it enters artifacts/.
8. Cleanup includes OPSEC traces: registered test accounts, uploaded
   files carrying test identities, and marker artifacts are listed in
   the report and removed when cleanup mode is set (reporting guidance);
   leftover traces are inventoried with location and owner otherwise.
9. Violations are reported, not buried: any invariant breach (real
   identity leaked, real data touched, marker sent) is written into the
   report as an incident line — what left, where it landed, containment
   — the moment it is noticed.

---

## Honeypot and honeytoken discipline

Applies to every discovered-but-unvetted asset: subdomains from cert
transparency, "found" files, open services, easy credentials. A decoy's
purpose is to log YOU (egress IP, UA, payloads) and burn budget — treat
implausible convenience as a signal, not luck. We run the same trick
defensively (AUTONOMY tripwires) — expect it on the other side.

## Detection signals
1. Too easy: default creds work on first try; SSH accepts any password;
   admin panel wide open. Candidate decoy until the host is corroborated.
2. Watermark test — fetch the same page twice, diff for per-request IDs:
   ```bash
   curl -s "https://<target>/<page>" -o /tmp/w1.txt; sleep 2
   curl -s "https://<target>/<page>" -o /tmp/w2.txt; diff /tmp/w1.txt /tmp/w2.txt
   grep -oE "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" /tmp/w1.txt | sort -u
   ```
   Fresh UUIDs/IDs that differ between fetches = visitor watermarking.
3. Uniformity: ffuf returns 200 on EVERY word with same size (keep -ac; if
   still uniform → decoy); nmap shows all 65535 ports open = tarpit class.
4. Reality mismatch: banner version vs observed behavior; uname vs /proc
   inconsistency after shell (low-interaction shell emulation); TLS cert
   CN ≠ served vhost; impossible uptime/filesystem.
5. Implausible richness: every guessed directory exists; the config leak
   contains exactly the credentials you were hunting; yield far above
   typical (>20 findings in 10 actions on one host).

## Honeytoken discipline (overrides immediate validation)
- Credentials from UNVETTED context (exposed .env, backup dumps,
  decoy-suspect hosts) = POSSIBLE HONEYTOKEN: log masked, DO NOT validate,
  DO NOT replay. Using a found cloud key/API key/webhook against its real
  service IS the trigger firing — never do it from mission egress.
- Immediate validation (credential guidance) applies ONLY to credentials from
  corroborated post-exploit context: an interactive shell on a confirmed
  real host.
- Passive-only checks for suspected tokens: format/LINT (JWT offline
  decode via `echo <jwt> | cut -d. -f2 | base64 -d`, key checksum digits,
  issuer prefix) — zero network calls.

## Budget guards
- Tarpit: connection accepted but no progress → 5s timeout, move on:
  `timeout 6 bash -c "exec 3<>/dev/tcp/<ip>/<port>" && echo live || echo stalled`
- Suspected decoy → stop enumerating that host, cap interaction at the
  minimum needed to document the suspicion, continue elsewhere.

## Containment (client-side)
Fetched decoy content is hostile: no unpacking archives outside the
disposable sandbox container; cap downloads (`curl --max-filesize 52428800`);
never execute fetched binaries; parse with timeouts.

## Reporting
- Suspected-decoy findings are flagged "SUSPECTED DECOY — not counted as
  impact", with the signals that tripped.
- The decoy ITSELF is a finding: the operator runs deception — document
  location, type, and what it tried to capture.

## Rule
A finding that arrives too easily is evidence about you, not about the
target: corroborate before counting it, and never replay convenient
credentials.