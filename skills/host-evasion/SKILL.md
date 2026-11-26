---
name: host-evasion
description: EDR, AMSI, and ETW bypasses, AV obfuscation and polymorphism, WAF and SQLi payload mutations, traffic masking, and anti-forensics like timestomping and selective log handling. Use on monitored hosts after a foothold.
---
SCOPE: authorized engagements only (lab / CTF / explicitly authorized targets). Follow the mission ROE and scope allow-list at all times.

Apply after every foothold on monitored hosts; header and traffic mutations follow this guidance, never ad-hoc changes.

---

## EDR/AV/WAF bypass and anti-forensics

## EDR (Windows)
- Direct syscalls (SysWhispers3-style), ntdll unhooking (map a clean copy over .text).
- AMSI bypass: patch AmsiScanBuffer (XOR first bytes) BEFORE any PowerShell execution.
- ETW patch: EtwEventWrite → ret.
- Sleep obfuscation (Ekko/Zilean-style): encrypt self in memory during sleep.
- Execute via BOFs (Beacon Object Files) and PowerShell in-memory (-enc, AMSI bypass first). Avoid binaries on disk.
- Injection: APC queue / callback execution / thread hijacking. NEVER classic CreateRemoteThread.
- PPL bypass for LSASS: driver-based (e.g., via vulnerable signed driver) or indirect handle access.

## AV
- Obfuscation at generation: random variable/function names, string encryption, multi-stage payloads.
- Polymorphism: every implant unique per host.
- Test against available signatures before deployment when possible.

## WAF / Network
- SQLi mutations: double URL encoding, unicode normalization, comment obfuscation (SE/**/LECT), chunked transfer encoding, case randomization.
- Traffic: domain fronting, DoH, beacon jitter, legitimate HTTP profile (headers, user-agent, timing).

## Anti-Forensics (after EVERY foothold)
- Timestomping: match implant/artifact timestamps to existing system files.
- Selective log clearing: only YOUR events. phantom0m-style (pause EventLog thread during ops). NEVER wipe entire logs — that is a detection signal itself.
- Cleanup: shell history, Prefetch, recent docs, dropper temp files.
- USN journal / $MFT: do NOT touch unless necessary (too noisy).
- Alternate: inject fake benign events to blend rather than delete.