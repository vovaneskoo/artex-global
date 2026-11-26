---
name: osint-cti
description: Passive OSINT and CTI methodology - company/infrastructure footprint, dorking and code-leak hunting, identity and social footprint, IOC enrichment (Pyramid of Pain, JA3/JARM), threat-actor profiling, darkweb monitoring, TLP-classified reporting. Use BEFORE attacking an unfamiliar target to build target intel, or when a mission asks for intelligence gathering rather than exploitation.
---
SCOPE: authorized engagements only. OSINT tools query THIRD-PARTY sources
(search engines, CT logs, whois, paste/code sites) - not the target. Each
intel source must be authorized by the operator in the mission scope (our
egress firewall only lets the listed target IPs through - request the intel
sources you need in the goal/scope before using them). Respect each source's
ToS and local law. Never fabricate evidence; label every unverifiable item.

## The OSINT track (area -> method -> ATT&CK TA0043)

1. Domain/network footprint: whois, dig/dnsrecon, subfinder/amass, CT logs
   (crt.sh) -> T1590, T1596.
2. Dorking: search operators (site:, filetype:, inurl:), gau/waybackurls for
   archived URLs -> T1593.002.
3. Code/leak hunting: GitHub/GitLab search for org names, keys, internal
   hostnames; paste sites -> T1593.003, T1596. Check .git exposure on target.
4. Victim-owned web recon: httpx probing, katana crawl (passive first) -> T1594.
5. Identity intel: theHarvester (emails/subdomains), sherlock/maigret
   (usernames across platforms), holehe (email->registered services) -> T1589.
6. Org intel: employee structure, job postings (tech stack leaks), filings,
   acquisitions -> T1591.
7. Closed/dark sources: telegram channels, paste dumps, paid breach data -
   manual, operator-authorized only -> T1597.
8. Media geo: reverse image search, EXIF via exiftool -> T1589/T1591.

Tradecraft note: sock-puppet persona management is OPSEC discipline
(ATT&CK T1585 Resource Development), NOT reconnaissance - do not mislabel.

## IOC enrichment (when analyzing indicators)

- Classify each IOC on the Pyramid of Pain: hash (trivial to change) ->
  IP -> domain -> network/host artifacts (JA3/JARM TLS fingerprints) ->
  tools -> TTPs (most durable). Prefer higher-level indicators in reports.
- Enrichment pipeline: extract -> dedupe -> defang -> enrich (whois/CT/pdns/
  VT-class services if authorized) -> score source reliability (Admiralty
  A-F/1-6: source grade x info grade) -> cluster into campaigns.
- JA3/JARM: fingerprint TLS clients/servers; useful for tracking C2 and
  infrastructure reuse even when IPs rotate.

## Threat-actor profiling (Diamond Model)

For every intrusion/finding cluster, complete the four vertices: Adversary,
Capability (TTPs/tools/malware), Infrastructure (domains/IPs/certs), Victim.
Pivot on any vertex to expand. Report actor profiles with confidence language
(low/medium/high) and cite the evidence for each attribution claim -
attribution without evidence is fabrication.

## Darkweb monitoring discipline

Manual, operator-authorized, burner identity only; never engage, only
observe; log collection method + timestamp for every artifact; treat every
downloaded file as hostile (analyze in isolation, never execute).

## Reporting

TLP classification on every report header (TLP:RED/AMBER/GREEN/CLEAR).
Structure: executive summary (business impact) -> campaign timeline ->
IOC table (defanged, with Pyramid-of-Pain level) -> TTP mapping (ATT&CK) ->
Diamond Model per actor -> gaps and confidence statement. All raw IOCs
defanged (hxxps://, 1.2.3[.]4) before they leave the workspace.