---
name: target-vocab-recon
description: Target-derived wordlists and behavioral oracles - mine the target's own JS bundles, source maps, markup, brand and employee names to build a small semantic wordlist, then use response differentials (body size, header, status, timing, 422 schema) as oracles instead of blind payload spraying. Use instead of generic SecLists sweeps on any live web target, and when a scan returns nothing but the app is clearly custom.
---

SCOPE: authorized engagements only (lab / CTF / explicitly authorized targets). Follow the mission ROE and scope allow-list at all times.

200 words from the target beat 200000 words from a generic list - and every oracle probe you build from them is one request instead of a blind guess.

---

## Why (and when)

Generic wordlists are a signature: everyone sends the same 500k paths, so WAFs,
CDNs and honeypots know the shape. They are also wrong for the target - custom
apps hide routes named after their own domain vocabulary. This skill builds a
**tiny, target-specific** vocabulary first, then probes with **differentials**
(the app's own normal vs abnormal responses) instead of payload lists.

Run this whenever a live custom app is found and generic discovery returns thin
coverage (or before spending budget on one). It complements, never replaces,
the compact probe playbook in web-recon: web-recon maps the surface, this
sharpens it.

## a) Vocabulary mining (passive, all local after one fetch)

Sources, in order of yield - each is a plain `curl` + parse:

1. JS bundles: every `<script src>`, plus inline `<script>` bodies. Collect:
   route/path fragments (`/api/v2/...`, method names), object field names,
   feature flags, vendor SDK name, version comments.
2. Source maps: `//# sourceMappingURL=` → fetch `.map` → the whole app tree
   (route list, component names, sometimes backend paths) falls out.
3. Markup: `data-*` attrs, id/class vocabulary, meta generator/version,
   form field names, hidden inputs, option values.
4. Text corpus for credentials/params: brand name, product names, locales,
   employee names from About/Team/OSINT, e-mail local-parts.
5. Robots.txt, sitemap.xml, `/.well-known/*` (which exists is itself signal).

Tokenize into a deduped list: split on non-alphanumerics, keep lowercase words
2-24 chars, add permutations the app already showed (plural, `-api`, `_v2`,
`.json`, `.bak`). Cap at ~250 entries - beyond that the list stops being
"target-specific" and becomes noise. Persist as `work/vocab.txt`; also keep the
raw JS map in `work/artifacts/` as provenance.

Never harvest from `node_modules` blobs or minified token soup - filter tokens
that appear in the app's own routes/fields only.

## b) Probes from the vocabulary (semantic, not spray)

- `ffuf -w work/vocab.txt` with **`-ac` auto-calibration and `-rate ≤20`**;
  extension set limited to what the stack implies (php→.php/.bak, node→none,
  java→.jsp), not a 30-way brute.
- Param candidates: run `arjun -u <endpoint> -w work/vocab.txt` - params are
  the mined field names, not a generic param list.
- Route guesses for APIs: take the mined object names to the API base and let
  the status-code triage (api-assault) read them.
- Auth surface: mined names feed `/reset`, `/invite`, `/profile` guessing and
  the username-enumeration oracle below.

## c) Behavioral oracles (replace blind payloads)

For a chosen param/route, first record the **baseline** (3 samples: status,
length, headers, timing median), then a single **mutation**, and diff:

| mutation | confirmed when |
|---|---|
| append/remove one path segment | 200/403 vs calibrated 404 length |
| type flip (`"1"`→`1`, `[]`→`{}`) | 422 field-name echo or 500 stack (schema/type oracle) |
| quote / single tick / `%00` | error string or length jump (injection lead) |
| duplicate parameter | last-vs-first wins (mass assignment / HPP) |
| long-ish value (256/4096) | different code path, NOT truncated same-page (length parity proves filter) |
| case/trailing-dot/trailing-slash on the path | 200 or redirect (routing bypass) |
| `-w` timing median ±5x | blind injection candidate → route into web-assault |
| callable URL param (`url=`, `src=`, `callback=`) | OAST hit (`interactsh-client`) - try before any file-based SSRF |

One mutation per probe - never stack (a diff you cannot attribute is wasted
requests). Log every probe: `path | param | mutation | baseline vs got | hypothesis`.

## d) Hygiene

Keep the mined artifact under ~250 lines and say in the report that discovery
was target-derived (a selling point for the client, and reproducible). Delete
throwaway tokens after the mission. Production: HEAD/GET oracles only.

## Rule
Mine the target's own words, then let the app's baseline tell you what is abnormal - one calibrated diff beats a thousand blind payloads.
