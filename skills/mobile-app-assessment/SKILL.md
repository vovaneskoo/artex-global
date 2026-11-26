---
name: mobile-app-assessment
description: Mobile APK analysis with jadx and apktool - manifest and network-config review, secrets and endpoint extraction, cross-version diffing, and lab-only dynamic interception with pinning bypass. Use when the target includes a mobile app.
---
SCOPE: authorized engagements only (lab / CTF / explicitly authorized targets). Follow the mission ROE and scope allow-list at all times.

Static-first; the APK already contains the API map, the secrets, and the auth scheme.

---

## Mobile APK analysis

Static-first: the APK already contains the API map, the secrets, and
the auth scheme. Decompile, sweep, diff versions — dynamic work is
optional depth, and everything below assumes lab/owned apps only.

## Scope gate
- Lab/owned apps ONLY: in-house builds, engagement-scoped apps, CTF
  challenges. Pull from an owned device: `adb shell pm path <pkg>`
  then `adb pull <apk-path> app.apk`, or from a store mirror of the
  OWN product. Third-party apps are out of scope.
- Hitting the app's OWN backend API on production: existence proof
  with throwaway identities only (<user-test-7f3> style), never
  real users' data (agent opsec).

## Tooling
- jadx: `apt install jadx`; headless `jadx -d out/ app.apk`;
  `jadx-gui app.apk` for interactive search.
- apktool (smali + resources): `apktool d app.apk -o apk-out/` —
  the readable AndroidManifest and res/xml live here.
- Diff across versions: `diff -ru <old>-out/ <new>-out/`.

## Static pass order
1. AndroidManifest (apktool output): exported components
   (`android:exported="true"` on activities/receivers/providers),
   `android:allowBackup="true"`, dangerous permissions — one
   finding line per component name.
2. Network security config res/xml/network_security_config.xml:
   cleartextTrafficPermitted? trust anchors? pin-set present?
   Pinning found → dynamic interception needs the lab bypass below.
3. Secrets sweep:
   `grep -rEi "(api[_-]?key|secret|token|password|Basic )" <outdir>/`
   — prioritize res/values/strings.xml, assets/, BuildConfig.
4. Endpoint extraction:
   `grep -roE "https?://[a-zA-Z0-9./_-]+" <outdir>/ | sort -u`
   — cluster the hits into API base candidates.
5. Registration credentials: mobile clients ship Basic-auth
   registration pairs — `Authorization:
   Basic <base64(<client-id>:<client-secret>)>`; find the literal,
   decode it, treat as a discovered credential (credential guidance).

## Version diff methodology
1. Obtain 2-3 versions of the OWN app (store mirrors keep history).
2. Decompile each: `jadx -d v<old>-out/ <app>-<old>.apk`, repeat
   per version.
3. `diff -ru v<old>-out/ v<new>-out/ | grep -Ei
   "^[+-].*(http|key|secret|token|auth|debug)"`
4. Read BOTH directions: old versions often retain debug endpoints
   and older auth still accepted server-side; new versions reveal
   fresh endpoints no one has mapped yet.

## Feeding forward
- Extracted endpoints + registration creds → API assault
  methodology: endpoint matrix first, payloads second.
- Production hits on the app's own API: existence proofs with
  throwaway identities only; full request matrices go to the
  lab/staging mirror when the ROE provides one.

## Dynamic depth (lab emulator ONLY)
- Interception: emulator apps via mitmproxy/burp at
  <proxy-host>:<proxy-port>, CA installed on the emulator image.
- Pinning bypass: `objection -g <pkg> explore` →
  `android sslpinning disable`, or `frida -U -f <pkg> -l <unpin.js>`.
  Optional depth — never required to close a finding.

## Evidence
- Manifest: `<component> | exported | <permission>` per finding.
- Secrets: file:line + masked value, first-2-chars + *** (e.g.
  <ab***>); raw values only in /work/<engagement>/loot/ (chmod 600).
- Diff deltas as unified-diff snippets into artifacts/; log line
  `<file> | <delta> | <hypothesis>` per interesting hunk.

## Rule
Decompile and diff before dynamic testing — the secrets and
endpoints are usually already in the APK.