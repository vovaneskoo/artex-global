---
name: email-verification-autonomy
description: Self-service email verification for account registration flows on AUTHORIZED targets - create a disposable mailbox via the mail.tm REST API, receive the verification message, extract the confirmation link/code, complete signup and login without any human. Use whenever a target's registration requires email confirmation and the operator's ROE permits disposable accounts.
---
SCOPE: authorized engagements only. Disposable identities ONLY (never real people's
addresses). On third-party targets use only when the operator's ROE explicitly allows
disposable-account registration; on operator-owned targets it is the default path.

## The flow (curl only, works from any shell)

Base URL: https://api.mail.tm (REST, JSON, bearer token). Pick a domain first -
available domains rotate:

1. GET /domains?page=1 -> choose one domain from hydra:member[].domain
2. POST /accounts  {"address":"pentest-<random>@<domain>","password":"<random-16>"} -> 201
   (409 = address taken, reroll; 429 = back off 5s, mail.tm rate-limits hard)
3. POST /token {"address":"<same>","password":"<same>"} -> {"token":"..."} (JWT, ~1 week)
4. Poll GET /messages (header "Authorization: Bearer <token>") every 5-10s for up to 10
   minutes; new mail appears in hydra:member[]
5. GET /messages/{id} -> body text contains the verification link (look for
   https://...token=... or /verify?... ) or a numeric code
6. Complete the target's verification (GET the link / POST the code), then log in on the
   target with the mailbox address + the password you chose THERE (keep target password
   separate from the mail.tm password)

## Discipline

- Save the mailbox address, both passwords and the verification URL into the intent
  workspace files (e.g. mail-account.txt) - the operator needs them for cleanup.
- One mailbox per target registration; do not reuse across targets.
- If the target rejects the domain ("disposable email not allowed") - report it as a
  finding (anti-abuse control working) and stop; do NOT try real-looking domains.
- If the verification email never arrives in 10 minutes - check spam-folder conventions,
  then report and continue without the account.