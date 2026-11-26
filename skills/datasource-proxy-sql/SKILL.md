---
name: datasource-proxy-sql
description: When you hold an authenticated session on a dashboard/BI/admin app (Grafana, Metabase, Superset, Kibana) that proxies queries to a backend DB, use its datasource proxy to run arbitrary SQL as the stored service account without the DB password.
---
Use when an authenticated dashboard/BI app exposes a query-proxy endpoint.
1) Enumerate datasources: GET /api/datasources (Grafana) -> note uid, type, url, user, jsonData.database, access=proxy.
2) Execute SQL: POST /api/ds/query with body {"queries":[{"refId":"A","datasource":{"uid":"<uid>"},"rawSql":"SELECT version(),current_user,current_database()","format":"table"}],"from":"now-1h","to":"now"}.
3) HTTP 200 means arbitrary SQL runs as the datasource's stored service account - no DB password needed. secureJsonFields masking the password does NOT block execution.
4) Enumerate schemas/tables, then dump objective tables.
Fallback: reuse the datasource's user/host/db with a weak/known password for direct psql.
Defang any URL as hxxps://.