# Context economy (LLM token spend)

Every agent turn re-reads the whole context (system prompt, tool schemas, transcript).
Input is ~99% of the bill (`llm_usage`); output is noise. Discipline below is baked
into the worker prompt (`agent/worker.go` default + DB override) and reviewed here.

## Rules for workers

1. **One long script per turn.** Put the whole batch inside one script, let the
   script persist results to files, and close shell output with `| tail -n 20`,
   `| grep -c`, etc. Never `cat` whole files or paste large response bodies.
2. **Checkpoint facts for batches >2–3 minutes.** Before starting a long batch,
   `record_fact` a checkpoint (what the batch does, where results land). After the
   first partial output, record the newly learned facts immediately — do not wait
   for batch completion, or a crash/step exhaustion loses everything.
3. **Bad upstreams (packet loss / timeouts).** Retry inside the script (loop +
   counter), not by re-invoking the LLM per packet. The script prints a final
   success/failure tally.
4. **Reuse before re-running.** Check traffic (`traffic_search`) and assets
   (`list_assets`) first; read logs incrementally (`tail`).

## Rules for planners

- Split dictionary/stage work into intents of ≤5k combinations with a resume
  marker (completed cursor in the intent payload) so a wind-down never burns the
  whole corpus.
- Prefer one intent per short upstream; a lossy upstream (loss >5%) belongs in a
  batch script intent, not in a per-element LLM loop.

## Knobs

- `task_token_budget` (settings, tokens; 0 = off) — hard per-task ceiling, winds
  the task down with `budget_exhausted`.
- `llm_dead_window_minutes` / `llm_dead_min_failures` (settings) — early wind-down
  when every call in the window fails (`llm_dead`).
- Profile `context_window_k` — compaction threshold scales with it; production
  worker profiles run at 64.
- Agent `max_turns` / `run_seconds` — per-turn/per-run ceilings (worker: 80/720).
- `llm_usage` error rows carry `http_status` / `error_code` — slice dead-provider
  burn apart from legitimate zero-token calls.
