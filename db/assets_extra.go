package db

import (
	"encoding/json"
)

// MergeExtra shallow-merges patch into the extra JSONB column of an asset
// (extra || patch: top-level keys in patch replace existing ones). Used by the
// enrich engine to write back async results (HTTP headers, CVE candidates)
// without rewriting the whole asset. Best-effort: a missing asset is not an
// error (the row may have been deleted between upsert and async write-back).
func (s *AssetStore) MergeExtra(assetID int64, patch map[string]any) error {
	if assetID <= 0 {
		return nil
	}
	if len(patch) == 0 {
		return nil
	}
	raw, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	const q = `UPDATE assets SET extra = extra || $2::jsonb, updated_at = now() WHERE id = $1`
	var res interface{ RowsAffected() (int64, error) }
	if s.tx != nil {
		res, err = s.tx.Exec(q, assetID, raw)
	} else {
		res, err = s.db.Exec(q, assetID, raw)
	}
	if err != nil {
		return err
	}
	_, _ = res.RowsAffected()
	return nil
}
