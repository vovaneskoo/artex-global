package db

import (
	"context"
	"testing"
)

func TestRecordFindingDedupesSameClassAssetSummary(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()
	tk, err := d.CreateTask("去重测试", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)
	es := d.Exploration(tk.ExplorationID)
	a1, err := d.Assets().UpsertOtherService(UpsertOtherServiceReq{IP: "10.9.9.9", Port: 80, ServiceName: "http", TaskID: tk.ID})
	if err != nil {
		t.Fatal(err)
	}

	first, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, Worker: "w", VulnClass: "sqli", Severity: "high",
		Summary: "Unauthenticated SQL injection in GET /rest/products/search?q=", AssetIDs: []int64{a1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Deduped {
		t.Fatal("first finding must not be a duplicate")
	}
	if first.NodeID == 0 || first.FindingID == 0 {
		t.Fatal("first finding must be persisted")
	}

	// Same class, same asset, paraphrased summary → deduped onto the first.
	second, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, Worker: "w", VulnClass: "sqli", Severity: "high",
		Summary: "SQL injection (UNION) unauthenticated in /rest/products/search q param", AssetIDs: []int64{a1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !second.Deduped || second.FindingID != first.FindingID || second.NodeID != first.NodeID {
		t.Fatalf("expected dedupe onto %d/%d, got %+v", first.FindingID, first.NodeID, second)
	}

	// Different class on same asset → new finding.
	third, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, Worker: "w", VulnClass: "xss", Severity: "medium",
		Summary: "Reflected XSS in /rest/products/search?q=", AssetIDs: []int64{a1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if third.Deduped {
		t.Fatal("different vulnclass must not dedupe")
	}

	// Same class, same asset, genuinely different summary → new finding.
	fourth, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, Worker: "w", VulnClass: "sqli", Severity: "high",
		Summary: "Blind time-based SQL injection in /rest/user/login email field", AssetIDs: []int64{a1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fourth.Deduped {
		t.Fatal("different endpoint summary must not dedupe")
	}

	// Different asset, same class+summary → new finding.
	a2, err := d.Assets().UpsertOtherService(UpsertOtherServiceReq{IP: "10.9.9.10", Port: 80, ServiceName: "http", TaskID: tk.ID})
	if err != nil {
		t.Fatal(err)
	}
	fifth, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, Worker: "w", VulnClass: "sqli", Severity: "high",
		Summary: "Unauthenticated SQL injection in GET /rest/products/search?q=", AssetIDs: []int64{a2},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fifth.Deduped {
		t.Fatal("different asset must not dedupe")
	}
}

func TestRecordFindingNameFallback(t *testing.T) {
	d := notifyTestDB(t)
	tk, err := d.CreateTask("名字回退", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)
	es := d.Exploration(tk.ExplorationID)
	f, err := es.RecordFinding(context.Background(), RecordFindingInput{
		TaskID: tk.ID, Worker: "w", VulnClass: "open-redirect", Severity: "low", Summary: "s",
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.Deduped {
		t.Fatal("unexpected dedupe")
	}
	var name string
	if err := d.QueryRow(`SELECT name FROM findings WHERE id=$1`, f.FindingID).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "open-redirect" {
		t.Fatalf("name fallback = %q, want vulnclass", name)
	}
}
