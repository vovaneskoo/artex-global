package db

import (
	"context"
	"strings"
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

func TestRecordFindingMergesSameTargetAngle(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()
	tk, err := d.CreateTask("同目标不同角度", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)
	es := d.Exploration(tk.ExplorationID)
	a, err := d.Assets().UpsertOtherService(UpsertOtherServiceReq{IP: "10.9.9.11", Port: 80, ServiceName: "http", TaskID: tk.ID})
	if err != nil {
		t.Fatal(err)
	}
	first, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, Worker: "w1", VulnClass: "information-disclosure", Severity: "medium",
		Summary: "Unauthenticated GET /rest/memories leaks User objects with MD5 hashes", Evidence: "curl ...", AssetIDs: []int64{a},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, Worker: "w2", VulnClass: "information-disclosure", Severity: "medium",
		Summary: "The /rest/memories endpoint publishes unsalted MD5 password hashes for every account", Evidence: "jq output", AssetIDs: []int64{a},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !second.Deduped || second.FindingID != first.FindingID {
		t.Fatalf("same-target angle should merge, got %+v", second)
	}
	var evidence string
	if err := d.QueryRow(`SELECT evidence FROM findings WHERE id=$1`, first.FindingID).Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(evidence, "curl ...") || !strings.Contains(evidence, "duplicate report by w2") || !strings.Contains(evidence, "jq output") {
		t.Fatalf("evidence trail not merged: %q", evidence)
	}
}

func TestRecordFindingKeepsDifferentEndpointsOnSameHost(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()
	tk, err := d.CreateTask("不同端点", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)
	es := d.Exploration(tk.ExplorationID)
	a, err := d.Assets().UpsertOtherService(UpsertOtherServiceReq{IP: "10.9.9.12", Port: 80, ServiceName: "http", TaskID: tk.ID})
	if err != nil {
		t.Fatal(err)
	}
	first, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, Worker: "w", VulnClass: "sqli", Severity: "high",
		Summary: "SQL injection in /rest/user/login email field", AssetIDs: []int64{a},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, Worker: "w", VulnClass: "sqli", Severity: "high",
		Summary: "UNION-based SQL injection in /rest/products/search q parameter", AssetIDs: []int64{a},
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Deduped || second.FindingID == first.FindingID {
		t.Fatalf("distinct endpoints must stay separate, got %+v", second)
	}
}

func TestRecordFindingCrossClassNeedsTwoSharedFacts(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()
	tk, err := d.CreateTask("跨类合并", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)
	es := d.Exploration(tk.ExplorationID)
	a, err := d.Assets().UpsertOtherService(UpsertOtherServiceReq{IP: "10.9.9.13", Port: 5432, ServiceName: "postgres", TaskID: tk.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, Worker: "w", VulnClass: "weak-credentials", Severity: "high",
		Summary: "PostgreSQL 16.15 at 10.9.9.13:5432 accepts superuser password `labpass123`", AssetIDs: []int64{a},
	}); err != nil {
		t.Fatal(err)
	}
	merged, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, Worker: "w", VulnClass: "excessive-privileges", Severity: "high",
		Summary: "PostgreSQL 16.15 superuser at 10.9.9.13:5432 grants OS command execution", AssetIDs: []int64{a},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !merged.Deduped {
		t.Fatal("two shared facts across classes should merge")
	}

	// Same path, different classes, no second shared fact → stay separate.
	b, err := d.Assets().UpsertOtherService(UpsertOtherServiceReq{IP: "10.9.9.14", Port: 80, ServiceName: "http", TaskID: tk.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, Worker: "w", VulnClass: "xss", Severity: "medium",
		Summary: "Reflected XSS in /rest/products/search q param", AssetIDs: []int64{b},
	}); err != nil {
		t.Fatal(err)
	}
	separate, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, Worker: "w", VulnClass: "sqli", Severity: "high",
		Summary: "UNION SQL injection in /rest/products/search q param", AssetIDs: []int64{b},
	})
	if err != nil {
		t.Fatal(err)
	}
	if separate.Deduped {
		t.Fatal("one shared path across classes must stay separate")
	}
}
