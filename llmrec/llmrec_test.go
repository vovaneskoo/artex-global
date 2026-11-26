package llmrec

import (
	"errors"
	"context"
	"iter"
	"os"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
	"github.com/google/uuid"
)

type completeProvider struct{}

func (completeProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(func(llm.StreamEvent, error) bool) {}
}

func (completeProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{
		Role: llm.RoleAssistant,
		Content: []llm.ContentBlock{
			{Type: llm.BlockThinking, Thinking: "reasoning"},
			llm.TextBlock("answer"),
		},
	}, "stop", llm.Usage{InputTokens: 7, OutputTokens: 3}, nil
}

func TestTaskIDContextUsesExplicitRegistryID(t *testing.T) {
	ctx := WithTaskID(context.Background(), " 42 ")
	if got := TaskIDFrom(ctx); got != "42" {
		t.Fatalf("TaskIDFrom()=%q want 42", got)
	}
	if got := TaskIDFrom(WithTaskID(ctx, "   ")); got != "42" {
		t.Fatalf("blank task id should preserve parent context, got %q", got)
	}
	if got := TaskIDFrom(nil); got != "" {
		t.Fatalf("nil context returned %q", got)
	}
}

func TestParseSessionFallbackIsExplorationScoped(t *testing.T) {
	taskID, worker := parseSession("exp12-worker-i99")
	if taskID != "12" || worker != "worker" {
		t.Fatalf("parseSession()=(%q,%q)", taskID, worker)
	}
	if taskID, worker := parseSession("not-a-task"); taskID != "" || worker != "" {
		t.Fatalf("unexpected non-session parse: (%q,%q)", taskID, worker)
	}
}

func TestCompleteForwardsAtomicResponse(t *testing.T) {
	recorder := Wrap(completeProvider{}, nil, "model", "profile", "", "", func() bool { return false })
	msg, stopReason, usage, err := recorder.Complete(context.Background(), llm.CompletionRequest{})
	if err != nil {
		t.Fatalf("Complete() error: %v", err)
	}
	if got := msg.Text(); got != "answer" {
		t.Fatalf("Complete() text=%q want answer", got)
	}
	if stopReason != "stop" {
		t.Fatalf("Complete() stop reason=%q want stop", stopReason)
	}
	if usage.InputTokens != 7 || usage.OutputTokens != 3 {
		t.Fatalf("Complete() usage=%+v", usage)
	}
}

type meteredStreamProvider struct{ completeProvider }

func (meteredStreamProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		if !yield(llm.StreamEvent{Type: llm.SEMessageStart, Usage: llm.Usage{InputTokens: 23}}, nil) {
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SEMessageDelta, Usage: llm.Usage{OutputTokens: 5}}, nil) {
			return
		}
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

func TestSideUsageRecordedOnceOnConsumerCancellation(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("requires isolated ARTEX_PG_DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	// llm_usage 는 db.Open 의 기본 스키마에 들어 있지 않고 EnsureLLMUsageTable 로만
	// 만들어진다(운영에서는 server/manager.go 가 호출한다). 격리된 빈 데이터베이스에서
	// 이 테스트를 단독으로 돌릴 때 다른 패키지가 같은 데이터베이스에 테이블을 먼저
	// 만들어 주기를 기대하지 않도록, 여기서 직접 테이블 존재를 보장한다.
	if err := pg.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	for _, early := range []bool{false, true} {
		profile := "btw-metering-" + uuid.NewString()
		ctx, cancel := context.WithCancel(transcript.WithSessionID(t.Context(), "exp0-btw-test"))
		recorder := Wrap(meteredStreamProvider{}, pg, "fixture", profile, "", "", func() bool { return false })
		for event, err := range recorder.Stream(ctx, llm.CompletionRequest{}) {
			if err != nil {
				t.Fatal(err)
			}
			if early && event.Type == llm.SEMessageDelta {
				cancel()
				break // Consumer exits before the provider can return a cancellation event.
			}
		}
		cancel()
		var count, input, output int
		var worker, status string
		err = pg.QueryRow(`SELECT count(*),max(input_tokens),max(output_tokens),max(worker),max(status)
FROM llm_usage WHERE profile_name=$1`, profile).Scan(&count, &input, &output, &worker, &status)
		_, _ = pg.Exec(`DELETE FROM llm_usage WHERE profile_name=$1`, profile)
		if err != nil {
			t.Fatal(err)
		}
		wantStatus := "ok"
		if early {
			wantStatus = "error"
		}
		if count != 1 || input != 23 || output != 5 || worker != "btw" || status != wantStatus {
			t.Fatalf("early=%v: count=%d usage=%d/%d worker=%q status=%q", early, count, input, output, worker, status)
		}
	}
}

func TestClassifyError(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{nil, 0, ""},
		{errors.New("openai: status 402: Insufficient balance"), 402, "http_402"},
		{errors.New("openai: status 401: invalid api key"), 401, "http_401"},
		{errors.New("stream empty before message_start"), 0, "empty_stream"},
		{errors.New("dial tcp 127.0.0.1:9: connect: connection refused"), 0, "unreachable"},
		{errors.New("net/http: request canceled"), 0, "other"},
		{context.Canceled, 0, "canceled"},
		{context.DeadlineExceeded, 0, "deadline"},
		{errors.New("tls handshake timeout"), 0, "timeout"},
	}
	for _, c := range cases {
		status, code := classifyError(c.err)
		if status != c.status || code != c.code {
			t.Fatalf("classifyError(%v)=(%d,%q) want (%d,%q)", c.err, status, code, c.status, c.code)
		}
	}
}

type failingCompleteProvider struct{ err error }

func (p failingCompleteProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) { yield(llm.StreamEvent{}, p.err) }
}

func (p failingCompleteProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{}, "", llm.Usage{}, p.err
}

func TestFailedCallRecordsHTTPFingerprint(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("requires isolated ARTEX_PG_DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	if err := pg.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	profile := "btw-fail-" + uuid.NewString()
	recorder := Wrap(failingCompleteProvider{err: errors.New("relay: status 402: quota exceeded")},
		pg, "fixture", profile, "", "", func() bool { return false })
	_, _, _, callErr := recorder.Complete(context.Background(), llm.CompletionRequest{})
	if callErr == nil {
		t.Fatal("expected provider error")
	}
	var status string
	var httpStatus int
	var code *string
	err = pg.QueryRow(`SELECT status, http_status, error_code FROM llm_usage WHERE profile_name=$1`, profile).
		Scan(&status, &httpStatus, &code)
	_, _ = pg.Exec(`DELETE FROM llm_usage WHERE profile_name=$1`, profile)
	if err != nil {
		t.Fatal(err)
	}
	if status != "error" || httpStatus != 402 || code == nil || *code != "http_402" {
		t.Fatalf("row status=%q http=%d code=%v, want error/402/http_402", status, httpStatus, code)
	}
}
