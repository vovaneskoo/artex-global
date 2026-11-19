package privacycheck_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/llmpool"
	"github.com/Autumn-27/norma/llm"
)

const syntheticAPIKey = "privacy-fallback-test-key"

type observedRequest struct {
	method string
	path   string
	host   string
	model  string
	apiKey string
}

type requestLog struct {
	mu       sync.Mutex
	requests []observedRequest
}

func (l *requestLog) add(r observedRequest) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.requests = append(l.requests, r)
}

func (l *requestLog) snapshot() []observedRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]observedRequest(nil), l.requests...)
}

func anthropicHandler(t *testing.T, log *requestLog, status int, response string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		var decoded struct {
			Model string `json:"model"`
		}
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Errorf("decode Anthropic request body: %v", err)
		}
		log.add(observedRequest{
			method: r.Method,
			path:   r.URL.Path,
			host:   r.URL.Host,
			model:  decoded.Model,
			apiKey: r.Header.Get("x-api-key"),
		})
		if status != http.StatusOK {
			http.Error(w, `{"error":{"message":"synthetic test response"}}`, status)
			return
		}
		w.Header().Set("content-type", "text/event-stream")
		_, _ = io.WriteString(w, response)
	}
}

func provider(t *testing.T, baseURL, model, proxy string) llm.Provider {
	t.Helper()
	p, err := (agent.Config{
		Format:  llm.FormatAnthropic,
		BaseURL: baseURL,
		APIKey:  syntheticAPIKey,
		Model:   model,
		Proxy:   proxy,
		// Avoid hidden SDK retries in these request-routing assertions. The pool
		// itself owns profile failover; no external provider is involved.
		Retry: agent.RetryConfig{ConnectAttempts: -1},
	}).NewProvider()
	if err != nil {
		t.Fatalf("NewProvider(%q): %v", model, err)
	}
	return p
}

func member(id int64, name, model string, rank int, p llm.Provider) *llmpool.Member {
	return &llmpool.Member{
		ID: id, Name: name, Model: model, Format: string(llm.FormatAnthropic),
		Rank: rank, Prov: p,
	}
}

func request() llm.CompletionRequest {
	return llm.CompletionRequest{
		Messages: []llm.Message{{
			Role:    "user",
			Content: []llm.ContentBlock{{Type: "text", Text: "local routing check"}},
		}},
		MaxTokens: 32,
	}
}

func anthropicSSE(text string) string {
	data, _ := json.Marshal(map[string]any{
		"type":  "content_block_delta",
		"index": 0,
		"delta": map[string]any{"type": "text_delta", "text": text},
	})
	stop, _ := json.Marshal(map[string]string{"type": "message_stop"})
	return "event: content_block_delta\ndata: " + string(data) + "\n\n" +
		"event: message_stop\ndata: " + string(stop) + "\n\n"
}

func drainText(t *testing.T, p llm.Provider) string {
	t.Helper()
	var text strings.Builder
	for ev, err := range p.Stream(context.Background(), request()) {
		if err != nil {
			t.Fatalf("stream: %v", err)
		}
		if ev.Type == llm.SETextDelta {
			text.WriteString(ev.Text)
		}
	}
	return text.String()
}

func assertSingleRequest(t *testing.T, got []observedRequest, model string) {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("requests=%d, want exactly one: %#v", len(got), got)
	}
	r := got[0]
	if r.method != http.MethodPost || r.path != "/v1/messages" {
		t.Errorf("request method/path=%s %q, want POST /v1/messages", r.method, r.path)
	}
	if r.model != model {
		t.Errorf("request model=%q, want %q", r.model, model)
	}
	if r.apiKey != syntheticAPIKey {
		t.Errorf("request x-api-key=%q, want the synthetic test key", r.apiKey)
	}
}

func TestLocalAnthropicFallbackRoutesPrimaryThenBackup(t *testing.T) {
	var primaryLog, backupLog requestLog
	primary := httptest.NewServer(anthropicHandler(t, &primaryLog, http.StatusPaymentRequired, ""))
	defer primary.Close()
	backup := httptest.NewServer(anthropicHandler(t, &backupLog, http.StatusOK, anthropicSSE("backup-marker")))
	defer backup.Close()

	pool := llmpool.New([]*llmpool.Member{
		member(101, "primary", "primary-test-model", llmpool.RankActive,
			provider(t, primary.URL, "primary-test-model", "")),
		member(102, "backup", "backup-test-model", 1,
			provider(t, backup.URL, "backup-test-model", "")),
	}, nil)

	if got := drainText(t, pool); got != "backup-marker" {
		t.Fatalf("stream text=%q, want backup marker", got)
	}
	assertSingleRequest(t, primaryLog.snapshot(), "primary-test-model")
	assertSingleRequest(t, backupLog.snapshot(), "backup-test-model")
}

func TestLocalAnthropicSuccessDoesNotTouchBackup(t *testing.T) {
	var primaryLog, backupLog requestLog
	primary := httptest.NewServer(anthropicHandler(t, &primaryLog, http.StatusOK, anthropicSSE("primary-marker")))
	defer primary.Close()
	backup := httptest.NewServer(anthropicHandler(t, &backupLog, http.StatusOK, anthropicSSE("backup-marker")))
	defer backup.Close()

	pool := llmpool.New([]*llmpool.Member{
		member(201, "primary", "primary-test-model", llmpool.RankActive,
			provider(t, primary.URL, "primary-test-model", "")),
		member(202, "backup", "backup-test-model", 1,
			provider(t, backup.URL, "backup-test-model", "")),
	}, nil)

	if got := drainText(t, pool); got != "primary-marker" {
		t.Fatalf("stream text=%q, want primary marker", got)
	}
	assertSingleRequest(t, primaryLog.snapshot(), "primary-test-model")
	if got := backupLog.snapshot(); len(got) != 0 {
		t.Fatalf("backup received requests after primary success: %#v", got)
	}
}

func TestLocalAnthropicProfileUsesExplicitHTTPProxy(t *testing.T) {
	var proxyLog requestLog
	proxy := httptest.NewServer(anthropicHandler(t, &proxyLog, http.StatusOK, anthropicSSE("proxy-marker")))
	defer proxy.Close()

	// This loopback destination is intentionally not served. With no configured
	// profile proxy the request fails locally; with Proxy set, only the local
	// httptest proxy receives the absolute-form request.
	const target = "http://127.0.0.1:9"
	pool := llmpool.New([]*llmpool.Member{
		member(301, "proxied", "proxy-test-model", llmpool.RankActive,
			provider(t, target, "proxy-test-model", proxy.URL)),
	}, nil)

	if got := drainText(t, pool); got != "proxy-marker" {
		t.Fatalf("stream text=%q, want proxy marker", got)
	}
	got := proxyLog.snapshot()
	assertSingleRequest(t, got, "proxy-test-model")
	if got[0].host != "127.0.0.1:9" {
		t.Errorf("proxy target host=%q, want 127.0.0.1:9", got[0].host)
	}
}
