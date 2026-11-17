package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/selfupdate"
)

// F-05(server/update.go): when the build patch has disabled self-update
// (ARTEX_ENABLE_SELFUPDATE unset — the audit-patch default), the check endpoint
// must answer with a structured "disabled" flag instead of the generic error
// field. The generic field is what the frontend renders through the
// "can't connect to GitHub — set the global proxy" template (update-card
// connectError), which is exactly the wrong advice: the problem is the disabled
// build, not connectivity.

func TestUpdateCheckDisabledBuildStructured(t *testing.T) {
	// Force the disabled gate even if the host running the tests opted in.
	t.Setenv("ARTEX_ENABLE_SELFUPDATE", "")
	prev := relCache
	defer func() { relCache = prev }()
	relCache = newTestCache(func(context.Context, *http.Client) (*selfupdate.Release, error) {
		return nil, selfupdate.ErrDisabled
	})

	s := &Server{m: &Manager{}}
	req := httptest.NewRequest(http.MethodGet, "/api/update/check", nil)
	rec := httptest.NewRecorder()
	s.updateCheck(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if out["disabled"] != true {
		t.Errorf("disabled flag missing/false: %v", out)
	}
	if errVal, has := out["error"]; has {
		t.Errorf("disabled build must not surface as error (frontend renders it with proxy advice): %v", errVal)
	}
	reason, _ := out["reason"].(string)
	if !strings.Contains(reason, "disabled by build patch") {
		t.Errorf("reason must name the disabled build: %q", reason)
	}
	if strings.Contains(strings.ToLower(rec.Body.String()), "proxy") {
		t.Errorf("disabled-build response must not mention proxy: %s", rec.Body.String())
	}
}

// F-05: apply on a disabled build must be rejected as "service unavailable"
// naming the disabled build, not as a 502 gateway error blaming the network.
func TestUpdateApplyDisabledBuildRejected(t *testing.T) {
	t.Setenv("ARTEX_ENABLE_SELFUPDATE", "")
	prev := relCache
	defer func() { relCache = prev }()
	relCache = newTestCache(func(context.Context, *http.Client) (*selfupdate.Release, error) {
		return nil, selfupdate.ErrDisabled
	})

	s := &Server{m: &Manager{}}
	req := httptest.NewRequest(http.MethodPost, "/api/update/apply", nil)
	rec := httptest.NewRecorder()
	s.updateApply(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d (want 503), body %s", rec.Code, rec.Body.String())
	}
	msg := decodeErrorField(t, rec.Body.Bytes())
	if !strings.Contains(msg, "disabled by build patch") {
		t.Errorf("apply rejection must name the disabled build: %q", msg)
	}
	if strings.Contains(strings.ToLower(msg), "proxy") {
		t.Errorf("apply rejection must not advise a proxy: %q", msg)
	}
}
