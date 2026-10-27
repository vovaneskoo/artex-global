package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// createTask 的 skills_mode/allowed_skills 入口校验与回显回归测试。400 各例走
// server_localized_test.go 的 liveServer 直调 handler 方式(纯校验,不触 DB);
// custom 建任务回显走 core_test.go 的真实 mux 方式(需 postgres,无则跳过)。

func TestCreateTaskSkillsModeValidation(t *testing.T) {
	// 只过输入校验、在 DB 访问前就返回的服务器(空 Manager)。
	s := &Server{m: &Manager{tasks: map[string]*Task{"t1": {ID: "t1"}}}, engine: &Engine{}}
	over := make([]string, maxTaskAllowedSkills+1)
	for i := range over {
		over[i] = fmt.Sprintf("skill-%02d", i)
	}
	overBody, _ := json.Marshal(map[string]any{
		"goal": "g", "skills_mode": "custom", "allowed_skills": over,
	})
	cases := []struct {
		name string
		body string
		want string
	}{
		{"garbage-mode", `{"goal":"g","skills_mode":"turbo"}`, errCreateTaskSkillsModeInvalid},
		{"allowed-with-recon", `{"goal":"g","skills_mode":"recon","allowed_skills":["web-recon"]}`, errCreateTaskSkillsCustomOnly},
		{"allowed-with-inherit", `{"goal":"g","allowed_skills":["web-recon"]}`, errCreateTaskSkillsCustomOnly},
		{"too-many-skills", string(overBody), fmt.Sprintf(errCreateTaskSkillsLimit, maxTaskAllowedSkills)},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodPost, "/api/tasks", strings.NewReader(tc.body))
		rec := httptest.NewRecorder()
		s.createTask(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d body=%s", tc.name, rec.Code, rec.Body.String())
		}
		if got := decodeErrorField(t, rec.Body.Bytes()); got != tc.want {
			t.Fatalf("%s: error=%q want %q", tc.name, got, tc.want)
		}
	}
}

func TestCreateTaskSkillsModeCustomEcho(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	// 空白项剔除、trim、去重保序;未知名(nmap/http-fetch)保留 — 与 db 归一化一致。
	body, _ := json.Marshal(map[string]any{
		"description": "skills mode echo", "goal": "goal", "skills_mode": "custom",
		"allowed_skills": []string{" nmap ", "", "http-fetch", "nmap", "  "},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/tasks", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID            string   `json:"id"`
		SkillsMode    string   `json:"skills_mode"`
		AllowedSkills []string `json:"allowed_skills"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.SkillsMode != "custom" {
		t.Fatalf("unexpected echo: %+v", created)
	}
	if strings.Join(created.AllowedSkills, ",") != "nmap,http-fetch" {
		t.Fatalf("allowed_skills not normalized: %v", created.AllowedSkills)
	}
	id, _ := strconv.ParseInt(created.ID, 10, 64)
	t.Cleanup(func() { _ = m.pg.DeleteTask(id) })
}
