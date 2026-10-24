package guard

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/intercept"
)

// fakeScopeSource stands in for the pg-backed source: unit tests never touch pg.
type fakeScopeSource struct {
	list  *ScopeAllowList
	err   error
	calls int
}

func (f *fakeScopeSource) TaskScope(int64) (*ScopeAllowList, error) {
	f.calls++
	return f.list, f.err
}

func parseNet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("bad test net %q: %v", cidr, err)
	}
	return n
}

// targets renders extracted targets as "host=ip|domain" for easy comparison.
func targets(ts []scopeTarget) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		kind := "domain"
		if t.isIP {
			kind = "ip"
		}
		out = append(out, t.host+"="+kind)
	}
	return out
}

// v1 extracts literals only: URL hosts, IPv4/IPv6 literals, bare host(:port).
// Plain commands and file-name-shaped tokens must NOT become targets — a false
// deny on `ls`/`cat` would break benign work harder than a missed host.
func TestExtractScopeTargets(t *testing.T) {
	for _, tc := range []struct {
		cmd  string
		want []string
	}{
		// required by the ask: URL literal, bare host via nc, clean commands
		{`curl http://1.2.3.4/`, []string{"1.2.3.4=ip"}},
		{`nc host.example.com 443`, []string{"host.example.com=domain"}},
		{`ls -la /tmp`, nil},
		{`echo hello && cd /var/log`, nil},
		// URL hosts with ports/paths/userinfo
		{`curl -k https://sub.acme.com:8443/path?a=1`, []string{"sub.acme.com=domain"}},
		{`wget https://evil.com/x`, []string{"evil.com=domain"}},
		{`curl http://user:pw@10.9.8.7/admin`, []string{"10.9.8.7=ip"}},
		// piped command: URL cut at the pipe, second host picked up by bare pass
		{`curl http://a.acme.io/|nc b.acme.io 4444`, []string{"a.acme.io=domain", "b.acme.io=domain"}},
		// IP literals
		{`nmap -p22 10.0.0.5`, []string{"10.0.0.5=ip"}},
		{`ping -c1 2001:db8::1`, []string{"2001:db8::1=ip"}},
		{`curl http://[::1]:8080/x`, []string{"::1=ip"}},
		{`nc 172.17.0.3 3000`, []string{"172.17.0.3=ip"}},
		{`python3 script.py 1.2.3 2>&1`, nil},   // 3 octets: not an IP
		{`python3 script.py 1.2.3.999`, nil},    // invalid octet
		{`sleep 12:34:56 && date`, nil},         // time-shaped, not v6
		{`ip link show aa:bb:cc:dd:ee:ff`, nil}, // MAC, not v6
		// bare hosts: with a port any label count counts, without ≥3 labels
		{`api.acme.co.kr:443 healthy`, []string{"api.acme.co.kr=domain"}},
		{`host api.acme.co.kr`, []string{"api.acme.co.kr=domain"}},
		// v1 honest limits, pinned: no scheme + <3 labels + no port = no target
		{`ping acme.com`, nil},
		// file-name-shaped tokens are not targets
		{`cat notes.md`, nil},
		{`tar -xzf loot.tar.gz -C /tmp`, nil},
		{`--hostname=host.example.com`, []string{"host.example.com=domain"}},
		// localhost / single-label names: not scope-checkable literals in v1
		{`curl http://localhost:8080/health`, nil},
		{`curl http://box:8080/`, nil},
		// bench 2026-10-24 false positives, pinned: SQL :: casts are not v6
		// addresses; dotted python module paths are not hostnames.
		{`SELECT current_user, inet_server_addr()::text, inet_server_port()::text`, nil},
		{`python3 -c "from cryptography.hazmat.primitives.ciphers import AES"`, nil},
		{`mods=['Crypto','cryptography','hashlib','Crypto.Cipher.AES']`, nil},
	} {
		got := targets(extractScopeTargets(tc.cmd))
		if len(got) != len(tc.want) {
			t.Errorf("extract(%q) = %v, want %v", tc.cmd, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("extract(%q) = %v, want %v", tc.cmd, got, tc.want)
				break
			}
		}
	}
}

// The verdict against a mocked allow-list: infra nets always allowed, listed
// nets/domains allowed (subdomains included), everything else denied.
func TestCheckScopeTargetsVerdict(t *testing.T) {
	list := &ScopeAllowList{
		Nets:    []*net.IPNet{parseNet(t, "192.0.2.0/24")},
		Domains: []string{"example.com"},
	}
	for _, tc := range []struct {
		host  string
		isIP  bool
		allow bool
	}{
		{"127.0.0.1", true, true},           // loopback: box infra
		{"172.17.0.3", true, true},          // docker bridge: private, always allowed
		{"10.1.2.3", true, true},            // RFC1918
		{"::1", true, true},                 // v6 loopback
		{"fd00::5", true, true},             // v6 ULA
		{"192.0.2.7", true, true},           // listed net
		{"8.8.8.8", true, false},            // out of scope
		{"203.0.113.9", true, false},        // out of scope
		{"example.com", false, true},        // listed domain
		{"sub.example.com", false, true},    // subdomain of listed
		{"deep.a.example.com", false, true}, // nested subdomain
		{"notexample.com", false, false},    // suffix is not a label boundary
		{"evil.com", false, false},          // out of scope
		{"localhost", false, true},          // box infra by name
	} {
		ok, denied := checkScopeTargets([]scopeTarget{{host: tc.host, isIP: tc.isIP}}, list)
		if ok != tc.allow {
			t.Errorf("check(%s) allow=%v, want %v (denied=%q)", tc.host, ok, tc.allow, denied)
		}
	}
}

// The env gate: ARTEX_STRICT_SCOPE off → never blocks (upstream compatibility);
// on → deny lands as a hook block with target+rule in the audit reason; no task
// context / no targets / load error policies behave as documented.
func TestStrictScopeEnvGateAndDeny(t *testing.T) {
	newGuard := func(src *fakeScopeSource) *Guard {
		g := New()
		g.SetScopeSource(src)
		return g
	}
	taskCtx := intercept.WithTaskContext(context.Background(), "7", "worker-1", nil)
	bash := func(cmd string) []byte {
		b, _ := json.Marshal(map[string]string{"command": cmd})
		return b
	}

	t.Run("env off does not block", func(t *testing.T) {
		t.Setenv(envStrictScope, "")
		src := &fakeScopeSource{}
		g := newGuard(src)
		blocked, _, _ := g.Hooks().PreToolUse(taskCtx, "Bash", bash(`curl http://8.8.8.8/`))
		if blocked {
			t.Fatal("strict scope must be inert with ARTEX_STRICT_SCOPE unset")
		}
		if src.calls != 0 {
			t.Fatal("source must not be queried while the feature is off")
		}
	})

	t.Run("env on denies out-of-scope target", func(t *testing.T) {
		t.Setenv(envStrictScope, "1")
		g := newGuard(&fakeScopeSource{list: &ScopeAllowList{}}) // empty scope
		blocked, msg, _ := g.Hooks().PreToolUse(taskCtx, "Bash", bash(`curl http://8.8.8.8/`))
		if !blocked {
			t.Fatal("8.8.8.8 with an empty allow-list must be blocked")
		}
		if !strings.Contains(msg, "8.8.8.8") || !strings.Contains(msg, "스코프") {
			t.Errorf("block message should carry the target and the scope reason, got %q", msg)
		}
		audit := g.Audit()
		last := audit[len(audit)-1]
		if last.Tool != "Bash" || last.Action != "block" || !strings.Contains(last.Reason, "8.8.8.8") {
			t.Errorf("audit should record tool+target on deny, got %+v", last)
		}
	})

	t.Run("env on allows in-scope and infra targets", func(t *testing.T) {
		t.Setenv(envStrictScope, "1")
		src := &fakeScopeSource{list: &ScopeAllowList{
			Nets:    []*net.IPNet{parseNet(t, "192.0.2.0/24")},
			Domains: []string{"acme.com"},
		}}
		g := newGuard(src)
		for _, cmd := range []string{
			`curl http://192.0.2.10/`, `curl https://sub.acme.com/`, `curl http://127.0.0.1:8080/`,
			`nc 172.17.0.3 3000`, `ls -la`,
		} {
			blocked, _, _ := g.Hooks().PreToolUse(taskCtx, "Bash", bash(cmd))
			if blocked {
				t.Errorf("in-scope/infra command must pass, got block for %q", cmd)
			}
		}
	})

	t.Run("no task context skips check", func(t *testing.T) {
		t.Setenv(envStrictScope, "1")
		src := &fakeScopeSource{}
		g := newGuard(src)
		blocked, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", bash(`curl http://8.8.8.8/`))
		if blocked {
			t.Fatal("chat/plain context has no task scope to enforce")
		}
		if src.calls != 0 {
			t.Fatal("source must not be queried without a task context")
		}
	})

	t.Run("no targets skips check", func(t *testing.T) {
		t.Setenv(envStrictScope, "1")
		src := &fakeScopeSource{}
		g := newGuard(src)
		blocked, _, _ := g.Hooks().PreToolUse(taskCtx, "Bash", bash(`ls -la /tmp`))
		if blocked {
			t.Fatal("a local-only command is not strict scope's subject")
		}
		if src.calls != 0 {
			t.Fatal("source must not be queried when no target was extracted")
		}
	})

	t.Run("load error fails closed", func(t *testing.T) {
		t.Setenv(envStrictScope, "1")
		g := newGuard(&fakeScopeSource{err: errors.New("pg down")})
		blocked, msg, _ := g.Hooks().PreToolUse(taskCtx, "Bash", bash(`curl http://8.8.8.8/`))
		if !blocked || !strings.Contains(msg, "fail-closed") {
			t.Fatalf("allow-list load failure must deny (fail-closed), got blocked=%v msg=%q", blocked, msg)
		}
	})

	t.Run("WebFetch url is checked", func(t *testing.T) {
		t.Setenv(envStrictScope, "1")
		g := newGuard(&fakeScopeSource{list: &ScopeAllowList{}})
		input, _ := json.Marshal(map[string]string{"url": "http://8.8.8.8/x"})
		blocked, _, _ := g.Hooks().PreToolUse(taskCtx, "WebFetch", input)
		if !blocked {
			t.Fatal("WebFetch to an out-of-scope host must be blocked")
		}
	})
}
