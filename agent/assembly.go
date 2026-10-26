package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"runtime/debug"
	"strings"
	"unicode/utf8"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/llm"
)

// DeferredInfo carries the deferred-tools wiring an agent needs to build its
// Options: the MCP tool names whose schemas are withheld, the subset listed in the
// global system-prompt block (non-skill-gated), and the shared session unlock set.
// UnlockSkill unlocks a named skill's MCPs — hosts call it to rebuild the unlock set
// from history on a resumed session (design doc C2).
type DeferredInfo struct {
	FindingGuidance string            // derived from the final permitted tools, including DB overrides
	Deferred        []string          // all MCP tool names (schema withheld)
	GlobalNames     []string          // MCP names to list in the system-prompt block
	Unlock          *actool.UnlockSet // shared call-gate; nil when no MCP tools
	UnlockSkill     func(skillName string)
}

// ToolAugment, if set, returns the EXTRA tools an agent should see beyond its
// built-in base set — the agent's visible skills (packed into one Skill meta-tool)
// and visible MCP servers (expanded to mcp__server__tool). It also returns the
// DeferredInfo describing how those MCP tools are deferred/gated. The server wires
// it to the PG agent_visibility table. cleanup releases any spawned MCP clients.
//
// When nil, agents run with only their built-in tools — behavior is unchanged
// until a user assigns a skill/MCP to the agent in the UI.
var ToolAugment func(ctx context.Context, agentKey string) (extra []actool.CoreTool, def DeferredInfo, cleanup func())

// AugmentTools returns base plus the agent's visible skill/MCP tools, the
// DeferredInfo, and a cleanup func the caller must defer (closes MCP clients).
// Built-in base tools are kept as-is — never filtered (内置工具留代码层，不做可见性过滤).
func AugmentTools(ctx context.Context, agentKey string, base []actool.CoreTool) ([]actool.CoreTool, DeferredInfo, func()) {
	var (
		def     DeferredInfo
		cleanup = func() {}
		out     = base
	)
	if ToolAugment != nil {
		var extra []actool.CoreTool
		var cl func()
		extra, def, cl = ToolAugment(ctx, agentKey)
		if cl != nil {
			cleanup = cl
		}
		if len(extra) > 0 {
			out = append(append([]actool.CoreTool{}, base...), extra...)
		}
	}
	// DB tools table has the final say on the built-in tools: drop the ones this
	// agent isn't bound to (or that are disabled) and swap in overridden
	// descriptions/schemas + default injection. MCP/skill/host tools have no row
	// and pass through untouched, so deferred/unlock wiring stays consistent.
	if ToolResolve != nil {
		out = ToolResolve(ctx, agentKey, out)
	}
	out, def.FindingGuidance = findingWorkflowTools(agentKey, out)
	// Register lowercase/snake_case aliases for the CamelCase built-ins (Bash →
	// bash, WebFetch → web_fetch) and defer them, so a model that drifts to the
	// model-conventional spelling still hits the handler while the model keeps
	// seeing only the official names. See issue #19.
	out, def.Deferred = addToolAliases(out, def.Deferred)
	for i, t := range out {
		out[i] = guardPanic(t)
	}
	return out, def, cleanup
}

// guardPanic turns a panicking tool handler into an ordinary tool error. The
// harness runs each tool on its own goroutine, so a panic inside a handler can't
// be recovered by the caller that started the run — it takes the whole process
// down, and on restart the agent replays the same call and crashes again. Applied
// last, so it covers every tool the agent can reach: domain, SDK, MCP and skill.
func guardPanic(t actool.CoreTool) actool.CoreTool { return &guardedTool{CoreTool: t} }

type guardedTool struct{ actool.CoreTool }

func (g *guardedTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (res actool.Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[tools] %s panic: %v\n%s", g.Name(), r, debug.Stack())
			res, err = actool.Errorf(fmt.Sprintf("工具 %s 内部错误：%v（本次调用已失败，可换个参数或改用别的工具）", g.Name(), r)), nil
		}
	}()
	res, err = g.CoreTool.Call(ctx, in, tc)
	if err == nil {
		res = sanitizeToolResult(res)
	}
	return res, err
}

// SanitizeControlChars rewrites a string so it is safe to embed in an LLM
// message history: NUL bytes and C0/C1 control characters (except \t\n\r) are
// replaced by '�'. This choke point exists because provider APIs reject control
// characters outright — Anthropic-compatible gateways answer
// 400 "String must not contain null bytes" (messages[N].content) — and a single
// binary tool output (head of /dev/urandom, a PNG, a SQLite dump) would
// otherwise poison the whole session: the invalid bytes stay in the history and
// EVERY subsequent request of that intent fails. Invalid UTF-8 is also
// normalized (each bad byte becomes '�') for the same reason: it must survive
// JSON serialization into the request body.
//
// Replacement rather than stripping keeps offsets honest (a model quoting line
// numbers of its own earlier output is not silently misled) while removing the
// API-breaking bytes.
func SanitizeControlChars(s string) string {
	if s == "" {
		return s
	}
	clean := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0x00 || (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			clean = false
			break
		}
		// C1 controls (U+0080–U+009F) encode in UTF-8 as 0xC2 0x80–0x9F.
		if c == 0xc2 && i+1 < len(s) && s[i+1] >= 0x80 && s[i+1] <= 0x9f {
			clean = false
			break
		}
	}
	if clean && utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s { // range decodes runes; invalid bytes yield RuneError with size 1
		switch {
		case r == utf8.RuneError:
			// covers both a literal U+FFFD in the input and an undecodable byte:
			// neither is safe/meaningful to forward
			b.WriteRune('�')
		case r == 0x7f || (r < 0x20 && r != '\t' && r != '\n' && r != '\r'):
			// C0 controls (minus tab/LF/CR) and DEL
			b.WriteRune('�')
		case r >= 0x80 && r <= 0x9f:
			// C1 controls (U+0080–U+009F); JSON-legal but rejected by strict providers
			b.WriteRune('�')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sanitizeToolResult rewrites every text surface of a tool result — content
// blocks (recursively: a tool_result block nests its content) and any Extra
// messages the tool injects after its result — so no control character or
// invalid UTF-8 from a tool reaches the conversation history the harness
// appends and later replays to the provider. Non-text fields (tool_use ids,
// raw JSON inputs) are model-generated and already JSON-safe.
func sanitizeToolResult(res actool.Result) actool.Result {
	for i, blk := range res.Content {
		res.Content[i] = sanitizeContentBlock(blk)
	}
	for mi, msg := range res.Extra {
		for ci, blk := range msg.Content {
			msg.Content[ci] = sanitizeContentBlock(blk)
		}
		res.Extra[mi] = msg
	}
	return res
}

func sanitizeContentBlock(blk llm.ContentBlock) llm.ContentBlock {
	if blk.Text != "" {
		blk.Text = SanitizeControlChars(blk.Text)
	}
	if blk.Thinking != "" {
		blk.Thinking = SanitizeControlChars(blk.Thinking)
	}
	if len(blk.Content) > 0 {
		for i, nested := range blk.Content {
			blk.Content[i] = sanitizeContentBlock(nested)
		}
	}
	return blk
}
