// Server-Sent Events client with short-lived URL tickets.
//
// EventSource cannot send an Authorization header, so the stream has to be
// authenticated through the URL. Putting the 7-day session JWT there (?token=)
// leaked a full credential into server logs, browser history and any proxy in
// between. Instead, each stream handshake mints a 10-minute ticket via
// POST /api/auth/sse-token (Bearer-authenticated, never in a URL) and only the
// ticket travels as ?ticket=. Native EventSource auto-reconnect reuses the same
// URL forever, so after a ticket expires reconnects would 401-loop; we close on
// error and reopen with a fresh ticket instead.
//
// Base URL selection mirrors the old sseUrl():
// - production (static export / Docker): the Go backend serves the UI and the
//   streams on the same origin, so a relative URL works behind reverse proxies.
// - dev (next dev): the Next.js /api rewrite buffers streamed responses, so we
//   connect straight to the Go backend on :8787 (CORS-allowlisted).
// - override either default with NEXT_PUBLIC_SSE_BASE ("" forces same-origin).
import { http } from "@/lib/api";

const RECONNECT_MS = 3000;

function sseBase(): string {
  return (
    process.env.NEXT_PUBLIC_SSE_BASE ??
    (process.env.NODE_ENV !== "production" && typeof window !== "undefined"
      ? `${window.location.protocol}//${window.location.hostname}:8787`
      : "")
  );
}

async function fetchTicket(): Promise<string | null> {
  try {
    const r = await http<{ token: string }>("/auth/sse-token", { method: "POST" });
    return r.token || null;
  } catch {
    return null; // stream opens unauthenticated and fails — reconnect will retry
  }
}

// appendTicket adds the ?ticket= param (extra ?/& aware). Exported for tests.
export function appendTicket(path: string, ticket: string | null): string {
  if (!ticket) return path;
  const sep = path.includes("?") ? "&" : "?";
  return `${path}${sep}ticket=${encodeURIComponent(ticket)}`;
}

export interface SseStreamHandlers {
  onOpen?: () => void;
  onMessage?: (ev: MessageEvent) => void;
  // Return false to stop the stream permanently (e.g. the update stream during
  // a server restart). Omit it (or return true) to keep auto-reconnecting with
  // a fresh ticket.
  onError?: () => boolean;
  // Attach named-event listeners (e.g. "snapshot"). Re-invoked on every
  // reconnect with the new EventSource instance.
  addEventListener?: (es: EventSource) => void;
}

export interface SseStream {
  close(): void;
}

export function openSseStream(path: string, h: SseStreamHandlers): SseStream {
  let closed = false;
  let es: EventSource | null = null;
  let retryTimer: ReturnType<typeof setTimeout> | null = null;

  const open = async () => {
    const ticket = await fetchTicket();
    if (closed) return;
    const stream = new EventSource(sseBase() + appendTicket(path, ticket));
    es = stream;
    h.addEventListener?.(stream);
    stream.onopen = () => h.onOpen?.();
    stream.onmessage = (ev) => h.onMessage?.(ev);
    stream.onerror = () => {
      // The ticket may have expired (or the connection dropped): reconnecting
      // natively would replay the same dead ticket, so re-open with a new one.
      stream.close();
      if (es === stream) es = null;
      if (closed) return;
      if (h.onError && !h.onError()) return;
      retryTimer = setTimeout(() => void open(), RECONNECT_MS);
    };
  };
  void open();

  return {
    close() {
      closed = true;
      if (retryTimer !== null) clearTimeout(retryTimer);
      es?.close();
      es = null;
    },
  };
}
