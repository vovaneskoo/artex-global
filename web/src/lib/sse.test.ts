import { describe, expect, it } from "vitest";
import { appendTicket } from "./sse";

// The SSE ticket replaces the long-lived JWT in stream URLs: these are the
// query-string shapes openSseStream builds for EventSource.
describe("appendTicket", () => {
  it("appends ?ticket= to a bare path", () => {
    expect(appendTicket("/api/logs/stream", "abc.def")).toBe("/api/logs/stream?ticket=abc.def");
  });

  it("uses & when the path already carries a query", () => {
    expect(appendTicket("/api/exploration/activity/stream?task=1&since=5", "t.k")).toBe(
      "/api/exploration/activity/stream?task=1&since=5&ticket=t.k",
    );
  });

  it("URL-encodes the ticket value", () => {
    expect(appendTicket("/api/s", "a+b/c")).toBe("/api/s?ticket=a%2Bb%2Fc");
  });

  it("leaves the path untouched without a ticket", () => {
    expect(appendTicket("/api/logs/stream", null)).toBe("/api/logs/stream");
    expect(appendTicket("/api/x?y=1", "")).toBe("/api/x?y=1");
  });
});
