import { describe, expect, it } from "vitest";

import { reportQuery } from "./api";

// The task report endpoint renders its skeleton in ?lang= (en/ru/ko, anything
// else falls back server-side) and switches to an attachment with
// download=1. These tests pin the exact query the server handler parses, so
// the report tab, copy button and download button keep requesting the same
// artifact.
describe("reportQuery", () => {
  it("omits the query string when neither task nor locale is given", () => {
    expect(reportQuery()).toBe("");
    expect(reportQuery(undefined, "")).toBe("");
  });

  it("passes the task selector alone", () => {
    expect(reportQuery("7")).toBe("?task=7");
  });

  it("passes the UI locale as lang=", () => {
    expect(reportQuery(undefined, "ru")).toBe("?lang=ru");
  });

  it("combines task and locale with the right separators", () => {
    expect(reportQuery("7", "ru")).toBe("?task=7&lang=ru");
  });

  it("appends download=1 only for downloads", () => {
    expect(reportQuery("7", "ru", true)).toBe("?task=7&lang=ru&download=1");
    expect(reportQuery(undefined, "en", true)).toBe("?lang=en&download=1");
  });
});
