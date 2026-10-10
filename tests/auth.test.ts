import { describe, it, expect, beforeEach } from "vitest";
import { secretOk, safeEqual } from "@/lib/auth";

beforeEach(() => {
  process.env.MCP_SECRET = "s3cr3t";
});

function req(url: string, headers: Record<string, string> = {}) {
  return new Request(url, { headers });
}

describe("secretOk", () => {
  it("accepts a correct Authorization: Bearer header", () => {
    expect(secretOk(req("https://x/api/mcp", { authorization: "Bearer s3cr3t" }))).toBe(true);
  });
  it("no longer accepts the secret as a ?key query param", () => {
    expect(secretOk(req("https://x/api/mcp?key=s3cr3t"))).toBe(false);
  });
  it("rejects a wrong secret", () => {
    expect(secretOk(req("https://x/api/mcp", { authorization: "Bearer nope" }))).toBe(false);
  });
  it("rejects a missing secret", () => {
    expect(secretOk(req("https://x/api/mcp"))).toBe(false);
  });
});

describe("safeEqual", () => {
  it("matches equal strings and rejects different ones of any length", () => {
    expect(safeEqual("abc", "abc")).toBe(true);
    expect(safeEqual("abc", "abd")).toBe(false);
    expect(safeEqual("abc", "abcdef")).toBe(false);
  });
});
