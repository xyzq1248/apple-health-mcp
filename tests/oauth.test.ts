import { describe, it, expect, beforeEach } from "vitest";
import crypto from "node:crypto";
import {
  sign, verify, verifyPkce, issueCode, issueAccessToken,
  validateAccessToken, exchangeCode, nowSec, redirectAllowed,
} from "@/lib/oauth";

beforeEach(() => { process.env.MCP_SECRET = "s3cr3t"; });

describe("sign/verify", () => {
  it("round-trips a payload", () => {
    const t = sign({ t: "access", exp: nowSec() + 100 });
    expect(verify(t)).toMatchObject({ t: "access" });
  });
  it("rejects a tampered body", () => {
    const t = sign({ t: "access", exp: nowSec() + 100 });
    const bad = "x" + t.slice(1);
    expect(verify(bad)).toBeNull();
  });
  it("rejects a token signed with a different secret", () => {
    const t = sign({ t: "access", exp: nowSec() + 100 });
    process.env.MCP_SECRET = "different";
    expect(verify(t)).toBeNull();
  });
  it("rejects an expired token", () => {
    const t = sign({ t: "access", exp: nowSec() - 1 });
    expect(verify(t)).toBeNull();
  });
});

describe("verifyPkce", () => {
  it("validates an S256 challenge", () => {
    const verifier = "abc123def456ghi789jkl012mno345pqr678stu";
    const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
    expect(verifyPkce(verifier, challenge, "S256")).toBe(true);
    expect(verifyPkce("wrong", challenge, "S256")).toBe(false);
  });
  it("validates a plain challenge", () => {
    expect(verifyPkce("samevalue", "samevalue", "plain")).toBe(true);
    expect(verifyPkce("a", "b", "plain")).toBe(false);
  });
});

describe("access tokens", () => {
  it("validates a freshly issued access token", () => {
    expect(validateAccessToken(issueAccessToken())).toBe(true);
  });
  it("rejects a code used as an access token", () => {
    const code = issueCode({ cc: "x", ccm: "S256", ru: "https://c/cb", cid: "c1" });
    expect(validateAccessToken(code)).toBe(false); // wrong type
  });
  it("rejects garbage", () => {
    expect(validateAccessToken("not.a.token")).toBe(false);
  });
});

describe("exchangeCode", () => {
  const verifier = "abc123def456ghi789jkl012mno345pqr678stu";
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");

  it("exchanges a valid code + verifier for an access token", () => {
    const code = issueCode({ cc: challenge, ccm: "S256", ru: "https://c/cb", cid: "c1" });
    const r = exchangeCode({ grant_type: "authorization_code", code, code_verifier: verifier, redirect_uri: "https://c/cb" });
    expect("access_token" in r).toBe(true);
    if ("access_token" in r) expect(validateAccessToken(r.access_token)).toBe(true);
  });
  it("rejects a wrong PKCE verifier", () => {
    const code = issueCode({ cc: challenge, ccm: "S256", ru: "https://c/cb", cid: "c1" });
    const r = exchangeCode({ grant_type: "authorization_code", code, code_verifier: "wrong", redirect_uri: "https://c/cb" });
    expect(r).toEqual({ error: "invalid_grant" });
  });
  it("rejects a redirect_uri mismatch", () => {
    const code = issueCode({ cc: challenge, ccm: "S256", ru: "https://c/cb", cid: "c1" });
    const r = exchangeCode({ grant_type: "authorization_code", code, code_verifier: verifier, redirect_uri: "https://evil/cb" });
    expect(r).toEqual({ error: "invalid_grant" });
  });
  it("rejects an unsupported grant type", () => {
    const r = exchangeCode({ grant_type: "password" });
    expect(r).toEqual({ error: "unsupported_grant_type" });
  });
  it("rejects an access token presented as a code", () => {
    const r = exchangeCode({ grant_type: "authorization_code", code: issueAccessToken(), code_verifier: verifier });
    expect(r).toEqual({ error: "invalid_grant" });
  });
  it("rejects a code minted without a PKCE challenge", () => {
    const code = issueCode({ cc: "", ccm: "S256", ru: "https://c/cb", cid: "c1" });
    const r = exchangeCode({ grant_type: "authorization_code", code, code_verifier: verifier, redirect_uri: "https://c/cb" });
    expect(r).toEqual({ error: "invalid_grant" });
  });
  it("rejects the plain PKCE method", () => {
    const code = issueCode({ cc: verifier, ccm: "plain", ru: "https://c/cb", cid: "c1" });
    const r = exchangeCode({ grant_type: "authorization_code", code, code_verifier: verifier, redirect_uri: "https://c/cb" });
    expect(r).toEqual({ error: "invalid_grant" });
  });
});

describe("redirectAllowed", () => {
  const ok = (s: string) => redirectAllowed(new URL(s));
  it("accepts Claude's hosted callback and loopback callbacks on any port", () => {
    expect(ok("https://claude.ai/api/mcp/auth_callback")).toBe(true);
    expect(ok("http://localhost:3118/callback")).toBe(true);
    expect(ok("http://127.0.0.1:51234/callback")).toBe(true);
  });
  it("rejects anything else", () => {
    expect(ok("https://evil.example/api/mcp/auth_callback")).toBe(false);
    expect(ok("https://claude.ai.evil.example/api/mcp/auth_callback")).toBe(false);
    expect(ok("http://claude.ai/api/mcp/auth_callback")).toBe(false);
    expect(ok("https://claude.ai/other")).toBe(false);
    expect(ok("https://user:pw@claude.ai/api/mcp/auth_callback")).toBe(false);
    expect(ok("http://localhost.evil.example/callback")).toBe(false);
  });
});
