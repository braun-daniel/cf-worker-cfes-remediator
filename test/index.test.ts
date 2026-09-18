/**
 * Tests for the CF Email Security False-Positive Remediator Worker.
 *
 * Runs inside the Workers runtime via @cloudflare/vitest-pool-workers, which
 * provides real KVNamespace bindings (from wrangler.toml) and the full Workers
 * API surface. Outbound `fetch` calls are stubbed with `vi.stubGlobal`.
 */

import { env } from "cloudflare:workers";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

import worker, {
  authHeaders,
  parsePatterns,
  parseDispositions,
  matchesPatterns,
  isProcessed,
  markProcessed,
  searchMessages,
  getRawEmail,
  moveMessage,
  moveMessagesBulk,
  releaseFromQuarantine,
  reclassifyMessage,
  type Env,
} from "../src/index";

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Minimal Env fixture — KV is provided by the Workers runtime via wrangler.toml binding. */
function makeEnv(overrides: Partial<Env> = {}): Env {
  return {
    FP_REMEDIATOR_KV: env.FP_REMEDIATOR_KV,
    CF_API_TOKEN: "test-token",
    CF_ACCOUNT_ID: "test-account",
    CONTENT_PATTERNS: '["phoenix project"]',
    TARGET_DISPOSITIONS: '["MALICIOUS","SUSPICIOUS","SPOOF"]',
    LOOKBACK_MINUTES: "5",
    RECLASSIFY_FP: "false",
    MAX_MESSAGES_PER_RUN: "100",
    DRY_RUN: "false",
    ...overrides,
  };
}

/** Build a minimal InvestigateListResponse fixture. */
function makeMessage(overrides: Record<string, unknown> = {}) {
  return {
    id: "msg-001",
    postfix_id: "postfix-001",
    is_quarantined: false,
    is_phish_submission: false,
    client_recipients: ["user@example.com"],
    detection_reasons: ["phishing"],
    sender: "sender@example.com",
    final_disposition: "MALICIOUS",
    delivery_status: "moved",
    properties: {},
    ...overrides,
  };
}

/** Build a Response stub that returns JSON. */
function okJson(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

/** Build a Response stub with a non-2xx status. */
function errorResponse(status: number, body = "Error"): Response {
  return new Response(body, { status });
}

// ─── authHeaders ─────────────────────────────────────────────────────────────

describe("authHeaders", () => {
  it("returns Bearer token and Content-Type", () => {
    const headers = authHeaders("my-secret-token") as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer my-secret-token");
    expect(headers["Content-Type"]).toBe("application/json");
  });

  it("works with an empty token string", () => {
    const headers = authHeaders("") as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer ");
  });
});

// ─── parsePatterns ────────────────────────────────────────────────────────────

describe("parsePatterns", () => {
  it("parses a valid JSON array of patterns into RegExp objects", () => {
    const patterns = parsePatterns('["foo","bar"]');
    expect(patterns).toHaveLength(2);
    expect(patterns[0]).toBeInstanceOf(RegExp);
    expect(patterns[1]).toBeInstanceOf(RegExp);
  });

  it("applies the case-insensitive flag", () => {
    const [re] = parsePatterns('["hello"]');
    expect(re.flags).toContain("i");
    expect(re.test("HELLO WORLD")).toBe(true);
  });

  it("returns an empty array for an empty JSON array", () => {
    expect(parsePatterns("[]")).toEqual([]);
  });

  it("returns an empty array and does not throw for invalid JSON", () => {
    expect(parsePatterns("not-json")).toEqual([]);
  });

  it("returns an empty array for an empty string", () => {
    expect(parsePatterns("")).toEqual([]);
  });
});

// ─── parseDispositions ───────────────────────────────────────────────────────

describe("parseDispositions", () => {
  it("parses a valid JSON array", () => {
    const dispositions = parseDispositions('["SPAM","BULK"]');
    expect(dispositions).toEqual(["SPAM", "BULK"]);
  });

  it("falls back to defaults on invalid JSON", () => {
    const dispositions = parseDispositions("bad json");
    expect(dispositions).toEqual(["MALICIOUS", "SUSPICIOUS", "SPOOF"]);
  });

  it("falls back to defaults on empty string", () => {
    const dispositions = parseDispositions("");
    expect(dispositions).toEqual(["MALICIOUS", "SUSPICIOUS", "SPOOF"]);
  });

  it("returns an empty array when given '[]'", () => {
    expect(parseDispositions("[]")).toEqual([]);
  });
});

// ─── matchesPatterns ─────────────────────────────────────────────────────────

describe("matchesPatterns", () => {
  it("returns true when a pattern matches the raw EML", () => {
    const patterns = [/phoenix project/i];
    expect(matchesPatterns("Subject: Re: Phoenix Project update\n\nHello", patterns)).toBe(true);
  });

  it("is case-insensitive when the regex has the i flag", () => {
    const patterns = [/internal-tool/i];
    expect(matchesPatterns("X-Internal-Tool: monthly-report", patterns)).toBe(true);
  });

  it("returns false when no pattern matches", () => {
    const patterns = [/top secret/i];
    expect(matchesPatterns("Subject: Normal email\n\nHello", patterns)).toBe(false);
  });

  it("returns false for an empty patterns array", () => {
    expect(matchesPatterns("any content here", [])).toBe(false);
  });

  it("returns true when any of multiple patterns matches", () => {
    const patterns = [/first/i, /second/i];
    expect(matchesPatterns("first", patterns)).toBe(true);
    expect(matchesPatterns("second", patterns)).toBe(true);
    expect(matchesPatterns("neither", patterns)).toBe(false);
  });

  it("can match against email headers", () => {
    const raw = "From: trusted@corp.com\nSubject: Quarterly Report\n\nBody text";
    expect(matchesPatterns(raw, [/From:.*trusted@corp\.com/i])).toBe(true);
  });
});

// ─── KV dedup: isProcessed / markProcessed ───────────────────────────────────

describe("isProcessed / markProcessed", () => {
  it("returns false for a message that has not been processed", async () => {
    const kv = env.FP_REMEDIATOR_KV;
    expect(await isProcessed(kv, "new-msg-id")).toBe(false);
  });

  it("returns true after markProcessed is called", async () => {
    const kv = env.FP_REMEDIATOR_KV;
    await markProcessed(kv, "marked-msg-id");
    expect(await isProcessed(kv, "marked-msg-id")).toBe(true);
  });

  it("stores the value with key prefix 'processed:'", async () => {
    const kv = env.FP_REMEDIATOR_KV;
    await markProcessed(kv, "prefix-test");
    const raw = await kv.get("processed:prefix-test");
    expect(raw).not.toBeNull();
  });

  it("stores an ISO timestamp as the value", async () => {
    const kv = env.FP_REMEDIATOR_KV;
    const before = new Date().toISOString();
    await markProcessed(kv, "ts-test");
    const stored = await kv.get("processed:ts-test");
    expect(stored).not.toBeNull();
    expect(new Date(stored!).getTime()).toBeGreaterThanOrEqual(new Date(before).getTime());
  });

  it("different IDs are independent", async () => {
    const kv = env.FP_REMEDIATOR_KV;
    await markProcessed(kv, "id-a-unique");
    expect(await isProcessed(kv, "id-a-unique")).toBe(true);
    expect(await isProcessed(kv, "id-b-unique")).toBe(false);
  });
});

// ─── searchMessages ──────────────────────────────────────────────────────────

describe("searchMessages", () => {
  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("returns messages from result field", async () => {
    const message = makeMessage();
    vi.mocked(fetch).mockResolvedValueOnce(
      okJson({ success: true, result: [message], result_info: {} }),
    );
    const result = await searchMessages(makeEnv(), { disposition: "MALICIOUS" });
    expect(result.messages).toHaveLength(1);
    expect(result.messages[0].id).toBe("msg-001");
    expect(result.cursor).toBeUndefined();
  });

  it("falls back to results field when result is absent", async () => {
    const message = makeMessage({ id: "fallback-msg" });
    vi.mocked(fetch).mockResolvedValueOnce(
      okJson({ success: true, results: [message] }),
    );
    const result = await searchMessages(makeEnv(), {});
    expect(result.messages[0].id).toBe("fallback-msg");
  });

  it("returns the next cursor from result_info.cursor", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      okJson({ success: true, result: [], result_info: { cursor: "abc123" } }),
    );
    const result = await searchMessages(makeEnv(), {});
    expect(result.cursor).toBe("abc123");
  });

  it("returns the next cursor from result_info.cursors.after", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      okJson({ success: true, result: [], result_info: { cursors: { after: "cursor-after" } } }),
    );
    const result = await searchMessages(makeEnv(), {});
    expect(result.cursor).toBe("cursor-after");
  });

  it("throws on HTTP error status", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(errorResponse(401, "Unauthorized"));
    await expect(searchMessages(makeEnv(), {})).rejects.toThrow("searchMessages HTTP 401");
  });

  it("throws on API-level errors array", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      okJson({ success: false, result: null, errors: [{ code: 1000, message: "Invalid token" }] }),
    );
    await expect(searchMessages(makeEnv(), {})).rejects.toThrow("searchMessages API errors");
  });

  it("builds URL with disposition query param", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      okJson({ success: true, result: [], result_info: {} }),
    );
    await searchMessages(makeEnv(), { disposition: "SPOOF" });
    const url = new URL((vi.mocked(fetch).mock.calls[0][0] as string));
    expect(url.searchParams.get("final_disposition")).toBe("SPOOF");
  });

  it("builds URL with cursor query param", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      okJson({ success: true, result: [], result_info: {} }),
    );
    await searchMessages(makeEnv(), { cursor: "my-cursor" });
    const url = new URL((vi.mocked(fetch).mock.calls[0][0] as string));
    expect(url.searchParams.get("cursor")).toBe("my-cursor");
  });

  it("sends Authorization header", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      okJson({ success: true, result: [], result_info: {} }),
    );
    await searchMessages(makeEnv({ CF_API_TOKEN: "super-secret" }), {});
    const init = vi.mocked(fetch).mock.calls[0][1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer super-secret");
  });
});

// ─── getRawEmail ─────────────────────────────────────────────────────────────

describe("getRawEmail", () => {
  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("returns the raw EML string", async () => {
    const rawEml = "From: sender@example.com\nSubject: Hello\n\nBody";
    vi.mocked(fetch).mockResolvedValueOnce(
      okJson({ success: true, result: { raw: rawEml } }),
    );
    expect(await getRawEmail(makeEnv(), "msg-001")).toBe(rawEml);
  });

  it("returns empty string when result.raw is absent", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(okJson({ success: true, result: {} }));
    expect(await getRawEmail(makeEnv(), "msg-001")).toBe("");
  });

  it("throws on HTTP error", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(errorResponse(403, "Forbidden"));
    await expect(getRawEmail(makeEnv(), "msg-001")).rejects.toThrow("getRawEmail HTTP 403");
  });

  it("throws when errors array is non-empty", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      okJson({ success: false, errors: [{ code: 9001, message: "Not found" }] }),
    );
    await expect(getRawEmail(makeEnv(), "msg-001")).rejects.toThrow("getRawEmail API errors");
  });

  it("includes the investigateId in the URL", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      okJson({ success: true, result: { raw: "eml" } }),
    );
    await getRawEmail(makeEnv(), "specific-id-xyz");
    const url = vi.mocked(fetch).mock.calls[0][0] as string;
    expect(url).toContain("specific-id-xyz/raw");
  });
});

// ─── moveMessage ─────────────────────────────────────────────────────────────

describe("moveMessage", () => {
  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("returns true on success", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(okJson({ success: true }));
    expect(await moveMessage(makeEnv(), "msg-001", "Inbox")).toBe(true);
  });

  it("returns false when success is false", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(okJson({ success: false }));
    expect(await moveMessage(makeEnv(), "msg-001", "Inbox")).toBe(false);
  });

  it("returns false on HTTP error (does not throw)", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(errorResponse(500, "Internal Server Error"));
    expect(await moveMessage(makeEnv(), "msg-001", "Inbox")).toBe(false);
  });

  it("sends destination in the request body", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(okJson({ success: true }));
    await moveMessage(makeEnv(), "msg-002", "JunkEmail");
    const init = vi.mocked(fetch).mock.calls[0][1] as RequestInit;
    expect(JSON.parse(init.body as string)).toEqual({ destination: "JunkEmail" });
  });

  it("includes the investigateId in the URL", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(okJson({ success: true }));
    await moveMessage(makeEnv(), "specific-move-id", "Inbox");
    const url = vi.mocked(fetch).mock.calls[0][0] as string;
    expect(url).toContain("specific-move-id/move");
  });
});

// ─── moveMessagesBulk ────────────────────────────────────────────────────────

describe("moveMessagesBulk", () => {
  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("separates moved and failed messages from the API response", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(okJson({
      success: true,
      result: [
        { id: "id-1", status: "success" },
        { id: "id-2", status: "failed" },
        { id: "id-3" },
      ],
    }));
    const result = await moveMessagesBulk(makeEnv(), ["id-1", "id-2", "id-3"], "Inbox");
    expect(result.moved).toEqual(expect.arrayContaining(["id-1", "id-3"]));
    expect(result.failed).toEqual(["id-2"]);
  });

  it("returns all IDs as failed on HTTP error", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(errorResponse(503, "Service Unavailable"));
    const result = await moveMessagesBulk(makeEnv(), ["x", "y"], "Inbox");
    expect(result.moved).toEqual([]);
    expect(result.failed).toEqual(["x", "y"]);
  });

  it("returns empty arrays for empty result list", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(okJson({ success: true, result: [] }));
    const result = await moveMessagesBulk(makeEnv(), [], "Inbox");
    expect(result.moved).toEqual([]);
    expect(result.failed).toEqual([]);
  });

  it("sends ids and destination in the request body", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(okJson({ success: true, result: [] }));
    await moveMessagesBulk(makeEnv(), ["a", "b"], "JunkEmail");
    const init = vi.mocked(fetch).mock.calls[0][1] as RequestInit;
    expect(JSON.parse(init.body as string)).toEqual({ destination: "JunkEmail", ids: ["a", "b"] });
  });
});

// ─── releaseFromQuarantine ───────────────────────────────────────────────────

describe("releaseFromQuarantine", () => {
  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("correctly classifies delivered, failed, and undelivered", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(okJson({
      success: true,
      result: [
        { id: "id-1", delivered: ["a@b.com"], failed: [], undelivered: [] },
        { id: "id-2", delivered: [], failed: ["c@d.com"], undelivered: [] },
        { id: "id-3", delivered: [], failed: [], undelivered: ["e@f.com"] },
      ],
    }));
    const result = await releaseFromQuarantine(makeEnv(), ["id-1", "id-2", "id-3"]);
    expect(result.delivered).toEqual(["id-1"]);
    expect(result.failed).toEqual(["id-2"]);
    expect(result.undelivered).toEqual(["id-3"]);
  });

  it("returns all IDs as failed on HTTP error", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(errorResponse(500, "Server Error"));
    const result = await releaseFromQuarantine(makeEnv(), ["q1", "q2"]);
    expect(result.delivered).toEqual([]);
    expect(result.failed).toEqual(["q1", "q2"]);
    expect(result.undelivered).toEqual([]);
  });

  it("sends array of IDs as the JSON body (not wrapped in an object)", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(okJson({ success: true, result: [] }));
    await releaseFromQuarantine(makeEnv(), ["id-x", "id-y"]);
    const init = vi.mocked(fetch).mock.calls[0][1] as RequestInit;
    expect(JSON.parse(init.body as string)).toEqual(["id-x", "id-y"]);
  });

  it("message with delivered and failed recipients is counted in both buckets", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(okJson({
      success: true,
      result: [
        { id: "id-multi", delivered: ["a@b.com"], failed: ["c@d.com"], undelivered: [] },
      ],
    }));
    const result = await releaseFromQuarantine(makeEnv(), ["id-multi"]);
    expect(result.delivered).toContain("id-multi");
    expect(result.failed).toContain("id-multi");
  });
});

// ─── reclassifyMessage ───────────────────────────────────────────────────────

describe("reclassifyMessage", () => {
  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("returns true on success", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(okJson({ success: true }));
    expect(await reclassifyMessage(makeEnv(), "msg-001", "NONE")).toBe(true);
  });

  it("returns false when success is false", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(okJson({ success: false }));
    expect(await reclassifyMessage(makeEnv(), "msg-001", "NONE")).toBe(false);
  });

  it("returns false on HTTP error (does not throw)", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(errorResponse(429, "Too Many Requests"));
    expect(await reclassifyMessage(makeEnv(), "msg-001", "NONE")).toBe(false);
  });

  it("sends expected_disposition in request body", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(okJson({ success: true }));
    await reclassifyMessage(makeEnv(), "msg-001", "BULK");
    const init = vi.mocked(fetch).mock.calls[0][1] as RequestInit;
    expect(JSON.parse(init.body as string)).toEqual({ expected_disposition: "BULK" });
  });

  it("includes the investigateId in the URL", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(okJson({ success: true }));
    await reclassifyMessage(makeEnv(), "unique-id-42", "SUSPICIOUS");
    const url = vi.mocked(fetch).mock.calls[0][0] as string;
    expect(url).toContain("unique-id-42/reclassify");
  });
});

// ─── HTTP handler: fetch ──────────────────────────────────────────────────────

describe("fetch handler", () => {
  it("GET /health returns 200 with status ok", async () => {
    const req = new Request("https://worker.example.com/health");
    const res = await worker.fetch(req, makeEnv());
    expect(res.status).toBe(200);
    const body = await res.json<{ status: string; timestamp: string }>();
    expect(body.status).toBe("ok");
    expect(typeof body.timestamp).toBe("string");
  });

  it("GET /health returns a valid ISO timestamp", async () => {
    const req = new Request("https://worker.example.com/health");
    const res = await worker.fetch(req, makeEnv());
    const { timestamp } = await res.json<{ timestamp: string }>();
    expect(new Date(timestamp).toISOString()).toBe(timestamp);
  });

  it("unknown path returns 404", async () => {
    const req = new Request("https://worker.example.com/unknown-path");
    const res = await worker.fetch(req, makeEnv());
    expect(res.status).toBe(404);
  });

  it("GET /trigger returns 404 (requires POST)", async () => {
    const req = new Request("https://worker.example.com/trigger", { method: "GET" });
    const res = await worker.fetch(req, makeEnv());
    expect(res.status).toBe(404);
  });

  it("POST /trigger with no patterns configured returns triggered status", async () => {
    // No CONTENT_PATTERNS → scheduled() exits early; should still return { status: "triggered" }
    const req = new Request("https://worker.example.com/trigger", { method: "POST" });
    const testEnv = makeEnv({ CONTENT_PATTERNS: "[]" });
    const res = await worker.fetch(req, testEnv);
    expect(res.status).toBe(200);
    const body = await res.json<{ status: string }>();
    expect(body.status).toBe("triggered");
  });

  it("POST /trigger returns a valid ISO timestamp", async () => {
    const req = new Request("https://worker.example.com/trigger", { method: "POST" });
    const res = await worker.fetch(req, makeEnv({ CONTENT_PATTERNS: "[]" }));
    const { timestamp } = await res.json<{ timestamp: string }>();
    expect(new Date(timestamp).toISOString()).toBe(timestamp);
  });

  it("GET /health Content-Type is application/json", async () => {
    const req = new Request("https://worker.example.com/health");
    const res = await worker.fetch(req, makeEnv());
    expect(res.headers.get("Content-Type")).toBe("application/json");
  });
});

// ─── scheduled handler: early-exit guards ────────────────────────────────────

describe("scheduled handler: early exits", () => {
  it("exits early when CONTENT_PATTERNS is empty (no API calls made)", async () => {
    // No fetch stub installed → if fetch were called it would throw with "not a function"
    const testEnv = makeEnv({ CONTENT_PATTERNS: "[]" });
    await expect(
      worker.scheduled({} as ScheduledController, testEnv, {} as ExecutionContext),
    ).resolves.toBeUndefined();
  });

  it("exits early when CF_API_TOKEN is missing", async () => {
    const testEnv = makeEnv({ CF_API_TOKEN: "" });
    await expect(
      worker.scheduled({} as ScheduledController, testEnv, {} as ExecutionContext),
    ).resolves.toBeUndefined();
  });

  it("exits early when CF_ACCOUNT_ID is missing", async () => {
    const testEnv = makeEnv({ CF_ACCOUNT_ID: "" });
    await expect(
      worker.scheduled({} as ScheduledController, testEnv, {} as ExecutionContext),
    ).resolves.toBeUndefined();
  });

  it("exits early when CONTENT_PATTERNS is invalid JSON", async () => {
    const testEnv = makeEnv({ CONTENT_PATTERNS: "not-json" });
    await expect(
      worker.scheduled({} as ScheduledController, testEnv, {} as ExecutionContext),
    ).resolves.toBeUndefined();
  });
});

// ─── scheduled handler: full run (integration) ───────────────────────────────

describe("scheduled handler: full run", () => {
  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.unstubAllGlobals(); });

  /** Returns empty results for all dispositions except MALICIOUS. */
  function emptyForDisposition(disposition: string): Response {
    return okJson({ success: true, result: [], result_info: {} });
  }

  it("processes a non-quarantined matching message via move", async () => {
    const message = makeMessage({ id: "full-run-001", is_quarantined: false });
    vi.mocked(fetch)
      // MALICIOUS search
      .mockResolvedValueOnce(okJson({ success: true, result: [message], result_info: {} }))
      // raw content — matches pattern
      .mockResolvedValueOnce(okJson({ success: true, result: { raw: "Subject: Phoenix Project update" } }))
      // SUSPICIOUS search → empty
      .mockResolvedValueOnce(okJson({ success: true, result: [], result_info: {} }))
      // SPOOF search → empty
      .mockResolvedValueOnce(okJson({ success: true, result: [], result_info: {} }))
      // bulk move
      .mockResolvedValueOnce(okJson({ success: true, result: [{ id: "full-run-001", status: "success" }] }));

    const testEnv = makeEnv({ CONTENT_PATTERNS: '["phoenix project"]', RECLASSIFY_FP: "false" });
    await expect(
      worker.scheduled({} as ScheduledController, testEnv, {} as ExecutionContext),
    ).resolves.toBeUndefined();

    // Message should now be marked as processed in KV
    expect(await isProcessed(env.FP_REMEDIATOR_KV, "full-run-001")).toBe(true);
  });

  it("uses release endpoint for quarantined matching messages", async () => {
    const message = makeMessage({ id: "quar-001", is_quarantined: true });
    vi.mocked(fetch)
      .mockResolvedValueOnce(okJson({ success: true, result: [message], result_info: {} }))
      .mockResolvedValueOnce(okJson({ success: true, result: { raw: "phoenix project here" } }))
      .mockResolvedValueOnce(okJson({ success: true, result: [], result_info: {} }))
      .mockResolvedValueOnce(okJson({ success: true, result: [], result_info: {} }))
      // release
      .mockResolvedValueOnce(okJson({
        success: true,
        result: [{ id: "quar-001", delivered: ["user@example.com"], failed: [], undelivered: [] }],
      }));

    const testEnv = makeEnv({ CONTENT_PATTERNS: '["phoenix project"]', RECLASSIFY_FP: "false" });
    await expect(
      worker.scheduled({} as ScheduledController, testEnv, {} as ExecutionContext),
    ).resolves.toBeUndefined();

    // Verify release was called (5th fetch call is the release endpoint)
    const releaseCall = vi.mocked(fetch).mock.calls[4];
    const url = releaseCall[0] as string;
    expect(url).toContain("/release");
  });

  it("also calls reclassify when RECLASSIFY_FP is true", async () => {
    const message = makeMessage({ id: "reclassify-001", is_quarantined: false });
    vi.mocked(fetch)
      .mockResolvedValueOnce(okJson({ success: true, result: [message], result_info: {} }))
      .mockResolvedValueOnce(okJson({ success: true, result: { raw: "phoenix project" } }))
      .mockResolvedValueOnce(okJson({ success: true, result: [], result_info: {} }))
      .mockResolvedValueOnce(okJson({ success: true, result: [], result_info: {} }))
      .mockResolvedValueOnce(okJson({ success: true, result: [{ id: "reclassify-001" }] })) // move
      .mockResolvedValueOnce(okJson({ success: true })); // reclassify

    const testEnv = makeEnv({ CONTENT_PATTERNS: '["phoenix project"]', RECLASSIFY_FP: "true" });
    await expect(
      worker.scheduled({} as ScheduledController, testEnv, {} as ExecutionContext),
    ).resolves.toBeUndefined();

    // 6 fetch calls total: 3 searches + 1 raw + 1 move + 1 reclassify
    expect(vi.mocked(fetch).mock.calls).toHaveLength(6);
    const reclassifyUrl = vi.mocked(fetch).mock.calls[5][0] as string;
    expect(reclassifyUrl).toContain("reclassify-001/reclassify");
  });

  it("skips already-processed messages (no raw fetch)", async () => {
    await markProcessed(env.FP_REMEDIATOR_KV, "already-done-v2");
    const message = makeMessage({ id: "already-done-v2" });

    vi.mocked(fetch)
      .mockResolvedValueOnce(okJson({ success: true, result: [message], result_info: {} }))
      .mockResolvedValueOnce(okJson({ success: true, result: [], result_info: {} }))
      .mockResolvedValueOnce(okJson({ success: true, result: [], result_info: {} }));

    const testEnv = makeEnv({ CONTENT_PATTERNS: '["phoenix project"]' });
    await expect(
      worker.scheduled({} as ScheduledController, testEnv, {} as ExecutionContext),
    ).resolves.toBeUndefined();

    // Only 3 fetch calls (3 disposition searches); no /raw call
    expect(vi.mocked(fetch).mock.calls).toHaveLength(3);
  });

  it("skips allowlisted messages (no raw fetch)", async () => {
    const message = makeMessage({
      id: "allowlisted-001",
      properties: { allowlisted_pattern: "some-pattern" },
    });

    vi.mocked(fetch)
      .mockResolvedValueOnce(okJson({ success: true, result: [message], result_info: {} }))
      .mockResolvedValueOnce(okJson({ success: true, result: [], result_info: {} }))
      .mockResolvedValueOnce(okJson({ success: true, result: [], result_info: {} }));

    const testEnv = makeEnv({ CONTENT_PATTERNS: '["phoenix project"]' });
    await expect(
      worker.scheduled({} as ScheduledController, testEnv, {} as ExecutionContext),
    ).resolves.toBeUndefined();

    // Only 3 disposition searches; no /raw call
    expect(vi.mocked(fetch).mock.calls).toHaveLength(3);
  });

  it("does not remediate a non-matching message but still marks it processed", async () => {
    const message = makeMessage({ id: "no-match-001", is_quarantined: false });

    vi.mocked(fetch)
      .mockResolvedValueOnce(okJson({ success: true, result: [message], result_info: {} }))
      .mockResolvedValueOnce(okJson({ success: true, result: { raw: "completely unrelated content" } }))
      .mockResolvedValueOnce(okJson({ success: true, result: [], result_info: {} }))
      .mockResolvedValueOnce(okJson({ success: true, result: [], result_info: {} }));

    const testEnv = makeEnv({ CONTENT_PATTERNS: '["phoenix project"]' });
    await expect(
      worker.scheduled({} as ScheduledController, testEnv, {} as ExecutionContext),
    ).resolves.toBeUndefined();

    // 4 calls: 3 searches + 1 raw; no move or release
    expect(vi.mocked(fetch).mock.calls).toHaveLength(4);

    // Message is still marked processed to avoid reprocessing
    expect(await isProcessed(env.FP_REMEDIATOR_KV, "no-match-001")).toBe(true);
  });

  it("respects MAX_MESSAGES_PER_RUN cap", async () => {
    const messages = ["cap-001", "cap-002", "cap-003"].map((id) =>
      makeMessage({ id }),
    );

    vi.mocked(fetch)
      .mockResolvedValueOnce(okJson({ success: true, result: messages, result_info: {} }))
      // Only 2 raw calls (cap=2)
      .mockResolvedValueOnce(okJson({ success: true, result: { raw: "no match" } }))
      .mockResolvedValueOnce(okJson({ success: true, result: { raw: "no match" } }));

    const testEnv = makeEnv({
      CONTENT_PATTERNS: '["phoenix project"]',
      TARGET_DISPOSITIONS: '["MALICIOUS"]',
      MAX_MESSAGES_PER_RUN: "2",
    });
    await expect(
      worker.scheduled({} as ScheduledController, testEnv, {} as ExecutionContext),
    ).resolves.toBeUndefined();

    // 1 search + 2 raw = 3 total (not 4)
    expect(vi.mocked(fetch).mock.calls).toHaveLength(3);
  });

  it("handles search API failure gracefully and continues to next disposition", async () => {
    vi.mocked(fetch)
      // MALICIOUS search fails
      .mockResolvedValueOnce(errorResponse(500, "Server Error"))
      // SUSPICIOUS search succeeds but empty
      .mockResolvedValueOnce(okJson({ success: true, result: [], result_info: {} }))
      // SPOOF search succeeds but empty
      .mockResolvedValueOnce(okJson({ success: true, result: [], result_info: {} }));

    const testEnv = makeEnv({ CONTENT_PATTERNS: '["phoenix project"]' });
    await expect(
      worker.scheduled({} as ScheduledController, testEnv, {} as ExecutionContext),
    ).resolves.toBeUndefined();
  });
});

// ─── Dry-run mode ─────────────────────────────────────────────────────────────

describe("dry-run mode", () => {
  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("does not call move, release, or reclassify for a matching message", async () => {
    const message = makeMessage({ id: "dry-run-001", is_quarantined: false });

    vi.mocked(fetch)
      .mockResolvedValueOnce(okJson({ success: true, result: [message], result_info: {} }))
      .mockResolvedValueOnce(okJson({ success: true, result: { raw: "phoenix project" } }))
      .mockResolvedValueOnce(okJson({ success: true, result: [], result_info: {} }))
      .mockResolvedValueOnce(okJson({ success: true, result: [], result_info: {} }));

    const testEnv = makeEnv({
      CONTENT_PATTERNS: '["phoenix project"]',
      RECLASSIFY_FP: "true",
      DRY_RUN: "true",
    });
    await expect(
      worker.scheduled({} as ScheduledController, testEnv, {} as ExecutionContext),
    ).resolves.toBeUndefined();

    // 3 searches + 1 raw = 4 total; no move/release/reclassify calls
    expect(vi.mocked(fetch).mock.calls).toHaveLength(4);
    const urls = vi.mocked(fetch).mock.calls.map((c) => c[0] as string);
    expect(urls.some((u) => u.includes("/move"))).toBe(false);
    expect(urls.some((u) => u.includes("/release"))).toBe(false);
    expect(urls.some((u) => u.includes("/reclassify"))).toBe(false);
  });

  it("does not call release for a matching quarantined message", async () => {
    const message = makeMessage({ id: "dry-run-quar", is_quarantined: true });

    vi.mocked(fetch)
      .mockResolvedValueOnce(okJson({ success: true, result: [message], result_info: {} }))
      .mockResolvedValueOnce(okJson({ success: true, result: { raw: "phoenix project" } }))
      .mockResolvedValueOnce(okJson({ success: true, result: [], result_info: {} }))
      .mockResolvedValueOnce(okJson({ success: true, result: [], result_info: {} }));

    const testEnv = makeEnv({
      CONTENT_PATTERNS: '["phoenix project"]',
      DRY_RUN: "true",
    });
    await expect(
      worker.scheduled({} as ScheduledController, testEnv, {} as ExecutionContext),
    ).resolves.toBeUndefined();

    const urls = vi.mocked(fetch).mock.calls.map((c) => c[0] as string);
    expect(urls.some((u) => u.includes("/release"))).toBe(false);
  });

  it("does not write to KV for processed messages in dry-run mode", async () => {
    const message = makeMessage({ id: "dry-run-kv-001" });

    vi.mocked(fetch)
      .mockResolvedValueOnce(okJson({ success: true, result: [message], result_info: {} }))
      .mockResolvedValueOnce(okJson({ success: true, result: { raw: "phoenix project" } }))
      .mockResolvedValueOnce(okJson({ success: true, result: [], result_info: {} }))
      .mockResolvedValueOnce(okJson({ success: true, result: [], result_info: {} }));

    const testEnv = makeEnv({ CONTENT_PATTERNS: '["phoenix project"]', DRY_RUN: "true" });
    await worker.scheduled({} as ScheduledController, testEnv, {} as ExecutionContext);

    // Message must NOT be in KV — dry-run must not mark it processed
    expect(await isProcessed(env.FP_REMEDIATOR_KV, "dry-run-kv-001")).toBe(false);
  });

  it("re-scans the same message on a second run in dry-run mode", async () => {
    const message = makeMessage({ id: "dry-run-rescan" });
    const searchReply = () => okJson({ success: true, result: [message], result_info: {} });
    const emptyReply = () => okJson({ success: true, result: [], result_info: {} });
    const rawReply = () => okJson({ success: true, result: { raw: "no match" } });

    // Two full runs: 3 searches + 1 raw each = 8 fetch calls total
    vi.mocked(fetch)
      .mockResolvedValueOnce(searchReply())
      .mockResolvedValueOnce(rawReply())
      .mockResolvedValueOnce(emptyReply())
      .mockResolvedValueOnce(emptyReply())
      .mockResolvedValueOnce(searchReply())
      .mockResolvedValueOnce(rawReply())
      .mockResolvedValueOnce(emptyReply())
      .mockResolvedValueOnce(emptyReply());

    const testEnv = makeEnv({ CONTENT_PATTERNS: '["phoenix project"]', DRY_RUN: "true" });
    await worker.scheduled({} as ScheduledController, testEnv, {} as ExecutionContext);
    await worker.scheduled({} as ScheduledController, testEnv, {} as ExecutionContext);

    // Both runs must have fetched /raw — message was not deduped
    expect(vi.mocked(fetch).mock.calls).toHaveLength(8);
  });

  it("GET /health includes dry_run: true when DRY_RUN is true", async () => {
    const req = new Request("https://worker.example.com/health");
    const res = await worker.fetch(req, makeEnv({ DRY_RUN: "true" }));
    const body = await res.json<{ dry_run: boolean }>();
    expect(body.dry_run).toBe(true);
  });

  it("GET /health includes dry_run: false when DRY_RUN is false", async () => {
    const req = new Request("https://worker.example.com/health");
    const res = await worker.fetch(req, makeEnv({ DRY_RUN: "false" }));
    const body = await res.json<{ dry_run: boolean }>();
    expect(body.dry_run).toBe(false);
  });

  it("POST /trigger includes dry_run in the response", async () => {
    const req = new Request("https://worker.example.com/trigger", { method: "POST" });
    const res = await worker.fetch(req, makeEnv({ CONTENT_PATTERNS: "[]", DRY_RUN: "true" }));
    const body = await res.json<{ dry_run: boolean }>();
    expect(body.dry_run).toBe(true);
  });
});
