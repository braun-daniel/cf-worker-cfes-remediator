/**
 * Cloudflare Email Security False-Positive Remediator
 *
 * A scheduled Worker that:
 *  1. Searches Cloudflare Email Security for messages matching a target disposition
 *  2. Fetches the raw EML content of each matched message
 *  3. Tests the content against user-defined regex patterns
 *  4. If a pattern matches (likely false positive):
 *     a. Moves the message back to Inbox (or releases from quarantine)
 *     b. Optionally submits a reclassification to train the ML model
 *  5. Tracks processed message IDs in KV to avoid duplicate work
 *
 * All API endpoints are confirmed against the official Cloudflare API reference:
 *   https://developers.cloudflare.com/api/resources/email_security/
 *
 * Required bindings (wrangler.toml):
 *   - KV namespace: FP_REMEDIATOR_KV  (dedup store)
 *   - Secret: CF_API_TOKEN            (Cloudflare API token with Email Security Write permission)
 *   - Var:   CF_ACCOUNT_ID            (Cloudflare account ID)
 *   - Var:   CONTENT_PATTERNS          (JSON array of regex strings to match against email content)
 *   - Var:   TARGET_DISPOSITIONS      (JSON array: e.g. ["MALICIOUS","SUSPICIOUS","SPOOF","SPAM","BULK"])
 *   - Var:   LOOKBACK_MINUTES         (string number: how far back to search, default "5")
 *   - Var:   RECLASSIFY_FP            ("true" to also submit reclassification, default "false")
 *   - Var:   MAX_MESSAGES_PER_RUN     (string number: safety cap, default "100")
 */

export interface Env {
  FP_REMEDIATOR_KV: KVNamespace;
  CF_API_TOKEN: string;
  CF_ACCOUNT_ID: string;
  CONTENT_PATTERNS: string;
  TARGET_DISPOSITIONS: string;
  LOOKBACK_MINUTES: string;
  RECLASSIFY_FP: string;
  MAX_MESSAGES_PER_RUN: string;
}

// ─── Types from the Cloudflare Email Security API ───────────────────────────

interface InvestigateListResponse {
  id: string;
  postfix_id: string;
  is_quarantined: boolean;
  is_phish_submission: boolean;
  client_recipients: string[];
  detection_reasons: string[];
  subject?: string;
  sender?: string;
  from_address?: string;
  final_disposition?: string;
  delivery_status?: string;
  properties?: {
    allowlisted_pattern?: string;
    allowlisted_pattern_type?: string;
    blocklisted_message?: boolean;
    [key: string]: unknown;
  };
  action_log?: Array<{
    operation: string;
    completed_at: string;
    status?: string;
    properties?: { folder?: string; requested_by?: string };
  }>;
}

interface ApiResponse<T> {
  result?: T;
  results?: T;
  errors?: Array<{ code: number; message: string; documentation_url?: string }>;
  messages?: Array<{ code: number; message: string }>;
  success?: boolean;
  result_info?: {
    cursor?: string;
    count?: number;
    per_page?: number;
    total_count?: number;
    cursors?: { before?: string; after?: string };
  };
}

export type Disposition = "MALICIOUS" | "SUSPICIOUS" | "SPOOF" | "SPAM" | "BULK" | "NONE";

export type MoveDestination = "Inbox" | "JunkEmail" | "DeletedItems" | "RecoverableItemsDeletions" | "RecoverableItemsPurges";

export type ReclassifyDisposition = "NONE" | "BULK" | "MALICIOUS" | "SPAM" | "SPOOF" | "SUSPICIOUS";

// ─── API client ──────────────────────────────────────────────────────────────

const API_BASE = "https://api.cloudflare.com/client/v4";

export function authHeaders(token: string): HeadersInit {
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };
}

/**
 * Search email messages.
 * GET /accounts/{account_id}/email-security/investigate
 *
 * Query params (confirmed from API docs):
 *   - final_disposition: MALICIOUS | SUSPICIOUS | SPOOF | SPAM | BULK | NONE
 *   - delivery_status:   delivered | moved | quarantined | rejected | deferred | bounced | queued | move_failed
 *   - domain:             sender domain filter
 *   - start / end:        ISO 8601 date range
 *   - cursor:             pagination cursor
 *   - detections_only:    boolean
 *   - message_action:     PREVIEW | QUARANTINE_RELEASED | MOVED
 */
export async function searchMessages(
  env: Env,
  params: {
    disposition?: Disposition;
    deliveryStatus?: string;
    start?: string;
    end?: string;
    cursor?: string;
    domain?: string;
  },
): Promise<{ messages: InvestigateListResponse[]; cursor?: string }> {
  const url = new URL(`${API_BASE}/accounts/${env.CF_ACCOUNT_ID}/email-security/investigate`);
  if (params.disposition) url.searchParams.set("final_disposition", params.disposition);
  if (params.deliveryStatus) url.searchParams.set("delivery_status", params.deliveryStatus);
  if (params.start) url.searchParams.set("start", params.start);
  if (params.end) url.searchParams.set("end", params.end);
  if (params.cursor) url.searchParams.set("cursor", params.cursor);
  if (params.domain) url.searchParams.set("domain", params.domain);

  const res = await fetch(url.toString(), {
    headers: authHeaders(env.CF_API_TOKEN),
    method: "GET",
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`searchMessages HTTP ${res.status}: ${body}`);
  }

  const data: ApiResponse<InvestigateListResponse[]> = await res.json();

  if (data.errors && data.errors.length > 0) {
    throw new Error(`searchMessages API errors: ${JSON.stringify(data.errors)}`);
  }

  const messages = data.result ?? data.results ?? [];
  const nextCursor = data.result_info?.cursor ?? data.result_info?.cursors?.after;
  return { messages, cursor: nextCursor };
}

/**
 * Get raw email content (EML).
 * GET /accounts/{account_id}/email-security/investigate/{investigate_id}/raw
 * Returns: { result: { raw: "<UTF-8 EML string>" } }
 */
export async function getRawEmail(env: Env, investigateId: string): Promise<string> {
  const url = `${API_BASE}/accounts/${env.CF_ACCOUNT_ID}/email-security/investigate/${investigateId}/raw`;
  const res = await fetch(url, { headers: authHeaders(env.CF_API_TOKEN), method: "GET" });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`getRawEmail HTTP ${res.status}: ${body}`);
  }

  const data: ApiResponse<{ raw: string }> = await res.json();
  if (data.errors && data.errors.length > 0) {
    throw new Error(`getRawEmail API errors: ${JSON.stringify(data.errors)}`);
  }
  return data.result?.raw ?? "";
}

/**
 * Move a single message to a destination folder.
 * POST /accounts/{account_id}/email-security/investigate/{investigate_id}/move
 * Body: { destination: "Inbox" | "JunkEmail" | "DeletedItems" | ... }
 */
export async function moveMessage(env: Env, investigateId: string, destination: MoveDestination): Promise<boolean> {
  const url = `${API_BASE}/accounts/${env.CF_ACCOUNT_ID}/email-security/investigate/${investigateId}/move`;
  const res = await fetch(url, {
    headers: authHeaders(env.CF_API_TOKEN),
    method: "POST",
    body: JSON.stringify({ destination }),
  });

  if (!res.ok) {
    const body = await res.text();
    console.error(`moveMessage failed for ${investigateId}: HTTP ${res.status}: ${body}`);
    return false;
  }
  const data: ApiResponse<unknown> = await res.json();
  return data.success ?? false;
}

/**
 * Move multiple messages in one request (bulk).
 * POST /accounts/{account_id}/email-security/investigate/move
 * Body: { destination: "Inbox", ids: ["id1","id2",...] }
 */
export async function moveMessagesBulk(env: Env, ids: string[], destination: MoveDestination): Promise<{ moved: string[]; failed: string[] }> {
  const url = `${API_BASE}/accounts/${env.CF_ACCOUNT_ID}/email-security/investigate/move`;
  const res = await fetch(url, {
    headers: authHeaders(env.CF_API_TOKEN),
    method: "POST",
    body: JSON.stringify({ destination, ids }),
  });

  if (!res.ok) {
    const body = await res.text();
    console.error(`moveMessagesBulk HTTP ${res.status}: ${body}`);
    return { moved: [], failed: ids };
  }

  const data: ApiResponse<Array<{ id: string; status?: string }>> = await res.json();
  const results = data.result ?? [];
  const moved = results.filter((r) => r.status !== "failed").map((r) => r.id);
  const failed = results.filter((r) => r.status === "failed").map((r) => r.id);
  return { moved, failed };
}

/**
 * Release messages from quarantine (bulk).
 * POST /accounts/{account_id}/email-security/investigate/release
 * Body: ["id1","id2",...]  (array of investigate IDs)
 * Returns per-message delivery status.
 */
export async function releaseFromQuarantine(env: Env, ids: string[]): Promise<{ delivered: string[]; failed: string[]; undelivered: string[] }> {
  const url = `${API_BASE}/accounts/${env.CF_ACCOUNT_ID}/email-security/investigate/release`;
  const res = await fetch(url, {
    headers: authHeaders(env.CF_API_TOKEN),
    method: "POST",
    body: JSON.stringify(ids),
  });

  if (!res.ok) {
    const body = await res.text();
    console.error(`releaseFromQuarantine HTTP ${res.status}: ${body}`);
    return { delivered: [], failed: ids, undelivered: [] };
  }

  const data: ApiResponse<Array<{ id: string; delivered?: string[]; failed?: string[]; undelivered?: string[] }>> = await res.json();
  const results = data.result ?? [];
  const delivered: string[] = [];
  const failed: string[] = [];
  const undelivered: string[] = [];

  for (const r of results) {
    if (r.delivered && r.delivered.length > 0) delivered.push(r.id);
    if (r.failed && r.failed.length > 0) failed.push(r.id);
    if (r.undelivered && r.undelivered.length > 0) undelivered.push(r.id);
  }
  return { delivered, failed, undelivered };
}

/**
 * Reclassify a message (report false positive).
 * POST /accounts/{account_id}/email-security/investigate/{investigate_id}/reclassify
 * Body: { expected_disposition: "NONE" | "BULK" | "MALICIOUS" | "SPAM" | "SPOOF" | "SUSPICIOUS" }
 * Processed asynchronously by Cloudflare's ML pipeline.
 */
export async function reclassifyMessage(env: Env, investigateId: string, expectedDisposition: ReclassifyDisposition): Promise<boolean> {
  const url = `${API_BASE}/accounts/${env.CF_ACCOUNT_ID}/email-security/investigate/${investigateId}/reclassify`;
  const res = await fetch(url, {
    headers: authHeaders(env.CF_API_TOKEN),
    method: "POST",
    body: JSON.stringify({ expected_disposition: expectedDisposition }),
  });

  if (!res.ok) {
    const body = await res.text();
    console.error(`reclassifyMessage failed for ${investigateId}: HTTP ${res.status}: ${body}`);
    return false;
  }
  const data: ApiResponse<unknown> = await res.json();
  return data.success ?? false;
}

// ─── Content matching ───────────────────────────────────────────────────────

export function parsePatterns(jsonStr: string): RegExp[] {
  try {
    const arr = JSON.parse(jsonStr) as string[];
    return arr.map((p) => new RegExp(p, "i"));
  } catch (err) {
    console.error("Failed to parse CONTENT_PATTERNS:", err);
    return [];
  }
}

export function parseDispositions(jsonStr: string): Disposition[] {
  try {
    return JSON.parse(jsonStr) as Disposition[];
  } catch {
    return ["MALICIOUS", "SUSPICIOUS", "SPOOF"];
  }
}

export function matchesPatterns(rawEml: string, patterns: RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(rawEml));
}

// ─── KV dedup ───────────────────────────────────────────────────────────────

const KV_TTL_SECONDS = 7 * 24 * 60 * 60; // 7 days

export async function isProcessed(kv: KVNamespace, id: string): Promise<boolean> {
  return (await kv.get(`processed:${id}`)) !== null;
}

export async function markProcessed(kv: KVNamespace, id: string): Promise<void> {
  await kv.put(`processed:${id}`, new Date().toISOString(), { expirationTtl: KV_TTL_SECONDS });
}

// ─── Main scheduled handler ─────────────────────────────────────────────────

export default {
  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    const startTime = Date.now();
    console.log(`[FP Remediator] Run started at ${new Date().toISOString()}`);

    const patterns = parsePatterns(env.CONTENT_PATTERNS ?? "[]");
    const dispositions = parseDispositions(env.TARGET_DISPOSITIONS ?? '["MALICIOUS","SUSPICIOUS","SPOOF"]');
    const lookbackMinutes = parseInt(env.LOOKBACK_MINUTES ?? "5", 10);
    const reclassifyFp = env.RECLASSIFY_FP === "true";
    const maxMessages = parseInt(env.MAX_MESSAGES_PER_RUN ?? "100", 10);

    if (patterns.length === 0) {
      console.warn("[FP Remediator] No content patterns configured. Skipping run.");
      return;
    }
    if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) {
      console.error("[FP Remediator] Missing CF_API_TOKEN or CF_ACCOUNT_ID. Skipping run.");
      return;
    }

    const now = new Date();
    const lookbackStart = new Date(now.getTime() - lookbackMinutes * 60 * 1000 - 60_000);

    let totalScanned = 0, totalMatched = 0, totalMoved = 0, totalReleased = 0;
    let totalReclassified = 0, totalSkipped = 0, totalErrors = 0;

    const toMove: string[] = [];
    const toRelease: string[] = [];
    const toReclassify: string[] = [];

    for (const disposition of dispositions) {
      let cursor: string | undefined;
      let hasMore = true;

      while (hasMore && totalScanned < maxMessages) {
        let searchResult: { messages: InvestigateListResponse[]; cursor?: string };
        try {
          searchResult = await searchMessages(env, { disposition, start: lookbackStart.toISOString(), end: now.toISOString(), cursor });
        } catch (err) {
          console.error(`[FP Remediator] Search failed for ${disposition}:`, err);
          totalErrors++;
          break;
        }

        const { messages, cursor: nextCursor } = searchResult;
        hasMore = !!nextCursor;
        cursor = nextCursor;

        for (const msg of messages) {
          totalScanned++;
          if (totalScanned > maxMessages) { hasMore = false; break; }

          if (await isProcessed(env.FP_REMEDIATOR_KV, msg.id)) { totalSkipped++; continue; }
          if (msg.properties?.allowlisted_pattern) { totalSkipped++; continue; }

          let rawEml: string;
          try {
            rawEml = await getRawEmail(env, msg.id);
          } catch (err) {
            console.error(`[FP Remediator] Failed to fetch raw for ${msg.id}:`, err);
            totalErrors++;
            await markProcessed(env.FP_REMEDIATOR_KV, msg.id);
            continue;
          }

          if (matchesPatterns(rawEml, patterns)) {
            totalMatched++;
            console.log(`[FP Remediator] FP match: id=${msg.id}, disposition=${disposition}, sender=${msg.sender ?? msg.from_address ?? "unknown"}`);

            if (msg.is_quarantined) toRelease.push(msg.id);
            else toMove.push(msg.id);
            if (reclassifyFp) toReclassify.push(msg.id);
          }

          await markProcessed(env.FP_REMEDIATOR_KV, msg.id);
        }
      }
    }

    // Release quarantined messages (batch)
    if (toRelease.length > 0) {
      try {
        const result = await releaseFromQuarantine(env, toRelease);
        totalReleased = result.delivered.length;
        if (result.failed.length > 0) console.error(`[FP Remediator] Release failed for ${result.failed.length} messages`);
        if (result.undelivered.length > 0) console.warn(`[FP Remediator] Undelivered: ${result.undelivered.length}`);
      } catch (err) { console.error("[FP Remediator] Release batch failed:", err); totalErrors++; }
    }

    // Move non-quarantined messages to Inbox (batch)
    if (toMove.length > 0) {
      try {
        const result = await moveMessagesBulk(env, toMove, "Inbox");
        totalMoved = result.moved.length;
        if (result.failed.length > 0) console.error(`[FP Remediator] Move failed for ${result.failed.length} messages`);
      } catch (err) { console.error("[FP Remediator] Move batch failed:", err); totalErrors++; }
    }

    // Reclassify (individual calls, async on API side)
    if (toReclassify.length > 0) {
      const promises = toReclassify.map((id) =>
        reclassifyMessage(env, id, "NONE").then((ok) => { if (ok) totalReclassified++; }).catch((err) => { console.error(`[FP Remediator] Reclassify failed for ${id}:`, err); totalErrors++; }),
      );
      await Promise.all(promises);
    }

    const elapsed = Date.now() - startTime;
    console.log(`[FP Remediator] Run complete in ${elapsed}ms: scanned=${totalScanned}, matched=${totalMatched}, moved=${totalMoved}, released=${totalReleased}, reclassified=${totalReclassified}, skipped=${totalSkipped}, errors=${totalErrors}`);
  },

  // Optional HTTP endpoint for manual trigger / health check
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ status: "ok", timestamp: new Date().toISOString() }), { headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname === "/trigger" && request.method === "POST") {
      console.log("[FP Remediator] Manual trigger received");
      try {
        await this.scheduled({} as ScheduledController, env, {} as ExecutionContext);
        return new Response(JSON.stringify({ status: "triggered", timestamp: new Date().toISOString() }), { headers: { "Content-Type": "application/json" } });
      } catch (err) {
        return new Response(JSON.stringify({ error: String(err) }), { status: 500, headers: { "Content-Type": "application/json" } });
      }
    }

    return new Response("Not found", { status: 404 });
  },
};
