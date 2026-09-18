# Cloudflare Email Security False-Positive Remediator

A scheduled Cloudflare Worker that automatically detects and remediates false-positive email flags in Cloudflare Email Security (formerly Area 1). It searches for messages with specific dispositions, fetches their raw content, tests against user-defined regex patterns, and moves matching messages back to the inbox (or releases them from quarantine).

## Problem

Cloudflare Email Security does not provide a mechanism to whitelist emails based on **content**. When legitimate emails from different senders are incorrectly flagged (false positives), there is no built-in way to say "if an email contains this content pattern, it is safe." This Worker fills that gap.

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│  Cron Trigger (every 5 min)                                  │
│                                                              │
│  1. SEARCH  → GET /email-security/investigate                │
│     Filter by disposition (MALICIOUS, SUSPICIOUS, SPOOF...)  │
│     Time window: last N minutes                              │
│                                                              │
│  2. FETCH   → GET /email-security/investigate/{id}/raw       │
│     Get raw EML content for each flagged message              │
│                                                              │
│  3. MATCH   → Test raw EML against user-defined regex        │
│     If pattern matches → likely false positive                │
│                                                              │
│  4. REMEDIATE                                                │
│     ├─ Quarantined? → POST /email-security/investigate/release │
│     └─ Moved/Other?  → POST /email-security/investigate/move  │
│                        (destination: Inbox)                    │
│                                                              │
│  5. RECLASSIFY (optional)                                     │
│     POST /email-security/investigate/{id}/reclassify         │
│     Reports false positive to train the ML model             │
│                                                              │
│  6. DEDUP → KV stores processed message IDs (7-day TTL)     │
└─────────────────────────────────────────────────────────────┘
```

## API Reference

See [docs/api.md](docs/api.md) for the full list of Cloudflare Email Security endpoints used by this Worker.

## Setup

### Prerequisites

1. Cloudflare account with Email Security (CES) subscription
2. Active integration with your mail platform (Microsoft 365 Graph API or Google Workspace BCC) for move/release operations to work
3. A Cloudflare API token with `Cloud Email Security: Write` permission
4. Node.js 18+ and npm

### Step 1: Clone and Install

```bash
cd email-security-fp-remediator
npm install
```

### Step 2: Create KV Namespace

```bash
npx wrangler kv namespace create FP_REMEDIATOR_KV
```

Copy the returned namespace ID into `wrangler.toml` under `[[kv_namespaces]]`.

### Step 3: Configure wrangler.toml

Edit `wrangler.toml` and set:

- `CF_ACCOUNT_ID`: Your Cloudflare account ID (find in the Cloudflare dashboard)
- `CONTENT_PATTERNS`: JSON array of regex patterns. Example:
  ```toml
  CONTENT_PATTERNS = '["X-Internal-Tool: monthly-report", "Project-Codename: Phoenix"]'
  ```
- `TARGET_DISPOSITIONS`: Which dispositions to search. Default: `["MALICIOUS","SUSPICIOUS","SPOOF"]`
- `LOOKBACK_MINUTES`: Search window. Should match or slightly exceed the cron interval (default: `"5"`)
- `RECLASSIFY_FP`: `"true"` to also submit false-positive reports to train the ML model
- `MAX_MESSAGES_PER_RUN`: Safety cap (default: `"100"`)
- `DRY_RUN`: `"true"` to scan and log matches without executing any write API calls (move, release, reclassify). KV dedup is also skipped so the same messages appear on every run. Use this to validate patterns before going live.

### Step 4: Set API Token Secret

```bash
npx wrangler secret put CF_API_TOKEN
# Paste your Cloudflare API token
```

### Step 5: Deploy

```bash
npx wrangler deploy
```

### Step 6: Verify

The Worker exposes two HTTP endpoints:

```bash
# Health check
curl https://your-worker.your-subdomain.workers.dev/health

# Manual trigger (for testing)
curl -X POST https://your-worker.your-subdomain.workers.dev/trigger
```

Check `npx wrangler tail` for run logs.

## Configuration Reference

| Variable | Type | Default | Description |
|---|---|---|---|
| `CF_API_TOKEN` | secret | required | Cloudflare API token with Email Security Write permission |
| `CF_ACCOUNT_ID` | var | required | Cloudflare account ID |
| `CONTENT_PATTERNS` | var (JSON) | `[]` | Array of regex strings to match against raw EML |
| `TARGET_DISPOSITIONS` | var (JSON) | `["MALICIOUS","SUSPICIOUS","SPOOF"]` | Dispositions to search |
| `LOOKBACK_MINUTES` | var (string) | `"5"` | Search lookback window in minutes |
| `RECLASSIFY_FP` | var (string) | `"true"` | Also submit false-positive reclassification |
| `MAX_MESSAGES_PER_RUN` | var (string) | `"100"` | Max messages to scan per run |
| `DRY_RUN` | var (string) | `"false"` | Scan and log matches without any write API calls or KV writes |
| Cron schedule | wrangler.toml | `*/5 * * * *` | Every 5 minutes |

## Disposition Values

Cloudflare Email Security assigns one of these dispositions to each scanned message:

| Disposition | Meaning |
|---|---|
| `MALICIOUS` | Confirmed malicious (phishing, malware) |
| `SUSPICIOUS` | Likely malicious but lower confidence |
| `SPOOF` | Sender identity spoofed |
| `SPAM` | Spam content |
| `BULK` | Bulk/marketing email |
| `NONE` | Benign, no threat detected |

## Security Considerations

### Content Patterns Are Not an Authorization Signal

**Content patterns are not a security boundary.** They are a convenience filter for reducing false positives on known-safe content, but they carry a fundamental limitation:

> An attacker who controls an email's content can craft a message that matches a configured pattern, including those that reference internal project names, sender headers, or body text. If that email is also classified as `MALICIOUS`, `SUSPICIOUS`, or `SPOOF`, this Worker will release and reclassify it as benign.

This design is intentional — there is no Cloudflare API mechanism to whitelist messages based on content, and this Worker works around that gap. That said, you must understand and accept this trade-off before deploying.

**Risk mitigation guidelines:**

- Keep patterns as specific and unique as possible. Avoid patterns that common phrases or header values an external sender can guess or reproduce.
- Use `TARGET_DISPOSITIONS` to limit remediation to the lowest-risk dispositions for your environment (e.g., `["SPAM","BULK"]` instead of including `MALICIOUS`).
- Enable `DRY_RUN = "true"` and audit matched messages before enabling live remediation.
- Combine with Cloudflare Email Security's sender-based allow policies (`allow_policies` API) for known-benign senders, so patterns do not need to be the sole control.
- Monitor the summary log after each run. An unexpected spike in `matched` count may indicate a malicious email is exploiting a pattern.
- Rotate or update patterns if you have reason to believe the pattern set has been exposed.

### No HTTP Trigger Endpoint

This Worker exposes only a `/health` endpoint. There is no `/trigger` endpoint. The scheduled handler is invoked exclusively by the Wrangler cron schedule configured in `wrangler.toml`. To test the Worker manually during development, use:

```bash
npx wrangler dev
# Then in a separate terminal:
curl "http://localhost:8787/__scheduled?cron=*+*+*+*+*"
```

Or for production debugging, use `wrangler tail` to stream live logs:

```bash
npx wrangler tail
```

## Important Notes

### Move vs Release

The Worker checks the `is_quarantined` field on each message:
- **Quarantined** messages use the `/release` endpoint, which delivers the message to its original recipients
- **Non-quarantined** (e.g., moved to junk) messages use the `/move` endpoint with `destination: "Inbox"`

Both require an active integration with the mail platform (Microsoft Graph API for M365, BCC for Google Workspace).

### Content Matching Scope

The regex patterns are tested against the **full raw EML**, which includes headers and body. This means you can match on:
- Subject lines: `Subject:.*Monthly Report`
- Header patterns: `X-Custom-Header:.*internal`
- Body content: `Project Phoenix Q3 Summary`
- Sender patterns in headers: `From:.*@trusted-domain\.com`

### KV Dedup

Processed message IDs are stored in KV with a 7-day TTL. This prevents reprocessing the same message across overlapping search windows and limits cost. The 1-minute overlap buffer in the lookback window ensures messages near the boundary are not missed.

### Dry-Run Mode

Set `DRY_RUN = "true"` to run the full scan pipeline without making any write API calls. In this mode:

- `move`, `release`, and `reclassify` API calls are **skipped entirely**.
- **KV dedup writes are skipped** — the same messages will appear on every run, so you can iterate on patterns without consuming your dedup budget.
- Each matched message is logged with a `[DRY RUN — would remediate]` suffix.
- The summary line is tagged `[DRY RUN]`.
- The `/health` and `/trigger` HTTP responses include `"dry_run": true`.

This is the recommended way to validate new `CONTENT_PATTERNS` before enabling live remediation.

### Reclassification

When `RECLASSIFY_FP` is `"true"`, the Worker submits a reclassification with `expected_disposition: "NONE"` for each matched message. This tells Cloudflare's ML model that the message was a false positive, which helps improve future detection accuracy. The reclassification is processed asynchronously.

### Limitations

1. **Raw EML availability**: The `/raw` endpoint only works for non-benign messages. Messages already classified as `NONE` do not have raw content available (but you would not be searching for those anyway).

2. **Rate limits**: The Cloudflare API has rate limits. The Worker processes messages sequentially within each search batch and batches move/release operations. If you need higher throughput, increase `MAX_MESSAGES_PER_RUN` gradually and monitor for 429 responses.

3. **Integration dependency**: Move and release operations require an active mail platform integration. If the integration is not configured, these API calls will fail. Ensure your CES deployment uses Graph API (M365) or BCC (Google Workspace) in post-delivery mode.

4. **Content policies are block-only**: The Cloudflare content_policies API creates block rules, not allow rules. It cannot be used to whitelist false positives based on content. This Worker is the workaround for that gap.

## File Structure

```
email-security-fp-remediator/
├── src/
│   └── index.ts          # Worker source (all API calls + scheduled handler)
├── package.json
├── wrangler.toml         # Configuration, KV binding, cron schedule, vars
├── tsconfig.json
└── README.md             # This file
```
