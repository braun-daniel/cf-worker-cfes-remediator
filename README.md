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

## Confirmed Cloudflare Email Security API Endpoints

All endpoints below are confirmed against the official Cloudflare API reference at `https://developers.cloudflare.com/api/resources/email_security/`. Authentication uses `Authorization: Bearer <API_TOKEN>` with the `Cloud Email Security: Write` permission.

### 1. Search Email Messages

```
GET /accounts/{account_id}/email-security/investigate
```

Returns information for each email matching the search parameters.

**Key query parameters:**

| Parameter | Type | Values |
|---|---|---|
| `final_disposition` | string | `MALICIOUS`, `SUSPICIOUS`, `SPOOF`, `SPAM`, `BULK`, `NONE` |
| `delivery_status` | string | `delivered`, `moved`, `quarantined`, `rejected`, `deferred`, `bounced`, `queued`, `move_failed` |
| `start` / `end` | string (ISO 8601) | Date range for search; `end` defaults to now |
| `cursor` | string | Pagination cursor |
| `domain` | string | Sender domain filter |
| `detections_only` | boolean | Include only detections |
| `message_action` | string | `PREVIEW`, `QUARANTINE_RELEASED`, `MOVED` |

**Response (per message):**
```json
{
  "id": "4Njp3P0STMz2c02Q-2024-01-05T10:00:00-12345678",
  "postfix_id": "4Njp3P0STMz2c02Q",
  "is_quarantined": false,
  "is_phish_submission": false,
  "client_recipients": ["user@example.com"],
  "detection_reasons": ["..."],
  "subject": "...",
  "sender": "sender@example.com",
  "final_disposition": "MALICIOUS",
  "delivery_status": "moved",
  "properties": {
    "allowlisted_pattern": null,
    "allowlisted_pattern_type": null,
    "blocklisted_message": false
  }
}
```

### 2. Get Message Details

```
GET /accounts/{account_id}/email-security/investigate/{investigate_id}
```

Retrieves comprehensive details for a specific email message including headers, recipients, sender information, and quarantine status.

### 3. Get Raw Email Content

```
GET /accounts/{account_id}/email-security/investigate/{investigate_id}/raw
```

Returns the raw EML of any non-benign message as a UTF-8 string. This is what the Worker uses for content matching.

**Response:**
```json
{
  "result": { "raw": "<UTF-8 encoded EML string>" },
  "success": true
}
```

### 4. Get Email Preview (PNG)

```
GET /accounts/{account_id}/email-security/investigate/{investigate_id}/preview
```

Returns a base64-encoded PNG screenshot of the email (for non-benign messages). Not used by this Worker but available for debugging/UI.

### 5. Get Message Detection Details

```
GET /accounts/{account_id}/email-security/investigate/{investigate_id}/detections
```

Returns detection details: threat categories, sender info, attachments, and findings.

### 6. Move a Single Message

```
POST /accounts/{account_id}/email-security/investigate/{investigate_id}/move
```

Moves a single message to a specified mailbox folder. Requires active integration (e.g., Microsoft Graph API for M365).

**Body:**
```json
{
  "destination": "Inbox",
  "expected_disposition": "NONE"
}
```

**Destination values:** `Inbox`, `JunkEmail`, `DeletedItems`, `RecoverableItemsDeletions`, `RecoverableItemsPurges`

### 7. Move Multiple Messages (Bulk)

```
POST /accounts/{account_id}/email-security/investigate/move
```

**Body:**
```json
{
  "destination": "Inbox",
  "ids": ["id1", "id2", "id3"]
}
```

This is the bulk variant the Worker uses for efficiency.

### 8. Release Messages from Quarantine

```
POST /accounts/{account_id}/email-security/investigate/release
```

Delivers one or more quarantined messages to their intended recipients. Use this when `is_quarantined: true` on the message.

**Body:** (array of investigate IDs, not an object)
```json
["4Njp3P0STMz2c02Q-2024-01-05T10:00:00-12345678"]
```

**Response:**
```json
{
  "result": [
    {
      "id": "4Njp3P0STMz2c02Q-...",
      "delivered": ["user@example.com"],
      "failed": [],
      "undelivered": []
    }
  ],
  "success": true
}
```

### 9. Reclassify a Message (Report False Positive)

```
POST /accounts/{account_id}/email-security/investigate/{investigate_id}/reclassify
```

Submits a request to reclassify an email's disposition. Use for reporting false positives or false negatives. The reclassification is processed asynchronously by Cloudflare's ML pipeline.

**Body:**
```json
{
  "expected_disposition": "NONE"
}
```

**Reclassify disposition values:** `NONE`, `BULK`, `MALICIOUS`, `SPAM`, `SPOOF`, `SUSPICIOUS`

### 10. Allow Policies (Alternative: Sender-Based Whitelisting)

```
POST /accounts/{account_id}/email-security/settings/allow_policies
```

Creates a sender-based allow policy. This is NOT content-based but can complement this Worker for known-benign senders.

**Body:**
```json
{
  "pattern": "trusted-sender@example.com",
  "pattern_type": "EMAIL",
  "is_trusted_sender": true,
  "verify_sender": true,
  "is_acceptable_sender": false,
  "is_exempt_recipient": false,
  "is_regex": false
}
```

Pattern types: `EMAIL`, `DOMAIN`, `IP`. The `is_trusted_sender` flag bypasses ALL detections including link following; `is_acceptable_sender` only bypasses Spam/Spoof/Bulk but not Malicious/Suspicious.

### 11. Content Policies (Block-Based, Not Allow)

```
POST /accounts/{account_id}/email-security/settings/content_policies
```

Creates a content policy that matches against email subject or body. Note: this is a **block** mechanism, not an allow/whitelist mechanism. Emails matching the pattern are subject to the configured action (block). It cannot be used to allowlist false positives, but is documented here for completeness.

**Body:**
```json
{
  "name": "Block sensitive content",
  "pattern": "regex_pattern_here",
  "targets": ["SUBJECT", "BODY"],
  "enabled": true
}
```

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
