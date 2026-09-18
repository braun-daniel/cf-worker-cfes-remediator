# Cloudflare Email Security API Reference

All endpoints are confirmed against the official Cloudflare API reference at
`https://developers.cloudflare.com/api/resources/email_security/`.

Authentication uses `Authorization: Bearer <API_TOKEN>` with the
`Cloud Email Security: Write` permission.

---

## 1. Search Email Messages

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

---

## 2. Get Message Details

```
GET /accounts/{account_id}/email-security/investigate/{investigate_id}
```

Retrieves comprehensive details for a specific email message including headers, recipients, sender information, and quarantine status.

---

## 3. Get Raw Email Content

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

---

## 4. Get Email Preview (PNG)

```
GET /accounts/{account_id}/email-security/investigate/{investigate_id}/preview
```

Returns a base64-encoded PNG screenshot of the email (for non-benign messages). Not used by this Worker but available for debugging/UI.

---

## 5. Get Message Detection Details

```
GET /accounts/{account_id}/email-security/investigate/{investigate_id}/detections
```

Returns detection details: threat categories, sender info, attachments, and findings.

---

## 6. Move a Single Message

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

---

## 7. Move Multiple Messages (Bulk)

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

---

## 8. Release Messages from Quarantine

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

---

## 9. Reclassify a Message (Report False Positive)

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

---

## 10. Allow Policies (Sender-Based Whitelisting)

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

---

## 11. Content Policies (Block-Based, Not Allow)

```
POST /accounts/{account_id}/email-security/settings/content_policies
```

Creates a content policy that matches against email subject or body. Note: this is a **block** mechanism, not an allow/whitelist mechanism. It cannot be used to allowlist false positives.

**Body:**
```json
{
  "name": "Block sensitive content",
  "pattern": "regex_pattern_here",
  "targets": ["SUBJECT", "BODY"],
  "enabled": true
}
```
