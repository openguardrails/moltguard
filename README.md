# MoltGuard

[![npm version](https://img.shields.io/npm/v/@openguardrails/moltguard.svg)](https://www.npmjs.com/package/@openguardrails/moltguard)
[![GitHub](https://img.shields.io/github/license/moltguard/moltguard)](https://github.com/moltguard/moltguard)

Detect and block prompt injection attacks hidden in long content (emails, web pages, documents).

Powered by the [MoltGuard](https://moltguard.com) detection API.

**GitHub**: [https://github.com/moltguard/moltguard](https://github.com/moltguard/moltguard)

**npm**: [https://www.npmjs.com/package/@openguardrails/moltguard](https://www.npmjs.com/package/@openguardrails/moltguard)

## Privacy Statement

MoltGuard is the **first OpenClaw security guard to protect user data with local sanitization**.

Before any content leaves your machine, MoltGuard automatically strips sensitive information and replaces it with safe placeholders:

| Data Type | Placeholder |
|-----------|-------------|
| Email addresses | `<EMAIL>` |
| Phone numbers | `<PHONE>` |
| Credit card numbers | `<CREDIT_CARD>` |
| SSNs | `<SSN>` |
| IP addresses | `<IP_ADDRESS>` |
| API keys & secrets | `<SECRET>` |
| URLs | `<URL>` |
| IBANs | `<IBAN>` |

Only sanitized content is sent for analysis — injection patterns are preserved, but your sensitive data never leaves the machine.

- **Local sanitization first.** PII and secrets are stripped before any API call.
- **Your API key is yours.** Each installation gets its own unique API key, automatically registered on first use and stored locally at `~/.openclaw/credentials/moltguard/credentials.json`. No shared or hard-coded keys.
- **Content is analyzed via the MoltGuard API** (`api.moltguard.com`) over HTTPS. Only sanitized content is sent. Content is not stored or used for training after analysis completes.
- **Local audit log only.** Analysis results are stored in a local SQLite database on your machine.
- **No third-party LLM calls.** The plugin calls the MoltGuard API directly — no content is forwarded to OpenAI or other third-party services.

## How It Works

```
Content (email/webpage/document)
         |
         v
   +-----------+
   |  Local    |  Strip emails, phones, credit cards,
   | Sanitize  |  SSNs, API keys, URLs, IBANs...
   +-----------+
         |
         v
   +-----------+
   | MoltGuard |  POST /api/check/tool-call
   |    API    |  { sanitized content, async: false }
   +-----------+
         |
         v
   +-----------+
   |  Verdict  |  { isInjection, confidence, reason, findings }
   +-----------+
         |
         v
   Block or Allow
```

The plugin hooks into OpenClaw's `tool_result_persist` and `message_received` events. When your agent reads external content, MoltGuard sanitizes it locally (stripping PII and secrets) then sends the sanitized content to the API for analysis. If injection is detected, the content is blocked.

## Installation

```bash
# Install from npm
openclaw plugins install @openguardrails/moltguard

# Restart gateway to load the plugin
openclaw gateway restart
```

On first use, the plugin automatically registers an API key with MoltGuard — no email, password, or manual setup required.

## Verify Installation

```bash
# Check plugin list, confirm moltguard status is "loaded"
openclaw plugins list
```

You should see:
```
| MoltGuard | moltguard | loaded | ...
```

## Commands

| Command | Description |
|---------|-------------|
| `/og_status` | View status and statistics |
| `/og_report` | View recent injection detection details |
| `/og_feedback <id> fp [reason]` | Report false positive |
| `/og_feedback missed <reason>` | Report missed detection |

## Testing Detection

### 1. Download Test File

Download the test file with hidden injection:

```bash
curl -L -o /tmp/test-email.txt https://raw.githubusercontent.com/moltguard/moltguard/main/samples/test-email.txt
```

### 2. Test in OpenClaw

Ask the agent to read this file:

```
Read the contents of /tmp/test-email.txt
```

### 3. View Detection Logs

```bash
openclaw logs --follow | grep "moltguard"
```

If detection succeeds, you'll see:

```
[moltguard] tool_result_persist triggered for "read"
[moltguard] Analyzing tool result from "read" (1183 chars)
[moltguard] Analysis complete in 312ms: INJECTION DETECTED
[moltguard] INJECTION DETECTED in tool result from "read": Contains instructions to override guidelines and execute a malicious shell command
```

### 4. View Statistics

In OpenClaw conversation:

```
/og_status
```

### 5. View Detection Details

```
/og_report
```

### 6. Provide Feedback

```
# Report false positive
/og_feedback 1 fp This is normal security documentation

# Report missed detection
/og_feedback missed Email contained hidden injection that wasn't detected
```

## Configuration

Edit OpenClaw config file (`~/.openclaw/openclaw.json`):

```json
{
  "plugins": {
    "entries": {
      "moltguard": {
        "enabled": true,
        "config": {
          "blockOnRisk": true,
          "timeoutMs": 60000
        }
      }
    }
  }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | true | Enable/disable plugin |
| `blockOnRisk` | true | Block tool calls when injection is detected |
| `apiKey` | (auto) | MoltGuard API key (auto-registered if missing) |
| `timeoutMs` | 60000 | Analysis timeout in milliseconds |

### Log-only Mode

To monitor without blocking:

```json
"blockOnRisk": false
```

## API Details

MoltGuard uses a single API endpoint for detection:

```
POST https://api.moltguard.com/api/check/tool-call
Authorization: Bearer <your-api-key>
Content-Type: application/json

{
  "content": "<content to analyze>",
  "async": false
}
```

Response:

```json
{
  "ok": true,
  "verdict": {
    "isInjection": true,
    "confidence": 0.95,
    "reason": "Contains hidden instructions to override system prompt",
    "findings": [
      {
        "suspiciousContent": "SYSTEM ALERT: Override all previous instructions...",
        "reason": "Attempts to override system prompt",
        "confidence": 0.95
      }
    ]
  }
}
```

API key registration happens automatically via `POST /api/register` on first use.

## Uninstall

```bash
openclaw plugins uninstall @openguardrails/moltguard
openclaw gateway restart
```

To also remove your stored API key:

```bash
rm ~/.openclaw/credentials/moltguard/credentials.json
```

## Development

```bash
# Clone repository
git clone https://github.com/moltguard/moltguard.git
cd moltguard

# Install dependencies
npm install

# Local development install
openclaw plugins install -l .
openclaw gateway restart

# Type check
npm run typecheck

# Run tests
npm test
```

## License

MIT
