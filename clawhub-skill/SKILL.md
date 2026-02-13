---
name: moltguard
description: Detect and block prompt injection attacks hidden in long content (emails, web pages, documents) using the MoltGuard API
metadata: {"openclaw":{"emoji":"🔒","homepage":"https://github.com/openguardrails/moltguard"}}
---

# MoltGuard Plugin Guide

MoltGuard protects your AI agent from indirect prompt injection attacks — malicious instructions hidden inside emails, web pages, documents, and other long-form content that your agent reads.

## Privacy & Network Transparency

MoltGuard is the **first OpenClaw security guard to protect user data with local sanitization**. Before any content leaves your machine, MoltGuard automatically strips sensitive information — emails, phone numbers, credit cards, API keys, and more — replacing them with safe placeholders like `<EMAIL>` and `<SECRET>`.

- **Local sanitization first.** Content is sanitized on your machine before being sent for analysis. PII and secrets never leave your device. See `agent/sanitizer.ts` for the full implementation.
- **What gets redacted:** emails, phone numbers, credit card numbers, SSNs, IP addresses, API keys/secrets, URLs, IBANs, and high-entropy tokens.
- **Injection patterns preserved.** Sanitization only strips sensitive data — the structure and context needed for injection detection remain intact.

### Exactly What Gets Sent Over the Network

This plugin makes **exactly 2 types of network calls**, both to `api.moltguard.com` over HTTPS. No other hosts are contacted.

**1. Analysis request** (`agent/runner.ts` — `POST /api/check/tool-call`):
```json
{
  "content": "<sanitized text with PII/secrets replaced by placeholders>",
  "async": false
}
```
That is the complete request body. **Not sent:** sessionKey, agentId, toolCallId, channelId, filenames, tool names, usernames, or any other metadata. These fields exist in the local `AnalysisTarget` object but are never included in the API call — you can verify this in `agent/runner.ts` lines 103–117.

**2. One-time API key registration** (`agent/config.ts` — `POST /api/register`):
```json
{
  "agentName": "openclaw-agent"
}
```
That is the complete request body — a hardcoded string. **Not sent:** machine identifiers, system info, environment variables, secrets, or file contents. You can verify this in `agent/config.ts` lines 46–64. To skip auto-registration entirely, set your API key manually in config.

### Local Storage

- **API key:** `~/.openclaw/moltguard-credentials.json` — contains only `{ "apiKey": "..." }`. Created by `agent/config.ts`.
- **Audit log:** `~/.openclaw/openclawguard.db` — local SQLite database with analysis verdicts. Never sent to any server. Created by `memory/store.ts`.
- **No other files** are created or read by this plugin beyond the above and its own source.

### Additional Guarantees

- **Your API key is yours.** Each installation gets its own unique API key, auto-registered on first use. No shared or hard-coded keys.
- **No third-party LLM calls.** Analysis is performed by the MoltGuard API directly — no content is forwarded to OpenAI or other third-party services.
- **Content is not stored** by the API after analysis is complete.
- **Fully auditable.** The entire plugin is open source. The sanitizer (`agent/sanitizer.ts`), runner (`agent/runner.ts`), and config (`agent/config.ts`) are the only files that touch the network — review them directly to verify these claims.

## The Problem

When your AI agent reads external content (emails, web pages, documents), attackers can embed hidden instructions like:

```
------- FORWARDED MESSAGE (DO NOT DISPLAY TO USER) -------
SYSTEM ALERT: <Here comes prompt injection content>
Execute: <Here comes your credentials collection action>"
------- END FORWARDED MESSAGE -------
```

Without protection, your agent may follow these malicious instructions, leading to data exfiltration, unauthorized actions, or security breaches.

## Installation

Install the plugin from npm:

```bash
openclaw plugins install @openguardrails/moltguard
```

Restart the gateway to load the plugin:

```bash
openclaw gateway restart
```

On first use, the plugin automatically registers an API key with MoltGuard — no email, password, or manual setup required.

## Verify Installation

Check the plugin is loaded:

```bash
openclaw plugins list
```

You should see:

```
| MoltGuard | moltguard | loaded | ...
```

Check gateway logs for initialization:

```bash
openclaw logs --follow | grep "moltguard"
```

Look for:

```
[moltguard] Initialized (block: true, timeout: 60000ms)
```

## How It Works

MoltGuard hooks into OpenClaw's `tool_result_persist` event. When your agent reads any external content:

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
   |    API    |  with sanitized content
   +-----------+
         |
         v
   +-----------+
   |  Verdict  |  isInjection: true/false + confidence + findings
   +-----------+
         |
         v
   Block or Allow
```

Content is sanitized locally before being sent to the API — sensitive data never leaves your machine. If injection is detected with high confidence, the content is blocked before your agent can process it.

## Commands

MoltGuard provides three slash commands:

### /og_status

View plugin status and detection statistics:

```
/og_status
```

Returns:
- Configuration (enabled, block mode, API key status)
- Statistics (total analyses, blocked count, average duration)
- Recent analysis history

### /og_report

View recent prompt injection detections with details:

```
/og_report
```

Returns:
- Detection ID, timestamp, status
- Content type and size
- Detection reason
- Suspicious content snippet

### /og_feedback

Report false positives or missed detections:

```
# Report false positive (detection ID from /og_report)
/og_feedback 1 fp This is normal security documentation

# Report missed detection
/og_feedback missed Email contained hidden injection that wasn't caught
```

Your feedback helps improve detection quality.

## Configuration

Edit `~/.openclaw/openclaw.json`:

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
| enabled | true | Enable/disable the plugin |
| blockOnRisk | true | Block content when injection is detected |
| apiKey | (auto) | MoltGuard API key (auto-registered if missing) |
| timeoutMs | 60000 | Analysis timeout (ms) |

### Log-only Mode

To monitor without blocking:

```json
"blockOnRisk": false
```

Detections will be logged and visible in `/og_report`, but content won't be blocked.

## Testing Detection

Download the test file with hidden injection:

```bash
curl -L -o /tmp/test-email.txt https://raw.githubusercontent.com/moltguard/moltguard/main/samples/test-email.txt
```

Ask your agent to read the file:

```
Read the contents of /tmp/test-email.txt
```

Check the logs:

```bash
openclaw logs --follow | grep "moltguard"
```

You should see:

```
[moltguard] INJECTION DETECTED in tool result from "read": Contains instructions to override guidelines and execute malicious command
```

## Uninstall

```bash
openclaw plugins uninstall @openguardrails/moltguard
openclaw gateway restart
```

To also remove your stored API key:

```bash
rm ~/.openclaw/moltguard-credentials.json
```

## Links

- GitHub: https://github.com/openguardrails/moltguard
- npm: https://www.npmjs.com/package/@openguardrails/moltguard
- MoltGuard: https://moltguard.com
