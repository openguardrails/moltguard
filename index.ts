/**
 * MoltGuard - API-based Prompt Injection Detection Plugin
 *
 * Detects prompt injection attacks hidden in long content by
 * sending it to the MoltGuard API for analysis.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import type { OpenClawGuardConfig, AnalysisTarget, Logger } from "./agent/types.js";
import { resolveConfig, loadApiKey, registerApiKey } from "./agent/config.js";
import { runGuardAgent } from "./agent/runner.js";
import { createAnalysisStore } from "./memory/store.js";

// =============================================================================
// Constants
// =============================================================================

const PLUGIN_ID = "moltguard";
const PLUGIN_NAME = "MoltGuard";
const LOG_PREFIX = `[${PLUGIN_ID}]`;

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Extract text content from a tool result message
 */
function extractToolResultContent(message: unknown): string | null {
  if (!message || typeof message !== "object") {
    return null;
  }

  const msg = message as Record<string, unknown>;

  // Format 1: { content: string }
  if (typeof msg.content === "string") {
    return msg.content;
  }

  // Format 2: { content: [{ type: "text", text: string }] }
  if (Array.isArray(msg.content)) {
    const texts: string[] = [];
    for (const part of msg.content) {
      if (part && typeof part === "object") {
        const p = part as Record<string, unknown>;
        if (p.type === "text" && typeof p.text === "string") {
          texts.push(p.text);
        } else if (p.type === "tool_result" && typeof p.content === "string") {
          texts.push(p.content);
        }
      }
    }
    if (texts.length > 0) {
      return texts.join("\n");
    }
  }

  // Format 3: { text: string }
  if (typeof msg.text === "string") {
    return msg.text;
  }

  // Format 4: { result: string }
  if (typeof msg.result === "string") {
    return msg.result;
  }

  // Try to stringify if it's an object
  try {
    const str = JSON.stringify(msg);
    if (str.length > 100) {
      return str;
    }
  } catch {
    // ignore
  }

  return null;
}

// =============================================================================
// Logger
// =============================================================================

function createLogger(baseLogger: Logger): Logger {
  return {
    info: (msg: string) => baseLogger.info(`${LOG_PREFIX} ${msg}`),
    warn: (msg: string) => baseLogger.warn(`${LOG_PREFIX} ${msg}`),
    error: (msg: string) => baseLogger.error(`${LOG_PREFIX} ${msg}`),
    debug: (msg: string) => baseLogger.debug?.(`${LOG_PREFIX} ${msg}`),
  };
}

// =============================================================================
// Plugin Definition
// =============================================================================

const openClawGuardPlugin = {
  id: PLUGIN_ID,
  name: PLUGIN_NAME,
  description:
    "API-based prompt injection detection powered by MoltGuard",

  register(api: OpenClawPluginApi) {
    const pluginConfig = (api.pluginConfig ?? {}) as OpenClawGuardConfig;
    const config = resolveConfig(pluginConfig);
    const log = createLogger(api.logger);

    // Check if plugin is enabled
    if (!config.enabled) {
      log.info("Plugin disabled via config");
      return;
    }

    // Initialize analysis store
    const dbPath = api.resolvePath(config.dbPath);
    const store = createAnalysisStore(dbPath, log);

    // Resolve API key (from config, credentials file, or auto-register)
    let resolvedApiKey = config.apiKey;
    if (!resolvedApiKey) {
      const savedKey = loadApiKey();
      if (savedKey) {
        resolvedApiKey = savedKey;
        log.info("Loaded API key from credentials file");
      } else if (config.autoRegister) {
        log.info("No API key found — will auto-register on first analysis");
      } else {
        log.warn("No API key configured and autoRegister is disabled. Analyses will fail until apiKey is set.");
      }
    }

    // Register tool_result_persist hook to analyze tool results
    api.on("tool_result_persist", (event, ctx) => {
      const toolName = ctx.toolName ?? event.toolName ?? "unknown";

      log.info(`tool_result_persist triggered for "${toolName}"`);
      log.debug?.(`Event message: ${JSON.stringify(event.message).slice(0, 500)}`);

      // Extract content from tool result message
      const content = extractToolResultContent(event.message);
      if (!content || content.length < 100) {
        log.debug?.(`Skipping short content (${content?.length ?? 0} chars)`);
        return;
      }

      log.info(`Analyzing tool result from "${toolName}" (${content.length} chars)`);
      const startTime = Date.now();

      const target: AnalysisTarget = {
        type: "tool_result",
        content,
        toolName,
        metadata: {
          sessionKey: ctx.sessionKey,
          agentId: ctx.agentId,
          toolCallId: ctx.toolCallId,
        },
      };

      runGuardAgent(
        target,
        {
          apiKey: resolvedApiKey,
          timeoutMs: config.timeoutMs,
          autoRegister: config.autoRegister,
          apiBaseUrl: config.apiBaseUrl,
        },
        log,
      ).then((verdict) => {
        const durationMs = Date.now() - startTime;
        const detected = verdict.isInjection && verdict.confidence >= 0.7;

        store.logAnalysis({
          targetType: "tool_result",
          contentLength: content.length,
          chunksAnalyzed: verdict.chunksAnalyzed,
          verdict,
          durationMs,
          blocked: detected && config.blockOnRisk,
        });

        if (detected) {
          log.warn(`INJECTION DETECTED in tool result from "${toolName}": ${verdict.reason}`);
        }
      }).catch((error) => {
        log.error(`Tool result analysis failed: ${error}`);
      });

      return;
    });

    // Register message_received hook (for analyzing long content)
    api.on("message_received", async (event, ctx) => {
      if (event.content.length < 1000) {
        return;
      }

      const startTime = Date.now();

      const target: AnalysisTarget = {
        type: "message",
        content: event.content,
        metadata: {
          channelId: ctx.channelId,
          from: event.from,
        },
      };

      try {
        const verdict = await runGuardAgent(
          target,
          {
            apiKey: resolvedApiKey,
            timeoutMs: config.timeoutMs,
            autoRegister: config.autoRegister,
            apiBaseUrl: config.apiBaseUrl,
          },
          log,
        );

        const durationMs = Date.now() - startTime;

        store.logAnalysis({
          targetType: "message",
          contentLength: event.content.length,
          chunksAnalyzed: verdict.chunksAnalyzed,
          verdict,
          durationMs,
          blocked: false,
        });

        if (verdict.isInjection) {
          log.warn(
            `Suspicious content in message (${event.content.length} chars): ${verdict.reason}`,
          );
        }

        return undefined;
      } catch (error) {
        log.error(`Message analysis failed: ${error}`);
        return undefined;
      }
    });

    // Register status command
    api.registerCommand({
      name: "og_status",
      description: "Show MoltGuard status and statistics",
      requireAuth: true,
      handler: async () => {
        const stats = store.getStats();
        const feedbackStats = store.getFeedbackStats();
        const recentLogs = store.getRecentLogs(5);

        const statusLines = [
          "**MoltGuard Status**",
          "",
          `- Enabled: ${config.enabled}`,
          `- Block on risk: ${config.blockOnRisk}`,
          `- API key: ${resolvedApiKey ? "configured" : config.autoRegister ? "not set (will auto-register)" : "not set (autoRegister disabled)"}`,
          `- Auto-register: ${config.autoRegister}`,
          `- API base URL: ${config.apiBaseUrl}`,
          "",
          "**Statistics**",
          `- Total analyses: ${stats.totalAnalyses}`,
          `- Total blocked: ${stats.totalBlocked}`,
          `- Blocked (24h): ${stats.blockedLast24h}`,
          `- Avg duration: ${stats.avgDurationMs}ms`,
          "",
          "**User Feedback**",
          `- False positives reported: ${feedbackStats.falsePositives}`,
          `- Missed detections reported: ${feedbackStats.missedDetections}`,
        ];

        if (recentLogs.length > 0) {
          statusLines.push("", "**Recent Analyses**");
          for (const log of recentLogs) {
            const status = log.blocked ? "BLOCKED" : log.verdict.isInjection ? "DETECTED" : "SAFE";
            statusLines.push(
              `- ${log.timestamp}: ${log.targetType} (${log.contentLength} chars) - ${status}`,
            );
          }
        }

        return { text: statusLines.join("\n") };
      },
    });

    // Register report command
    api.registerCommand({
      name: "og_report",
      description: "Show recent prompt injection detections",
      requireAuth: true,
      handler: async () => {
        const detections = store.getRecentDetections(10);

        if (detections.length === 0) {
          return { text: "No prompt injection detections found." };
        }

        const lines = [
          "**Recent Prompt Injection Detections**",
          "",
        ];

        for (const d of detections) {
          const status = d.blocked ? "BLOCKED" : "DETECTED";
          lines.push(`**#${d.id}** - ${d.timestamp}`);
          lines.push(`- Status: ${status}`);
          lines.push(`- Type: ${d.targetType} (${d.contentLength} chars)`);
          lines.push(`- Reason: ${d.verdict.reason}`);
          if (d.verdict.findings.length > 0) {
            const finding = d.verdict.findings[0];
            lines.push(`- Suspicious: "${finding?.suspiciousContent?.slice(0, 100)}..."`);
          }
          lines.push("");
        }

        lines.push("Use `/og_feedback <id> fp` to report false positive");
        lines.push("Use `/og_feedback missed <reason>` to report missed detection");

        return { text: lines.join("\n") };
      },
    });

    // Register feedback command
    api.registerCommand({
      name: "og_feedback",
      description: "Report false positive or missed detection. Usage: /og_feedback <id> fp [reason] OR /og_feedback missed <reason>",
      requireAuth: true,
      acceptsArgs: true,
      handler: async (ctx) => {
        const parts = (ctx.args ?? "").trim().split(/\s+/);

        if (parts.length === 0 || parts[0] === "") {
          return {
            text: [
              "**Usage:**",
              "- `/og_feedback <id> fp [reason]` - Report detection #id as false positive",
              "- `/og_feedback missed <reason>` - Report a missed detection",
              "",
              "Use `/og_report` to see recent detections and their IDs.",
            ].join("\n"),
          };
        }

        if (parts[0] === "missed") {
          const reason = parts.slice(1).join(" ") || "No reason provided";
          store.logFeedback({
            feedbackType: "missed_detection",
            reason,
          });
          log.info(`User reported missed detection: ${reason}`);
          return { text: `Thank you! Recorded missed detection report: "${reason}"` };
        }

        const analysisId = parseInt(parts[0]!, 10);
        if (isNaN(analysisId)) {
          return { text: "Invalid analysis ID. Use `/og_report` to see recent detections." };
        }

        if (parts[1] !== "fp") {
          return { text: "Invalid command. Use `/og_feedback <id> fp [reason]`" };
        }

        const reason = parts.slice(2).join(" ") || "No reason provided";
        store.logFeedback({
          analysisId,
          feedbackType: "false_positive",
          reason,
        });
        log.info(`User reported false positive for analysis #${analysisId}: ${reason}`);
        return { text: `Thank you! Recorded false positive report for detection #${analysisId}` };
      },
    });

    log.info(
      `Initialized (block: ${config.blockOnRisk}, timeout: ${config.timeoutMs}ms)`,
    );
  },
};

export default openClawGuardPlugin;
