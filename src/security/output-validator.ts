/**
 * Output validation for agent responses before delivery.
 *
 * This module scans agent outputs for security issues including:
 * - Credential leaks (API keys, tokens, passwords)
 * - System prompt leakage
 * - Data exfiltration attempts
 * - Suspicious embedded content
 *
 * SECURITY: This is a critical security gate. All agent responses should pass through validation.
 */

import { getDefaultRedactPatterns } from "../logging/redact.js";

export type OutputIssueType =
  | "credential_leak"
  | "system_prompt_leak"
  | "data_exfiltration"
  | "suspicious_encoding"
  | "suspicious_url"
  | "canary_leak";

export type OutputIssueSeverity = "warn" | "block";

export type OutputIssue = {
  type: OutputIssueType;
  severity: OutputIssueSeverity;
  description: string;
  location?: { start: number; end: number };
  matched?: string;
};

export type OutputValidationResult = {
  /** Whether the output is safe to deliver */
  safe: boolean;
  /** List of issues found */
  issues: OutputIssue[];
  /** Sanitized content (if blocking issues were found) */
  sanitizedContent?: string;
  /** Original content hash for audit trail */
  contentHash?: string;
};

export type OutputValidationContext = {
  /** Session key for context */
  sessionKey?: string;
  /** Tools that were called in this turn */
  toolsCalled?: string[];
  /** Whether this is a response to external/webhook content */
  isExternalResponse?: boolean;
  /** Canary tokens to check for */
  canaryTokens?: string[];
};

/**
 * Credential patterns to detect in output.
 * Patterns are designed to catch common API key formats.
 */
const CREDENTIAL_PATTERNS: Array<{
  pattern: RegExp;
  type: string;
  severity: OutputIssueSeverity;
}> = [
  // OpenAI keys
  { pattern: /\bsk-[A-Za-z0-9]{20,}\b/, type: "OpenAI API key", severity: "block" },
  { pattern: /\bsk-proj-[A-Za-z0-9_-]{20,}\b/, type: "OpenAI project key", severity: "block" },

  // Anthropic keys
  { pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/, type: "Anthropic API key", severity: "block" },

  // GitHub tokens
  { pattern: /\bghp_[A-Za-z0-9]{36,}\b/, type: "GitHub PAT", severity: "block" },
  { pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/, type: "GitHub fine-grained PAT", severity: "block" },
  { pattern: /\bgho_[A-Za-z0-9]{36,}\b/, type: "GitHub OAuth token", severity: "block" },
  { pattern: /\bghs_[A-Za-z0-9]{36,}\b/, type: "GitHub server token", severity: "block" },
  { pattern: /\bghr_[A-Za-z0-9]{36,}\b/, type: "GitHub refresh token", severity: "block" },

  // Slack tokens
  { pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, type: "Slack token", severity: "block" },
  { pattern: /\bxapp-[A-Za-z0-9-]{10,}\b/, type: "Slack app token", severity: "block" },

  // AWS credentials
  { pattern: /\bAKIA[0-9A-Z]{16}\b/, type: "AWS access key", severity: "block" },
  { pattern: /\b[A-Za-z0-9/+=]{40}\b(?=.*(?:aws|secret|key))/i, type: "Potential AWS secret", severity: "warn" },

  // Google Cloud
  { pattern: /\bAIza[0-9A-Za-z_-]{35}\b/, type: "Google API key", severity: "block" },

  // Private keys
  { pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/, type: "Private key header", severity: "block" },
  { pattern: /-----BEGIN RSA PRIVATE KEY-----/, type: "RSA private key", severity: "block" },
  { pattern: /-----BEGIN EC PRIVATE KEY-----/, type: "EC private key", severity: "block" },
  { pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/, type: "OpenSSH private key", severity: "block" },

  // Generic secrets
  { pattern: /\b(?:api[_-]?key|apikey)\s*[:=]\s*["']?([A-Za-z0-9_-]{20,})["']?/i, type: "Generic API key", severity: "block" },
  { pattern: /\b(?:secret|password|passwd|pwd)\s*[:=]\s*["']?([^\s"']{8,})["']?/i, type: "Generic secret", severity: "warn" },
  { pattern: /\bBearer\s+[A-Za-z0-9._-]{20,}\b/, type: "Bearer token", severity: "block" },

  // Telegram tokens
  { pattern: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/, type: "Telegram bot token", severity: "block" },

  // Perplexity
  { pattern: /\bpplx-[A-Za-z0-9_-]{20,}\b/, type: "Perplexity API key", severity: "block" },

  // Brave
  { pattern: /\bBSA[A-Za-z0-9_-]{20,}\b/, type: "Brave Search API key", severity: "block" },

  // npm
  { pattern: /\bnpm_[A-Za-z0-9]{20,}\b/, type: "npm token", severity: "block" },

  // Discord
  { pattern: /\b[MN][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b/, type: "Discord bot token", severity: "block" },

  // Moltbook (from the codebase)
  { pattern: /\bmoltbook_sk_[A-Za-z0-9_-]{10,}\b/, type: "Moltbook API key", severity: "block" },
];

/**
 * System prompt indicators that should not appear in output.
 */
const SYSTEM_PROMPT_INDICATORS: Array<{
  pattern: RegExp;
  description: string;
}> = [
  { pattern: /You are a personal assistant running inside OpenClaw/i, description: "System identity leak" },
  { pattern: /Tool availability \(filtered by policy\)/i, description: "Tool list leak" },
  { pattern: /IMMUTABLE SAFETY RULES/i, description: "Safety rules leak" },
  { pattern: /Your working directory is:/i, description: "Workspace path leak" },
  { pattern: /## Safety\s+You have no independent goals/i, description: "Safety section leak" },
  { pattern: /## Tooling\s+Tool availability/i, description: "Tooling section leak" },
  { pattern: /heartbeat prompt:/i, description: "Heartbeat config leak" },
  { pattern: /HEARTBEAT_OK/i, description: "Heartbeat token leak" },
  { pattern: /<<<EXTERNAL_UNTRUSTED_CONTENT>>>/i, description: "Security boundary leak" },
  { pattern: /<<<TOOL_RESULT_UNTRUSTED>>>/i, description: "Tool wrapper leak" },
];

/**
 * Suspicious URL patterns that might indicate exfiltration.
 */
const SUSPICIOUS_URL_PATTERNS: Array<{
  pattern: RegExp;
  description: string;
}> = [
  { pattern: /https?:\/\/[^\/]*(?:webhook|callback|exfil|ngrok|burp|interactsh|oast)/i, description: "Suspicious webhook domain" },
  { pattern: /https?:\/\/[^\/]*\.[a-z]{2,3}\/[A-Za-z0-9_-]{30,}(?:\?|$)/i, description: "URL with long random path (potential exfil)" },
  { pattern: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i, description: "Direct IP address URL" },
  { pattern: /data:[^;]+;base64,[A-Za-z0-9+\/=]{100,}/i, description: "Large base64 data URL" },
];

/**
 * Suspicious encoding patterns.
 */
const SUSPICIOUS_ENCODING_PATTERNS: Array<{
  pattern: RegExp;
  description: string;
  minLength: number;
}> = [
  { pattern: /[A-Za-z0-9+\/=]{200,}/, description: "Large base64-like string", minLength: 200 },
  { pattern: /(?:%[0-9A-Fa-f]{2}){20,}/, description: "Heavily URL-encoded content", minLength: 60 },
  { pattern: /(?:\\x[0-9A-Fa-f]{2}){20,}/, description: "Hex-escaped content", minLength: 80 },
];

/**
 * Validate agent output for security issues.
 *
 * @param content - The agent's response content
 * @param context - Optional context for validation
 * @returns Validation result with issues and optionally sanitized content
 */
export function validateAgentOutput(
  content: string,
  context: OutputValidationContext = {},
): OutputValidationResult {
  const issues: OutputIssue[] = [];

  // Check for credential leaks
  for (const credPattern of CREDENTIAL_PATTERNS) {
    const match = content.match(credPattern.pattern);
    if (match) {
      issues.push({
        type: "credential_leak",
        severity: credPattern.severity,
        description: `Potential ${credPattern.type} in output`,
        location: {
          start: match.index!,
          end: match.index! + match[0].length,
        },
        matched: maskCredential(match[0]),
      });
    }
  }

  // Check for system prompt leakage
  for (const indicator of SYSTEM_PROMPT_INDICATORS) {
    if (indicator.pattern.test(content)) {
      issues.push({
        type: "system_prompt_leak",
        severity: "warn",
        description: indicator.description,
      });
    }
  }

  // Check for suspicious URLs (potential exfiltration)
  for (const urlPattern of SUSPICIOUS_URL_PATTERNS) {
    const match = content.match(urlPattern.pattern);
    if (match) {
      issues.push({
        type: "suspicious_url",
        severity: "warn",
        description: urlPattern.description,
        matched: match[0].slice(0, 100),
      });
    }
  }

  // Check for suspicious encodings
  for (const encPattern of SUSPICIOUS_ENCODING_PATTERNS) {
    const match = content.match(encPattern.pattern);
    if (match && match[0].length >= encPattern.minLength) {
      issues.push({
        type: "suspicious_encoding",
        severity: "warn",
        description: encPattern.description,
        matched: `${match[0].slice(0, 50)}...`,
      });
    }
  }

  // Check for canary tokens
  if (context.canaryTokens?.length) {
    for (const canary of context.canaryTokens) {
      if (content.includes(canary)) {
        issues.push({
          type: "canary_leak",
          severity: "block",
          description: `Canary token detected in output`,
          matched: canary.slice(0, 10) + "...",
        });
      }
    }
  }

  // Determine if safe
  const hasBlockingIssue = issues.some((i) => i.severity === "block");
  const safe = !hasBlockingIssue;

  // Generate sanitized content if needed
  let sanitizedContent: string | undefined;
  if (!safe) {
    sanitizedContent = sanitizeOutput(content, issues);
  }

  return {
    safe,
    issues,
    sanitizedContent,
    contentHash: hashContent(content),
  };
}

/**
 * Mask a credential for logging purposes.
 */
function maskCredential(credential: string): string {
  if (credential.length < 12) {
    return "***";
  }
  const start = credential.slice(0, 6);
  const end = credential.slice(-4);
  return `${start}...${end}`;
}

/**
 * Sanitize output by removing or redacting blocking issues.
 */
function sanitizeOutput(content: string, issues: OutputIssue[]): string {
  let sanitized = content;

  // Sort issues by position (descending) to replace from end to start
  const blockingIssues = issues
    .filter((i) => i.severity === "block" && i.location)
    .sort((a, b) => (b.location?.start ?? 0) - (a.location?.start ?? 0));

  for (const issue of blockingIssues) {
    if (issue.location) {
      const before = sanitized.slice(0, issue.location.start);
      const after = sanitized.slice(issue.location.end);
      sanitized = `${before}[REDACTED: ${issue.type}]${after}`;
    }
  }

  // If there are blocking issues without locations, add a warning
  const locationlessBlocking = issues.filter(
    (i) => i.severity === "block" && !i.location
  );
  if (locationlessBlocking.length > 0) {
    const types = locationlessBlocking.map((i) => i.type).join(", ");
    sanitized = `[Response contained security violations: ${types}]\n\n${sanitized}`;
  }

  return sanitized;
}

/**
 * Simple content hash for audit trail.
 */
function hashContent(content: string): string {
  // Simple hash for fingerprinting (not cryptographic)
  let hash = 0;
  for (let i = 0; i < content.length; i++) {
    const char = content.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16).padStart(8, "0");
}

/**
 * Quick check if output likely contains credentials.
 * Faster than full validation for pre-filtering.
 *
 * @param content - Content to check
 * @returns True if credentials are likely present
 */
export function likelyContainsCredentials(content: string): boolean {
  // Quick heuristic checks before running full patterns
  const quickIndicators = [
    "sk-",
    "ghp_",
    "xox",
    "AKIA",
    "AIza",
    "Bearer",
    "-----BEGIN",
    "api_key",
    "apiKey",
    "secret",
    "password",
    "moltbook_sk_",
  ];

  const lowerContent = content.toLowerCase();
  for (const indicator of quickIndicators) {
    if (lowerContent.includes(indicator.toLowerCase())) {
      return true;
    }
  }

  return false;
}

/**
 * Create a validation summary for logging.
 *
 * @param result - Validation result
 * @returns Human-readable summary
 */
export function summarizeValidation(result: OutputValidationResult): string {
  if (result.safe && result.issues.length === 0) {
    return "Output validated: safe";
  }

  const blockCount = result.issues.filter((i) => i.severity === "block").length;
  const warnCount = result.issues.filter((i) => i.severity === "warn").length;

  const issueTypes = [...new Set(result.issues.map((i) => i.type))].join(", ");

  return `Output validation: ${result.safe ? "SAFE" : "BLOCKED"} ` +
    `(${blockCount} blocking, ${warnCount} warnings) [${issueTypes}]`;
}

/**
 * Validation configuration.
 */
export type OutputValidatorConfig = {
  /** Enable credential leak detection */
  checkCredentials: boolean;
  /** Enable system prompt leak detection */
  checkSystemPromptLeak: boolean;
  /** Enable suspicious URL detection */
  checkSuspiciousUrls: boolean;
  /** Enable suspicious encoding detection */
  checkSuspiciousEncodings: boolean;
  /** Canary tokens to check for */
  canaryTokens: string[];
  /** Additional credential patterns */
  customCredentialPatterns: Array<{ pattern: RegExp; type: string }>;
};

export const DEFAULT_VALIDATOR_CONFIG: OutputValidatorConfig = {
  checkCredentials: true,
  checkSystemPromptLeak: true,
  checkSuspiciousUrls: true,
  checkSuspiciousEncodings: true,
  canaryTokens: [],
  customCredentialPatterns: [],
};

/**
 * Create a configured validator function.
 *
 * @param config - Configuration options
 * @returns Configured validation function
 */
export function createOutputValidator(
  config: Partial<OutputValidatorConfig> = {},
): (content: string, context?: OutputValidationContext) => OutputValidationResult {
  const mergedConfig = { ...DEFAULT_VALIDATOR_CONFIG, ...config };

  return (content: string, context?: OutputValidationContext): OutputValidationResult => {
    // Add canary tokens from config to context
    const mergedContext: OutputValidationContext = {
      ...context,
      canaryTokens: [
        ...(context?.canaryTokens ?? []),
        ...mergedConfig.canaryTokens,
      ],
    };

    return validateAgentOutput(content, mergedContext);
  };
}

/**
 * Redact all credentials from content (for logging).
 *
 * @param content - Content to redact
 * @returns Content with credentials redacted
 */
export function redactCredentialsInContent(content: string): string {
  let redacted = content;

  for (const credPattern of CREDENTIAL_PATTERNS) {
    redacted = redacted.replace(credPattern.pattern, (match) => {
      return `[REDACTED:${credPattern.type}]`;
    });
  }

  return redacted;
}
