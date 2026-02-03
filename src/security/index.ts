/**
 * Security module exports.
 *
 * This module provides comprehensive security hardening for the OpenClaw agent platform:
 * - Injection pattern detection
 * - Tool result isolation
 * - Output validation
 * - Rate limiting
 * - Abuse detection
 * - Memory content guarding
 * - Canary token detection
 * - Security metrics collection
 */

// Injection pattern detection
export {
  calculateInjectionRiskScore,
  containsSuspiciousPatterns,
  getPatternsForCategory,
  addCustomPatterns,
  getPatternCategorySummary,
  INJECTION_PATTERNS,
  CATEGORY_MULTIPLIERS,
  type InjectionPatternCategory,
  type InjectionPattern,
  type InjectionMatch,
  type InjectionRiskAssessment,
} from "./injection-patterns.js";

// Tool result isolation
export {
  wrapToolResult,
  isWrappedToolResult,
  extractRawToolResult,
  summarizeToolResult,
  wrapToolResults,
  createToolResultWrapper,
  DEFAULT_WRAPPER_CONFIG,
  type WrapToolResultOptions,
  type WrappedToolResult,
  type ToolResultWrapperConfig,
} from "./tool-result-wrapper.js";

// Output validation
export {
  validateAgentOutput,
  likelyContainsCredentials,
  summarizeValidation,
  createOutputValidator,
  redactCredentialsInContent,
  DEFAULT_VALIDATOR_CONFIG,
  type OutputIssueType,
  type OutputIssueSeverity,
  type OutputIssue,
  type OutputValidationResult,
  type OutputValidationContext,
  type OutputValidatorConfig,
} from "./output-validator.js";

// Rate limiting
export {
  SessionRateLimiter,
  createRateLimiter,
  getGlobalRateLimiter,
  initGlobalRateLimiter,
  DEFAULT_RATE_LIMIT_CONFIG,
  type RateLimitConfig,
  type RateLimitCheckResult,
  type RateLimitEvent,
} from "./rate-limiter.js";

// Abuse detection
export {
  detectAbuse,
  analyzeMessage,
  createSessionHistory,
  addMessageToHistory,
  pruneHistory,
  AbuseDetector,
  createAbuseDetector,
  DEFAULT_ABUSE_DETECTOR_CONFIG,
  type AbusePatternId,
  type AbuseSeverity,
  type AbuseAction,
  type AbusePatternMatch,
  type MessageRecord,
  type SessionHistory,
  type AbuseDetectionResult,
  type AbuseDetectorConfig,
} from "./abuse-detector.js";

// Memory content guarding
export {
  scanMemoryContent,
  scanMemoryFiles,
  quickMemoryCheck,
  MemoryGuard,
  createMemoryGuard,
  wrapMemoryForContext,
  DEFAULT_MEMORY_GUARD_CONFIG,
  type MemorySource,
  type MemoryScanResult,
  type MemoryGuardConfig,
} from "./memory-guard.js";

// Canary token detection
export {
  generateCanaryToken,
  detectCanaries,
  CanaryManager,
  createCanaryManager,
  generateStandardCanaries,
  formatCanaryAlert,
  CANARY_LOCATIONS,
  DEFAULT_CANARY_CONFIG,
  type CanaryTokenConfig,
  type CanaryDetectionResult,
  type CanaryManagerConfig,
} from "./canary-detection.js";

// Security metrics
export {
  SecurityMetrics,
  createSecurityMetrics,
  getGlobalSecurityMetrics,
  initGlobalSecurityMetrics,
  formatMetricsSummary,
  DEFAULT_METRICS_CONFIG,
  type SecurityMetricType,
  type SecurityEvent,
  type MetricsSummary,
  type MetricsConfig,
} from "./metrics.js";

// External content handling (existing)
export {
  detectSuspiciousPatterns,
  wrapExternalContent,
  buildSafeExternalPrompt,
  isExternalHookSession,
  getHookType,
  type ExternalContentSource,
  type WrapExternalContentOptions,
} from "./external-content.js";

/**
 * Unified security configuration type.
 */
export type SecurityConfig = {
  /** Enable all security features */
  enabled: boolean;

  /** Injection pattern detection */
  injectionDetection: {
    enabled: boolean;
    warnThreshold: number;
    blockThreshold: number;
  };

  /** Tool result isolation */
  toolResultIsolation: {
    enabled: boolean;
    scanForInjection: boolean;
    riskThreshold: number;
  };

  /** Output validation */
  outputValidation: {
    enabled: boolean;
    blockCredentialLeaks: boolean;
    blockSystemPromptLeaks: boolean;
  };

  /** Rate limiting */
  rateLimiting: {
    enabled: boolean;
    messagesPerMinute: number;
    toolCallsPerMinute: number;
    tokensPerHour: number;
    cooldownMs: number;
    exemptSessions: string[];
  };

  /** Abuse detection */
  abuseDetection: {
    enabled: boolean;
    analysisWindowMs: number;
    disabledPatterns: string[];
  };

  /** Memory guarding */
  memoryGuard: {
    enabled: boolean;
    warnThreshold: number;
    blockThreshold: number;
    sanitizeInsteadOfBlock: boolean;
  };

  /** Canary tokens */
  canaryTokens: {
    enabled: boolean;
    tokens: Array<{
      value: string;
      name: string;
      location: string;
    }>;
  };

  /** Metrics collection */
  metrics: {
    enabled: boolean;
    alertThresholds: {
      criticalEventsPerHour: number;
      highEventsPerHour: number;
      totalEventsPerHour: number;
    };
  };
};

/**
 * Default unified security configuration.
 */
export const DEFAULT_SECURITY_CONFIG: SecurityConfig = {
  enabled: true,

  injectionDetection: {
    enabled: true,
    warnThreshold: 15,
    blockThreshold: 50,
  },

  toolResultIsolation: {
    enabled: true,
    scanForInjection: true,
    riskThreshold: 10,
  },

  outputValidation: {
    enabled: true,
    blockCredentialLeaks: true,
    blockSystemPromptLeaks: true,
  },

  rateLimiting: {
    enabled: true,
    messagesPerMinute: 30,
    toolCallsPerMinute: 60,
    tokensPerHour: 500_000,
    cooldownMs: 60_000,
    exemptSessions: [],
  },

  abuseDetection: {
    enabled: true,
    analysisWindowMs: 10 * 60 * 1000,
    disabledPatterns: [],
  },

  memoryGuard: {
    enabled: true,
    warnThreshold: 15,
    blockThreshold: 50,
    sanitizeInsteadOfBlock: false,
  },

  canaryTokens: {
    enabled: true,
    tokens: [],
  },

  metrics: {
    enabled: true,
    alertThresholds: {
      criticalEventsPerHour: 5,
      highEventsPerHour: 20,
      totalEventsPerHour: 100,
    },
  },
};
