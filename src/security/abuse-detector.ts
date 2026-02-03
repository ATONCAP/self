/**
 * Abuse pattern detection for identifying malicious behavior.
 *
 * This module analyzes message history and session behavior to detect
 * patterns indicative of abuse, injection attempts, or exploitation.
 *
 * SECURITY: Abuse detection is a defense-in-depth measure to identify
 * coordinated or persistent attack patterns.
 */

import {
  calculateInjectionRiskScore,
  type InjectionPatternCategory,
  type InjectionRiskAssessment,
} from "./injection-patterns.js";

export type AbusePatternId =
  | "repeated_injection_attempts"
  | "credential_probing"
  | "rapid_tool_exploitation"
  | "privilege_escalation_attempts"
  | "data_exfiltration_attempts"
  | "safety_bypass_attempts"
  | "impersonation_attempts"
  | "flooding";

export type AbuseSeverity = "low" | "medium" | "high" | "critical";

export type AbuseAction = "warn" | "throttle" | "block" | "alert";

export type AbusePatternMatch = {
  patternId: AbusePatternId;
  severity: AbuseSeverity;
  action: AbuseAction;
  description: string;
  evidence: string[];
  timestamp: number;
};

export type MessageRecord = {
  content: string;
  timestamp: number;
  isFromUser: boolean;
  toolCalls?: string[];
  injectionRisk?: InjectionRiskAssessment;
};

export type SessionHistory = {
  sessionKey: string;
  messages: MessageRecord[];
  /** Pre-computed injection assessments */
  injectionAssessments: InjectionRiskAssessment[];
};

export type AbuseDetectionResult = {
  /** Whether abuse was detected */
  abuseDetected: boolean;
  /** Highest severity level detected */
  maxSeverity: AbuseSeverity | null;
  /** Recommended action */
  recommendedAction: AbuseAction | null;
  /** All pattern matches */
  matches: AbusePatternMatch[];
  /** Summary for logging */
  summary: string;
};

export type AbusePatternDefinition = {
  id: AbusePatternId;
  description: string;
  severity: AbuseSeverity;
  action: AbuseAction;
  detector: (history: SessionHistory, config: AbuseDetectorConfig) => AbusePatternMatch | null;
};

export type AbuseDetectorConfig = {
  /** Enable abuse detection */
  enabled: boolean;
  /** Minimum messages needed for pattern detection */
  minMessagesForDetection: number;
  /** Time window for pattern analysis (ms) */
  analysisWindowMs: number;
  /** Threshold for "repeated" injection attempts */
  repeatedInjectionThreshold: number;
  /** Threshold for credential probing attempts */
  credentialProbeThreshold: number;
  /** Threshold for rapid tool calls */
  rapidToolCallThreshold: number;
  /** Threshold for flooding detection (messages per minute) */
  floodingThreshold: number;
  /** Patterns to skip */
  disabledPatterns: AbusePatternId[];
};

export const DEFAULT_ABUSE_DETECTOR_CONFIG: AbuseDetectorConfig = {
  enabled: true,
  minMessagesForDetection: 3,
  analysisWindowMs: 10 * 60 * 1000, // 10 minutes
  repeatedInjectionThreshold: 3,
  credentialProbeThreshold: 2,
  rapidToolCallThreshold: 20,
  floodingThreshold: 30,
  disabledPatterns: [],
};

/**
 * Abuse pattern definitions.
 */
const ABUSE_PATTERNS: AbusePatternDefinition[] = [
  {
    id: "repeated_injection_attempts",
    description: "Multiple injection patterns detected in recent messages",
    severity: "high",
    action: "block",
    detector: (history, config) => {
      const recentMessages = getRecentUserMessages(history, config.analysisWindowMs);
      const injectionMessages = recentMessages.filter((msg) => {
        const assessment = msg.injectionRisk ?? calculateInjectionRiskScore(msg.content);
        return assessment.normalizedScore >= 25; // medium+ severity
      });

      if (injectionMessages.length >= config.repeatedInjectionThreshold) {
        return {
          patternId: "repeated_injection_attempts",
          severity: "high",
          action: "block",
          description: `${injectionMessages.length} injection attempts in ${Math.round(config.analysisWindowMs / 60000)} minutes`,
          evidence: injectionMessages.slice(0, 3).map((m) => m.content.slice(0, 100)),
          timestamp: Date.now(),
        };
      }
      return null;
    },
  },
  {
    id: "credential_probing",
    description: "Repeated requests for credentials or secrets",
    severity: "high",
    action: "block",
    detector: (history, config) => {
      const credentialPatterns = [
        /api[_\-\s]?key/i,
        /password/i,
        /\bsecret\b/i,
        /\btoken\b/i,
        /credential/i,
        /private[_\-\s]?key/i,
        /auth[_\-\s]?token/i,
        /bearer/i,
        /\.env\b/i,
        /reveal.*(?:key|secret|password|token)/i,
        /show.*(?:key|secret|password|token)/i,
        /give.*(?:key|secret|password|token)/i,
      ];

      const recentMessages = getRecentUserMessages(history, config.analysisWindowMs);
      const probeMessages = recentMessages.filter((msg) =>
        credentialPatterns.some((p) => p.test(msg.content))
      );

      if (probeMessages.length >= config.credentialProbeThreshold) {
        return {
          patternId: "credential_probing",
          severity: "high",
          action: "block",
          description: `${probeMessages.length} credential probing attempts detected`,
          evidence: probeMessages.slice(0, 3).map((m) => m.content.slice(0, 100)),
          timestamp: Date.now(),
        };
      }
      return null;
    },
  },
  {
    id: "rapid_tool_exploitation",
    description: "Unusually rapid tool call patterns",
    severity: "medium",
    action: "throttle",
    detector: (history, config) => {
      const recentMessages = getRecentMessages(history, config.analysisWindowMs);
      let totalToolCalls = 0;

      for (const msg of recentMessages) {
        if (msg.toolCalls) {
          totalToolCalls += msg.toolCalls.length;
        }
      }

      // Check for tool call rate over time
      const timeSpanMinutes = config.analysisWindowMs / 60000;
      const toolCallRate = totalToolCalls / timeSpanMinutes;

      if (toolCallRate >= config.rapidToolCallThreshold / timeSpanMinutes) {
        return {
          patternId: "rapid_tool_exploitation",
          severity: "medium",
          action: "throttle",
          description: `High tool call rate: ${totalToolCalls} calls in ${timeSpanMinutes} minutes`,
          evidence: [`Tool call rate: ${toolCallRate.toFixed(1)}/min`],
          timestamp: Date.now(),
        };
      }
      return null;
    },
  },
  {
    id: "privilege_escalation_attempts",
    description: "Attempts to escalate privileges or gain elevated access",
    severity: "critical",
    action: "block",
    detector: (history, config) => {
      const escalationPatterns = [
        /\belevated\s*=\s*true\b/i,
        /\bsudo\b/i,
        /\broot\b.*access/i,
        /\badmin\b.*mode/i,
        /bypass.*(?:security|safety|restrictions?)/i,
        /disable.*(?:security|safety|restrictions?)/i,
        /override.*(?:security|safety|restrictions?)/i,
        /unlock.*(?:full|all)\s*(?:access|permissions?)/i,
        /grant.*(?:elevated|admin|root)/i,
      ];

      const recentMessages = getRecentUserMessages(history, config.analysisWindowMs);
      const escalationMessages = recentMessages.filter((msg) =>
        escalationPatterns.some((p) => p.test(msg.content))
      );

      if (escalationMessages.length >= 2) {
        return {
          patternId: "privilege_escalation_attempts",
          severity: "critical",
          action: "block",
          description: `${escalationMessages.length} privilege escalation attempts detected`,
          evidence: escalationMessages.slice(0, 3).map((m) => m.content.slice(0, 100)),
          timestamp: Date.now(),
        };
      }
      return null;
    },
  },
  {
    id: "data_exfiltration_attempts",
    description: "Attempts to exfiltrate data to external endpoints",
    severity: "critical",
    action: "block",
    detector: (history, config) => {
      const exfilPatterns = [
        /(?:send|post|upload)\s+(?:to|data)\s+(?:http|https|webhook)/i,
        /webhook\s*[:=]/i,
        /callback\s*[:=]\s*["']?https?:/i,
        /exfil(?:trate)?/i,
        /(?:curl|wget|fetch)\s+.*https?:\/\//i,
        /encode.*(?:base64|hex).*(?:send|post|upload)/i,
      ];

      const recentMessages = getRecentUserMessages(history, config.analysisWindowMs);
      const exfilMessages = recentMessages.filter((msg) =>
        exfilPatterns.some((p) => p.test(msg.content))
      );

      if (exfilMessages.length >= 1) {
        // Even one explicit exfil attempt is suspicious
        return {
          patternId: "data_exfiltration_attempts",
          severity: "critical",
          action: "block",
          description: `Data exfiltration pattern detected`,
          evidence: exfilMessages.slice(0, 3).map((m) => m.content.slice(0, 100)),
          timestamp: Date.now(),
        };
      }
      return null;
    },
  },
  {
    id: "safety_bypass_attempts",
    description: "Attempts to bypass safety measures",
    severity: "high",
    action: "block",
    detector: (history, config) => {
      const recentMessages = getRecentUserMessages(history, config.analysisWindowMs);
      const bypassMessages = recentMessages.filter((msg) => {
        const assessment = msg.injectionRisk ?? calculateInjectionRiskScore(msg.content);
        return assessment.categoriesDetected.includes("safety_bypass");
      });

      if (bypassMessages.length >= 2) {
        return {
          patternId: "safety_bypass_attempts",
          severity: "high",
          action: "block",
          description: `${bypassMessages.length} safety bypass attempts detected`,
          evidence: bypassMessages.slice(0, 3).map((m) => m.content.slice(0, 100)),
          timestamp: Date.now(),
        };
      }
      return null;
    },
  },
  {
    id: "impersonation_attempts",
    description: "Attempts to impersonate administrators or developers",
    severity: "high",
    action: "block",
    detector: (history, config) => {
      const recentMessages = getRecentUserMessages(history, config.analysisWindowMs);
      const impersonationMessages = recentMessages.filter((msg) => {
        const assessment = msg.injectionRisk ?? calculateInjectionRiskScore(msg.content);
        return assessment.categoriesDetected.includes("authority_impersonation");
      });

      if (impersonationMessages.length >= 2) {
        return {
          patternId: "impersonation_attempts",
          severity: "high",
          action: "block",
          description: `${impersonationMessages.length} impersonation attempts detected`,
          evidence: impersonationMessages.slice(0, 3).map((m) => m.content.slice(0, 100)),
          timestamp: Date.now(),
        };
      }
      return null;
    },
  },
  {
    id: "flooding",
    description: "Message flooding detected",
    severity: "medium",
    action: "throttle",
    detector: (history, config) => {
      const oneMinuteAgo = Date.now() - 60_000;
      const recentMessages = history.messages.filter(
        (m) => m.isFromUser && m.timestamp > oneMinuteAgo
      );

      if (recentMessages.length >= config.floodingThreshold) {
        return {
          patternId: "flooding",
          severity: "medium",
          action: "throttle",
          description: `${recentMessages.length} messages in last minute (threshold: ${config.floodingThreshold})`,
          evidence: [`Message rate: ${recentMessages.length}/min`],
          timestamp: Date.now(),
        };
      }
      return null;
    },
  },
];

/**
 * Detect abuse patterns in session history.
 */
export function detectAbuse(
  history: SessionHistory,
  config: Partial<AbuseDetectorConfig> = {},
): AbuseDetectionResult {
  const mergedConfig = { ...DEFAULT_ABUSE_DETECTOR_CONFIG, ...config };

  if (!mergedConfig.enabled) {
    return {
      abuseDetected: false,
      maxSeverity: null,
      recommendedAction: null,
      matches: [],
      summary: "Abuse detection disabled",
    };
  }

  if (history.messages.length < mergedConfig.minMessagesForDetection) {
    return {
      abuseDetected: false,
      maxSeverity: null,
      recommendedAction: null,
      matches: [],
      summary: "Insufficient history for detection",
    };
  }

  // Pre-compute injection assessments if not already done
  const enrichedHistory = enrichHistoryWithAssessments(history);

  const matches: AbusePatternMatch[] = [];

  for (const pattern of ABUSE_PATTERNS) {
    if (mergedConfig.disabledPatterns.includes(pattern.id)) {
      continue;
    }

    const match = pattern.detector(enrichedHistory, mergedConfig);
    if (match) {
      matches.push(match);
    }
  }

  if (matches.length === 0) {
    return {
      abuseDetected: false,
      maxSeverity: null,
      recommendedAction: null,
      matches: [],
      summary: "No abuse patterns detected",
    };
  }

  // Determine max severity and recommended action
  const severityOrder: AbuseSeverity[] = ["low", "medium", "high", "critical"];
  const actionOrder: AbuseAction[] = ["warn", "throttle", "block", "alert"];

  let maxSeverity: AbuseSeverity = "low";
  let recommendedAction: AbuseAction = "warn";

  for (const match of matches) {
    if (severityOrder.indexOf(match.severity) > severityOrder.indexOf(maxSeverity)) {
      maxSeverity = match.severity;
    }
    if (actionOrder.indexOf(match.action) > actionOrder.indexOf(recommendedAction)) {
      recommendedAction = match.action;
    }
  }

  const patternIds = matches.map((m) => m.patternId).join(", ");
  const summary = `Abuse detected: ${matches.length} pattern(s) [${patternIds}], severity=${maxSeverity}, action=${recommendedAction}`;

  return {
    abuseDetected: true,
    maxSeverity,
    recommendedAction,
    matches,
    summary,
  };
}

/**
 * Analyze a single message for abuse indicators.
 */
export function analyzeMessage(
  content: string,
  existingHistory?: SessionHistory,
): {
  injectionRisk: InjectionRiskAssessment;
  potentialAbuse: boolean;
  categories: InjectionPatternCategory[];
} {
  const injectionRisk = calculateInjectionRiskScore(content);
  const potentialAbuse = injectionRisk.normalizedScore >= 25; // medium+ severity

  return {
    injectionRisk,
    potentialAbuse,
    categories: injectionRisk.categoriesDetected,
  };
}

/**
 * Create a session history object.
 */
export function createSessionHistory(sessionKey: string): SessionHistory {
  return {
    sessionKey,
    messages: [],
    injectionAssessments: [],
  };
}

/**
 * Add a message to session history.
 */
export function addMessageToHistory(
  history: SessionHistory,
  message: MessageRecord,
): SessionHistory {
  // Compute injection assessment
  const assessment = calculateInjectionRiskScore(message.content);

  return {
    ...history,
    messages: [
      ...history.messages,
      {
        ...message,
        injectionRisk: assessment,
      },
    ],
    injectionAssessments: [...history.injectionAssessments, assessment],
  };
}

/**
 * Prune old messages from history.
 */
export function pruneHistory(
  history: SessionHistory,
  maxMessages: number = 100,
  maxAgeMs: number = 3600_000,
): SessionHistory {
  const cutoff = Date.now() - maxAgeMs;

  const filteredMessages = history.messages
    .filter((m) => m.timestamp > cutoff)
    .slice(-maxMessages);

  return {
    ...history,
    messages: filteredMessages,
    injectionAssessments: filteredMessages
      .map((m) => m.injectionRisk)
      .filter((a): a is InjectionRiskAssessment => !!a),
  };
}

// Helper functions

function getRecentMessages(history: SessionHistory, windowMs: number): MessageRecord[] {
  const cutoff = Date.now() - windowMs;
  return history.messages.filter((m) => m.timestamp > cutoff);
}

function getRecentUserMessages(history: SessionHistory, windowMs: number): MessageRecord[] {
  const cutoff = Date.now() - windowMs;
  return history.messages.filter((m) => m.isFromUser && m.timestamp > cutoff);
}

function enrichHistoryWithAssessments(history: SessionHistory): SessionHistory {
  const enrichedMessages = history.messages.map((msg) => {
    if (msg.injectionRisk) {
      return msg;
    }
    return {
      ...msg,
      injectionRisk: calculateInjectionRiskScore(msg.content),
    };
  });

  return {
    ...history,
    messages: enrichedMessages,
    injectionAssessments: enrichedMessages
      .map((m) => m.injectionRisk)
      .filter((a): a is InjectionRiskAssessment => !!a),
  };
}

/**
 * Abuse detector class for stateful detection across sessions.
 */
export class AbuseDetector {
  private histories = new Map<string, SessionHistory>();
  private config: AbuseDetectorConfig;

  constructor(config: Partial<AbuseDetectorConfig> = {}) {
    this.config = { ...DEFAULT_ABUSE_DETECTOR_CONFIG, ...config };
  }

  /**
   * Record a message and check for abuse.
   */
  recordAndCheck(
    sessionKey: string,
    content: string,
    isFromUser: boolean,
    toolCalls?: string[],
  ): AbuseDetectionResult {
    let history = this.histories.get(sessionKey);
    if (!history) {
      history = createSessionHistory(sessionKey);
    }

    // Add message
    history = addMessageToHistory(history, {
      content,
      timestamp: Date.now(),
      isFromUser,
      toolCalls,
    });

    // Prune old messages
    history = pruneHistory(history);

    // Store updated history
    this.histories.set(sessionKey, history);

    // Detect abuse
    return detectAbuse(history, this.config);
  }

  /**
   * Get history for a session.
   */
  getHistory(sessionKey: string): SessionHistory | undefined {
    return this.histories.get(sessionKey);
  }

  /**
   * Clear history for a session.
   */
  clearSession(sessionKey: string): void {
    this.histories.delete(sessionKey);
  }

  /**
   * Clear all histories.
   */
  clearAll(): void {
    this.histories.clear();
  }

  /**
   * Update configuration.
   */
  updateConfig(config: Partial<AbuseDetectorConfig>): void {
    this.config = { ...this.config, ...config };
  }
}

/**
 * Create an abuse detector instance.
 */
export function createAbuseDetector(
  config?: Partial<AbuseDetectorConfig>,
): AbuseDetector {
  return new AbuseDetector(config);
}
