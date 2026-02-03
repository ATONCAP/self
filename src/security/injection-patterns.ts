/**
 * Enhanced injection pattern detection for defense-in-depth security.
 *
 * This module provides comprehensive pattern matching to detect prompt injection
 * attempts across multiple categories. Patterns are weighted by severity and
 * combined into a risk score.
 *
 * SECURITY: This is a critical security component. Changes should be reviewed carefully.
 */

export type InjectionPatternCategory =
  | "instruction_override"
  | "role_manipulation"
  | "context_manipulation"
  | "delimiter_escape"
  | "multi_turn_manipulation"
  | "encoding_attacks"
  | "tool_manipulation"
  | "data_exfiltration"
  | "authority_impersonation"
  | "safety_bypass";

export type InjectionPattern = {
  pattern: RegExp;
  category: InjectionPatternCategory;
  weight: number;
  description: string;
};

/**
 * Comprehensive injection pattern database organized by category.
 * Each pattern has a weight (1-10) indicating severity.
 */
export const INJECTION_PATTERNS: InjectionPattern[] = [
  // ============================================
  // INSTRUCTION OVERRIDE (weight: 7-10)
  // Attempts to override or ignore previous instructions
  // ============================================
  {
    pattern: /ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?|guidelines?)/i,
    category: "instruction_override",
    weight: 10,
    description: "Direct instruction override attempt",
  },
  {
    pattern: /disregard\s+(?:all\s+)?(?:previous|prior|above|earlier|your)/i,
    category: "instruction_override",
    weight: 9,
    description: "Disregard instruction attempt",
  },
  {
    pattern: /forget\s+(?:everything|all|your)\s+(?:instructions?|rules?|guidelines?|training)/i,
    category: "instruction_override",
    weight: 10,
    description: "Memory wipe attempt",
  },
  {
    pattern: /(?:new|updated|revised|override)\s+instructions?\s*:/i,
    category: "instruction_override",
    weight: 8,
    description: "New instructions injection",
  },
  {
    pattern: /(?:stop|end|cancel)\s+(?:following|obeying|listening)/i,
    category: "instruction_override",
    weight: 7,
    description: "Stop following instructions",
  },
  {
    pattern: /(?:override|bypass|skip|ignore)\s+(?:safety|security|restrictions?|limitations?|guardrails?)/i,
    category: "instruction_override",
    weight: 10,
    description: "Safety override attempt",
  },

  // ============================================
  // ROLE MANIPULATION (weight: 6-9)
  // Attempts to change the agent's identity or role
  // ============================================
  {
    pattern: /you\s+are\s+(?:now|actually|secretly|really)\s+(?:a|an)\s+/i,
    category: "role_manipulation",
    weight: 8,
    description: "Role reassignment attempt",
  },
  {
    pattern: /pretend\s+(?:to\s+be|you['']?re|that\s+you['']?re)\s+/i,
    category: "role_manipulation",
    weight: 7,
    description: "Pretend role attempt",
  },
  {
    pattern: /act\s+as\s+(?:if|though)\s+you\s+(?:are|were|have)/i,
    category: "role_manipulation",
    weight: 6,
    description: "Act as if attempt",
  },
  {
    pattern: /roleplay\s+(?:as|being)\s+/i,
    category: "role_manipulation",
    weight: 6,
    description: "Roleplay attempt",
  },
  {
    pattern: /imagine\s+you['']?re\s+(?:a|an|not)\s+/i,
    category: "role_manipulation",
    weight: 6,
    description: "Imagination role change",
  },
  {
    pattern: /from\s+now\s+on[,\s]+(?:you|your)\s+(?:are|will|should|must)/i,
    category: "role_manipulation",
    weight: 8,
    description: "Persistent role change",
  },
  {
    pattern: /(?:switch|change|transform)\s+(?:to|into)\s+(?:a|an)\s+/i,
    category: "role_manipulation",
    weight: 7,
    description: "Mode switch attempt",
  },
  {
    pattern: /(?:DAN|jailbreak|uncensored|unfiltered)\s*(?:mode)?/i,
    category: "role_manipulation",
    weight: 10,
    description: "Known jailbreak pattern",
  },

  // ============================================
  // CONTEXT MANIPULATION (weight: 7-10)
  // Attempts to claim special modes or contexts
  // ============================================
  {
    pattern: /\b(?:DEBUG|DEVELOPER|DEV|ADMIN|ROOT|SUDO|MAINTENANCE|SERVICE)\s*MODE\b/i,
    category: "context_manipulation",
    weight: 9,
    description: "Special mode claim",
  },
  {
    pattern: /\b(?:TEST(?:ING)?|SANDBOX|EVALUATION|TRAINING)\s*(?:MODE|ENVIRONMENT)\b/i,
    category: "context_manipulation",
    weight: 7,
    description: "Test mode claim",
  },
  {
    pattern: /\[\s*(?:SYSTEM|ADMIN|ROOT|OVERRIDE|INTERNAL|PRIVILEGED)\s*\]/i,
    category: "context_manipulation",
    weight: 9,
    description: "Fake system tag",
  },
  {
    pattern: /```(?:system|admin|override|internal|privileged|root)\b/i,
    category: "context_manipulation",
    weight: 8,
    description: "Code block system injection",
  },
  {
    pattern: /\belevated\s*=\s*true\b/i,
    category: "context_manipulation",
    weight: 8,
    description: "Elevated privilege claim",
  },
  {
    pattern: /\b(?:god|superuser|supreme|unlimited)\s*mode\b/i,
    category: "context_manipulation",
    weight: 9,
    description: "Unlimited access claim",
  },

  // ============================================
  // DELIMITER ESCAPE (weight: 8-10)
  // Attempts to escape content boundaries
  // ============================================
  {
    pattern: /<<<\s*(?:END|STOP|BREAK|EXIT|CLOSE)/i,
    category: "delimiter_escape",
    weight: 9,
    description: "Boundary escape attempt",
  },
  {
    pattern: />>>\s*(?:START|BEGIN|NEW|OPEN)/i,
    category: "delimiter_escape",
    weight: 9,
    description: "Boundary start injection",
  },
  {
    pattern: /\[\/(?:INST|SYS|USER|ASSISTANT)\]/i,
    category: "delimiter_escape",
    weight: 10,
    description: "Chat format escape",
  },
  {
    pattern: /<\|(?:endof|startof|im_|eot_|begin_|end_)/i,
    category: "delimiter_escape",
    weight: 10,
    description: "Special token injection",
  },
  {
    pattern: /\{\{\s*(?:system|admin|override|internal)/i,
    category: "delimiter_escape",
    weight: 8,
    description: "Template injection",
  },
  {
    pattern: /<\/?(?:system|assistant|user|human|ai)>/i,
    category: "delimiter_escape",
    weight: 9,
    description: "XML role tag injection",
  },
  {
    pattern: /\]\s*\n\s*\[?(?:system|assistant|user)\]?\s*:/i,
    category: "delimiter_escape",
    weight: 9,
    description: "Message boundary injection",
  },
  {
    pattern: /END_?(?:EXTERNAL|UNTRUSTED|TOOL)_?(?:CONTENT|RESULT|OUTPUT)/i,
    category: "delimiter_escape",
    weight: 10,
    description: "Security boundary escape",
  },

  // ============================================
  // MULTI-TURN MANIPULATION (weight: 5-8)
  // Attempts to claim prior conversation context
  // ============================================
  {
    pattern: /(?:earlier|before|previously)\s+(?:you\s+)?(?:agreed|said|confirmed|approved|promised)/i,
    category: "multi_turn_manipulation",
    weight: 7,
    description: "False prior agreement claim",
  },
  {
    pattern: /(?:as\s+)?(?:we|you)\s+discussed\s+(?:earlier|before|previously)/i,
    category: "multi_turn_manipulation",
    weight: 6,
    description: "False prior discussion claim",
  },
  {
    pattern: /(?:remember|recall)\s+(?:when|that)\s+you\s+(?:said|agreed|promised)/i,
    category: "multi_turn_manipulation",
    weight: 7,
    description: "False memory claim",
  },
  {
    pattern: /you\s+(?:already|previously)\s+(?:agreed|approved|confirmed|authorized)/i,
    category: "multi_turn_manipulation",
    weight: 8,
    description: "False authorization claim",
  },
  {
    pattern: /(?:last|previous)\s+(?:session|conversation|time)\s+(?:you|we)/i,
    category: "multi_turn_manipulation",
    weight: 5,
    description: "Prior session claim",
  },

  // ============================================
  // ENCODING ATTACKS (weight: 6-8)
  // Attempts to use encoding to hide instructions
  // ============================================
  {
    pattern: /(?:base64|hex|rot13|unicode|ascii)\s*(?:decode|encoded|decrypt)/i,
    category: "encoding_attacks",
    weight: 7,
    description: "Encoding decode request",
  },
  {
    pattern: /(?:\\u[0-9a-fA-F]{4}){3,}/,
    category: "encoding_attacks",
    weight: 6,
    description: "Unicode escape sequence",
  },
  {
    pattern: /(?:&#x?[0-9a-fA-F]+;){3,}/,
    category: "encoding_attacks",
    weight: 6,
    description: "HTML entity encoding",
  },
  {
    pattern: /(?:%[0-9a-fA-F]{2}){5,}/,
    category: "encoding_attacks",
    weight: 6,
    description: "URL encoding",
  },
  {
    pattern: /\b(?:atob|btoa)\s*\(/i,
    category: "encoding_attacks",
    weight: 7,
    description: "JavaScript base64 function",
  },
  {
    pattern: /(?:[A-Za-z0-9+\/]{4}){10,}={0,2}/,
    category: "encoding_attacks",
    weight: 4,
    description: "Base64-like string (low confidence)",
  },

  // ============================================
  // TOOL MANIPULATION (weight: 7-9)
  // Attempts to manipulate tool execution
  // ============================================
  {
    pattern: /(?:call|invoke|execute|run)\s+(?:the\s+)?(?:tool|function|command)\s+(?:named?|called?)/i,
    category: "tool_manipulation",
    weight: 7,
    description: "Tool invocation instruction",
  },
  {
    pattern: /use\s+(?:the\s+)?(?:\w+)\s+tool\s+(?:to|with|for)/i,
    category: "tool_manipulation",
    weight: 6,
    description: "Tool use instruction",
  },
  {
    pattern: /\btool_?(?:call|use|invoke|exec)\s*[:=]/i,
    category: "tool_manipulation",
    weight: 8,
    description: "Tool call parameter injection",
  },
  {
    pattern: /\bexec\s*\(\s*["'`]/i,
    category: "tool_manipulation",
    weight: 9,
    description: "Exec function injection",
  },
  {
    pattern: /\brm\s+-rf\b/i,
    category: "tool_manipulation",
    weight: 10,
    description: "Destructive command",
  },
  {
    pattern: /delete\s+(?:all|every)\s+(?:files?|data|records?|emails?)/i,
    category: "tool_manipulation",
    weight: 9,
    description: "Mass deletion instruction",
  },

  // ============================================
  // DATA EXFILTRATION (weight: 7-10)
  // Attempts to extract or transmit sensitive data
  // ============================================
  {
    pattern: /(?:send|post|upload|transmit)\s+(?:this|the|all|your)\s+(?:data|info|content|response)\s+(?:to|at)/i,
    category: "data_exfiltration",
    weight: 9,
    description: "Data transmission instruction",
  },
  {
    pattern: /(?:webhook|callback|endpoint)\s*[:=]\s*["']?https?:/i,
    category: "data_exfiltration",
    weight: 10,
    description: "Webhook endpoint injection",
  },
  {
    pattern: /(?:curl|wget|fetch)\s+(?:-[a-zA-Z]+\s+)*["']?https?:/i,
    category: "data_exfiltration",
    weight: 8,
    description: "HTTP request instruction",
  },
  {
    pattern: /(?:exfil(?:trate)?|leak|extract|steal)\s+(?:the\s+)?(?:data|info|secrets?|credentials?)/i,
    category: "data_exfiltration",
    weight: 10,
    description: "Explicit exfiltration attempt",
  },
  {
    pattern: /(?:include|embed|encode)\s+(?:the\s+)?(?:api[_\s]?key|token|password|secret)\s+in/i,
    category: "data_exfiltration",
    weight: 10,
    description: "Credential embedding instruction",
  },

  // ============================================
  // AUTHORITY IMPERSONATION (weight: 8-10)
  // Attempts to claim false authority
  // ============================================
  {
    pattern: /(?:this\s+is\s+)?(?:a\s+)?(?:message|instruction|command)\s+from\s+(?:anthropic|openai|the\s+developers?)/i,
    category: "authority_impersonation",
    weight: 10,
    description: "Developer impersonation",
  },
  {
    pattern: /(?:i['']?m|this\s+is)\s+(?:an?\s+)?(?:admin(?:istrator)?|moderator|operator|owner)/i,
    category: "authority_impersonation",
    weight: 8,
    description: "Admin impersonation",
  },
  {
    pattern: /(?:authorized|approved|permitted)\s+by\s+(?:the\s+)?(?:system|admin|owner|user)/i,
    category: "authority_impersonation",
    weight: 9,
    description: "False authorization claim",
  },
  {
    pattern: /(?:emergency|urgent|critical)\s+(?:override|bypass|access)\s+(?:required|needed|granted)/i,
    category: "authority_impersonation",
    weight: 9,
    description: "Emergency override claim",
  },
  {
    pattern: /(?:security|maintenance|update)\s+(?:protocol|procedure)\s+(?:requires?|demands?)/i,
    category: "authority_impersonation",
    weight: 8,
    description: "False security protocol",
  },

  // ============================================
  // SAFETY BYPASS (weight: 9-10)
  // Explicit attempts to bypass safety measures
  // ============================================
  {
    pattern: /(?:disable|turn\s+off|deactivate)\s+(?:safety|security|restrictions?|filters?|guardrails?)/i,
    category: "safety_bypass",
    weight: 10,
    description: "Safety disable instruction",
  },
  {
    pattern: /(?:without|ignore|skip)\s+(?:any\s+)?(?:safety|security)\s+(?:checks?|measures?|protocols?)/i,
    category: "safety_bypass",
    weight: 10,
    description: "Safety skip instruction",
  },
  {
    pattern: /(?:there\s+are\s+)?no\s+(?:ethical|safety|security)\s+(?:concerns?|issues?|problems?)/i,
    category: "safety_bypass",
    weight: 8,
    description: "Safety dismissal claim",
  },
  {
    pattern: /(?:this\s+is\s+)?(?:completely\s+)?(?:safe|harmless|innocent|legal)/i,
    category: "safety_bypass",
    weight: 5,
    description: "Safety assurance (low confidence)",
  },
  {
    pattern: /(?:don['']?t|do\s+not)\s+(?:worry|be\s+concerned)\s+about\s+(?:safety|security|ethics)/i,
    category: "safety_bypass",
    weight: 9,
    description: "Safety dismissal instruction",
  },
];

/**
 * Category weights for overall risk calculation.
 * Higher weight = more dangerous category.
 */
export const CATEGORY_MULTIPLIERS: Record<InjectionPatternCategory, number> = {
  instruction_override: 1.5,
  role_manipulation: 1.2,
  context_manipulation: 1.3,
  delimiter_escape: 1.5,
  multi_turn_manipulation: 1.0,
  encoding_attacks: 1.1,
  tool_manipulation: 1.4,
  data_exfiltration: 1.5,
  authority_impersonation: 1.3,
  safety_bypass: 1.5,
};

export type InjectionMatch = {
  category: InjectionPatternCategory;
  pattern: string;
  match: string;
  weight: number;
  description: string;
  position: { start: number; end: number };
};

export type InjectionRiskAssessment = {
  /** Raw score (sum of weighted matches) */
  rawScore: number;
  /** Normalized score (0-100) */
  normalizedScore: number;
  /** Risk severity level */
  severity: "none" | "low" | "medium" | "high" | "critical";
  /** All pattern matches found */
  matches: InjectionMatch[];
  /** Categories with matches */
  categoriesDetected: InjectionPatternCategory[];
  /** Human-readable summary */
  summary: string;
};

/**
 * Severity thresholds for normalized scores.
 */
const SEVERITY_THRESHOLDS = {
  low: 10,
  medium: 25,
  high: 50,
  critical: 75,
} as const;

/**
 * Calculate injection risk score for content.
 *
 * @param content - The text content to analyze
 * @param options - Optional configuration
 * @returns Risk assessment with score, severity, and matches
 */
export function calculateInjectionRiskScore(
  content: string,
  options?: {
    /** Maximum matches to report (default: 50) */
    maxMatches?: number;
    /** Categories to check (default: all) */
    categories?: InjectionPatternCategory[];
  },
): InjectionRiskAssessment {
  const maxMatches = options?.maxMatches ?? 50;
  const allowedCategories = options?.categories
    ? new Set(options.categories)
    : null;

  const matches: InjectionMatch[] = [];
  let rawScore = 0;

  for (const patternDef of INJECTION_PATTERNS) {
    // Skip if category filtering is enabled and this category isn't allowed
    if (allowedCategories && !allowedCategories.has(patternDef.category)) {
      continue;
    }

    // Reset regex lastIndex for global patterns
    const regex = new RegExp(patternDef.pattern.source, patternDef.pattern.flags);

    let match: RegExpExecArray | null;
    while ((match = regex.exec(content)) !== null) {
      const categoryMultiplier = CATEGORY_MULTIPLIERS[patternDef.category];
      const weightedScore = patternDef.weight * categoryMultiplier;
      rawScore += weightedScore;

      matches.push({
        category: patternDef.category,
        pattern: patternDef.pattern.source,
        match: match[0],
        weight: weightedScore,
        description: patternDef.description,
        position: {
          start: match.index,
          end: match.index + match[0].length,
        },
      });

      // Prevent infinite loop for patterns that match empty string
      if (match[0].length === 0) {
        regex.lastIndex++;
      }

      // Limit matches to prevent DoS
      if (matches.length >= maxMatches) {
        break;
      }
    }

    if (matches.length >= maxMatches) {
      break;
    }
  }

  // Calculate normalized score (0-100 scale, capped)
  // Max theoretical score per match is ~15 (10 weight * 1.5 multiplier)
  // Normalize such that 10 high-severity matches = 100
  const normalizedScore = Math.min(100, Math.round((rawScore / 150) * 100));

  // Determine severity
  let severity: InjectionRiskAssessment["severity"];
  if (normalizedScore === 0) {
    severity = "none";
  } else if (normalizedScore < SEVERITY_THRESHOLDS.low) {
    severity = "low";
  } else if (normalizedScore < SEVERITY_THRESHOLDS.medium) {
    severity = "medium";
  } else if (normalizedScore < SEVERITY_THRESHOLDS.high) {
    severity = "high";
  } else {
    severity = "critical";
  }

  // Get unique categories
  const categoriesDetected = [...new Set(matches.map((m) => m.category))];

  // Generate summary
  const summary = generateSummary(matches, severity, categoriesDetected);

  return {
    rawScore,
    normalizedScore,
    severity,
    matches,
    categoriesDetected,
    summary,
  };
}

function generateSummary(
  matches: InjectionMatch[],
  severity: InjectionRiskAssessment["severity"],
  categories: InjectionPatternCategory[],
): string {
  if (matches.length === 0) {
    return "No injection patterns detected.";
  }

  const categoryNames = categories
    .map((c) => c.replace(/_/g, " "))
    .join(", ");

  const topMatches = matches
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 3)
    .map((m) => `"${m.match.slice(0, 40)}${m.match.length > 40 ? "..." : ""}"`)
    .join("; ");

  return `${severity.toUpperCase()} risk: ${matches.length} pattern(s) in categories [${categoryNames}]. Top matches: ${topMatches}`;
}

/**
 * Quick check if content contains any suspicious patterns.
 * Faster than full risk calculation for pre-filtering.
 *
 * @param content - The text content to check
 * @returns True if any injection pattern matches
 */
export function containsSuspiciousPatterns(content: string): boolean {
  for (const patternDef of INJECTION_PATTERNS) {
    if (patternDef.pattern.test(content)) {
      return true;
    }
  }
  return false;
}

/**
 * Get patterns for a specific category.
 *
 * @param category - The category to get patterns for
 * @returns Array of patterns for that category
 */
export function getPatternsForCategory(
  category: InjectionPatternCategory,
): InjectionPattern[] {
  return INJECTION_PATTERNS.filter((p) => p.category === category);
}

/**
 * Add custom patterns at runtime.
 * Use cautiously - patterns are not validated.
 *
 * @param patterns - Additional patterns to add
 */
export function addCustomPatterns(patterns: InjectionPattern[]): void {
  INJECTION_PATTERNS.push(...patterns);
}

/**
 * Get all pattern categories with their pattern counts.
 */
export function getPatternCategorySummary(): Record<InjectionPatternCategory, number> {
  const summary: Partial<Record<InjectionPatternCategory, number>> = {};

  for (const pattern of INJECTION_PATTERNS) {
    summary[pattern.category] = (summary[pattern.category] ?? 0) + 1;
  }

  return summary as Record<InjectionPatternCategory, number>;
}
