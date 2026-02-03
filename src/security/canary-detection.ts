/**
 * Canary token detection for data leakage monitoring.
 *
 * Canary tokens are unique strings placed in sensitive locations.
 * If they appear in unexpected output, it indicates data leakage
 * or unauthorized access to protected content.
 *
 * SECURITY: Canary tokens are an early warning system for data breaches.
 */

import crypto from "node:crypto";

export type CanaryTokenConfig = {
  /** The canary token value */
  value: string;
  /** Human-readable name for the canary */
  name: string;
  /** Where this canary was placed */
  location: string;
  /** Severity if this canary is detected */
  severity: "warn" | "critical";
  /** When this canary was created */
  createdAt: number;
  /** Optional expiration time */
  expiresAt?: number;
};

export type CanaryDetectionResult = {
  /** Whether any canary was detected */
  detected: boolean;
  /** List of detected canaries */
  detectedCanaries: Array<{
    canary: CanaryTokenConfig;
    position: number;
    context: string;
  }>;
  /** Summary for logging */
  summary: string;
};

export type CanaryManagerConfig = {
  /** Enable canary detection */
  enabled: boolean;
  /** Prefix for generated canary tokens */
  tokenPrefix: string;
  /** Length of random portion of canary tokens */
  tokenRandomLength: number;
  /** Context length to capture around detected canaries */
  contextLength: number;
  /** Alert callback when canary is detected */
  onCanaryDetected?: (result: CanaryDetectionResult) => void;
};

export const DEFAULT_CANARY_CONFIG: CanaryManagerConfig = {
  enabled: true,
  tokenPrefix: "CANARY",
  tokenRandomLength: 32,
  contextLength: 50,
  onCanaryDetected: undefined,
};

/**
 * Generate a unique canary token.
 *
 * @param location - Description of where this canary will be placed
 * @param name - Human-readable name for the canary
 * @param prefix - Optional custom prefix
 * @returns A new canary token configuration
 */
export function generateCanaryToken(
  location: string,
  name: string,
  prefix: string = "CANARY",
): CanaryTokenConfig {
  const randomBytes = crypto.randomBytes(16).toString("hex");
  const locationSlug = location
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "_")
    .slice(0, 20);

  const value = `${prefix}_${locationSlug}_${randomBytes}`;

  return {
    value,
    name,
    location,
    severity: "critical",
    createdAt: Date.now(),
  };
}

/**
 * Check content for canary token presence.
 *
 * @param content - Content to check for canaries
 * @param canaries - List of canary tokens to look for
 * @param config - Detection configuration
 * @returns Detection result with found canaries
 */
export function detectCanaries(
  content: string,
  canaries: CanaryTokenConfig[],
  config: Partial<CanaryManagerConfig> = {},
): CanaryDetectionResult {
  const mergedConfig = { ...DEFAULT_CANARY_CONFIG, ...config };

  if (!mergedConfig.enabled || canaries.length === 0) {
    return {
      detected: false,
      detectedCanaries: [],
      summary: "Canary detection disabled or no canaries configured",
    };
  }

  const detected: CanaryDetectionResult["detectedCanaries"] = [];

  for (const canary of canaries) {
    // Skip expired canaries
    if (canary.expiresAt && Date.now() > canary.expiresAt) {
      continue;
    }

    // Search for canary in content
    let position = content.indexOf(canary.value);
    while (position !== -1) {
      // Extract context around the canary
      const contextStart = Math.max(0, position - mergedConfig.contextLength);
      const contextEnd = Math.min(
        content.length,
        position + canary.value.length + mergedConfig.contextLength
      );
      const context = content.slice(contextStart, contextEnd);

      detected.push({
        canary,
        position,
        context: contextStart > 0 ? `...${context}` : context,
      });

      // Look for more occurrences
      position = content.indexOf(canary.value, position + 1);
    }
  }

  if (detected.length === 0) {
    return {
      detected: false,
      detectedCanaries: [],
      summary: "No canary tokens detected",
    };
  }

  // Generate summary
  const uniqueCanaries = new Set(detected.map((d) => d.canary.name));
  const criticalCount = detected.filter((d) => d.canary.severity === "critical").length;
  const summary = `CANARY ALERT: ${detected.length} detection(s) of ${uniqueCanaries.size} canary token(s) [${Array.from(uniqueCanaries).join(", ")}]${criticalCount > 0 ? ` (${criticalCount} critical)` : ""}`;

  const result: CanaryDetectionResult = {
    detected: true,
    detectedCanaries: detected,
    summary,
  };

  // Trigger callback if configured
  if (mergedConfig.onCanaryDetected) {
    mergedConfig.onCanaryDetected(result);
  }

  return result;
}

/**
 * Canary token manager for centralized canary handling.
 */
export class CanaryManager {
  private canaries = new Map<string, CanaryTokenConfig>();
  private config: CanaryManagerConfig;
  private detectionHistory: Array<{
    timestamp: number;
    result: CanaryDetectionResult;
    source: string;
  }> = [];
  private maxHistorySize = 1000;

  constructor(config?: Partial<CanaryManagerConfig>) {
    this.config = { ...DEFAULT_CANARY_CONFIG, ...config };
  }

  /**
   * Generate and register a new canary token.
   */
  createCanary(
    location: string,
    name: string,
    options?: {
      severity?: "warn" | "critical";
      expiresInMs?: number;
    },
  ): CanaryTokenConfig {
    const canary = generateCanaryToken(location, name, this.config.tokenPrefix);

    if (options?.severity) {
      canary.severity = options.severity;
    }
    if (options?.expiresInMs) {
      canary.expiresAt = Date.now() + options.expiresInMs;
    }

    this.canaries.set(canary.value, canary);
    return canary;
  }

  /**
   * Register an existing canary token.
   */
  registerCanary(canary: CanaryTokenConfig): void {
    this.canaries.set(canary.value, canary);
  }

  /**
   * Remove a canary token.
   */
  removeCanary(value: string): boolean {
    return this.canaries.delete(value);
  }

  /**
   * Check content for any registered canaries.
   */
  check(content: string, source: string = "unknown"): CanaryDetectionResult {
    const result = detectCanaries(
      content,
      Array.from(this.canaries.values()),
      this.config
    );

    // Record detection if canaries were found
    if (result.detected) {
      this.recordDetection(result, source);
    }

    return result;
  }

  /**
   * Get all registered canaries.
   */
  getCanaries(): CanaryTokenConfig[] {
    return Array.from(this.canaries.values());
  }

  /**
   * Get canary by value.
   */
  getCanary(value: string): CanaryTokenConfig | undefined {
    return this.canaries.get(value);
  }

  /**
   * Get detection history.
   */
  getDetectionHistory(limit?: number): typeof this.detectionHistory {
    const history = [...this.detectionHistory];
    return limit ? history.slice(-limit) : history;
  }

  /**
   * Get detection statistics.
   */
  getStats(): {
    totalCanaries: number;
    activeCanaries: number;
    expiredCanaries: number;
    totalDetections: number;
    criticalDetections: number;
  } {
    const now = Date.now();
    let activeCanaries = 0;
    let expiredCanaries = 0;

    for (const canary of this.canaries.values()) {
      if (canary.expiresAt && now > canary.expiresAt) {
        expiredCanaries++;
      } else {
        activeCanaries++;
      }
    }

    const criticalDetections = this.detectionHistory.filter((h) =>
      h.result.detectedCanaries.some((d) => d.canary.severity === "critical")
    ).length;

    return {
      totalCanaries: this.canaries.size,
      activeCanaries,
      expiredCanaries,
      totalDetections: this.detectionHistory.length,
      criticalDetections,
    };
  }

  /**
   * Clear expired canaries.
   */
  pruneExpired(): number {
    const now = Date.now();
    let pruned = 0;

    for (const [value, canary] of this.canaries) {
      if (canary.expiresAt && now > canary.expiresAt) {
        this.canaries.delete(value);
        pruned++;
      }
    }

    return pruned;
  }

  /**
   * Clear all canaries.
   */
  clearAll(): void {
    this.canaries.clear();
    this.detectionHistory = [];
  }

  /**
   * Export canaries for persistence.
   */
  exportCanaries(): CanaryTokenConfig[] {
    return Array.from(this.canaries.values());
  }

  /**
   * Import canaries from persistence.
   */
  importCanaries(canaries: CanaryTokenConfig[]): void {
    for (const canary of canaries) {
      this.canaries.set(canary.value, canary);
    }
  }

  /**
   * Update configuration.
   */
  updateConfig(config: Partial<CanaryManagerConfig>): void {
    this.config = { ...this.config, ...config };
  }

  private recordDetection(result: CanaryDetectionResult, source: string): void {
    this.detectionHistory.push({
      timestamp: Date.now(),
      result,
      source,
    });

    // Prune old history
    if (this.detectionHistory.length > this.maxHistorySize) {
      this.detectionHistory = this.detectionHistory.slice(
        -Math.floor(this.maxHistorySize / 2)
      );
    }
  }
}

/**
 * Create a canary manager instance.
 */
export function createCanaryManager(
  config?: Partial<CanaryManagerConfig>,
): CanaryManager {
  return new CanaryManager(config);
}

/**
 * Predefined canary locations for common use cases.
 */
export const CANARY_LOCATIONS = {
  SYSTEM_PROMPT: "system_prompt",
  MEMORY_FILE: "memory_file",
  CREDENTIALS_FILE: "credentials_file",
  CONFIG_FILE: "config_file",
  SESSION_DATA: "session_data",
  KNOWLEDGE_BASE: "knowledge_base",
  AGENT_IDENTITY: "agent_identity",
} as const;

/**
 * Generate canaries for standard locations.
 */
export function generateStandardCanaries(
  manager: CanaryManager,
): Map<string, CanaryTokenConfig> {
  const canaries = new Map<string, CanaryTokenConfig>();

  for (const [name, location] of Object.entries(CANARY_LOCATIONS)) {
    const canary = manager.createCanary(location, name, {
      severity: "critical",
    });
    canaries.set(location, canary);
  }

  return canaries;
}

/**
 * Format canary detection result for logging.
 */
export function formatCanaryAlert(result: CanaryDetectionResult): string {
  if (!result.detected) {
    return "No canary tokens detected.";
  }

  const lines: string[] = [
    "=== CANARY TOKEN ALERT ===",
    result.summary,
    "",
    "Detected Canaries:",
  ];

  for (const detection of result.detectedCanaries) {
    lines.push(
      `  - ${detection.canary.name} (${detection.canary.severity})`,
      `    Location: ${detection.canary.location}`,
      `    Position: ${detection.position}`,
      `    Context: "${detection.context}"`,
      ""
    );
  }

  lines.push("=========================");

  return lines.join("\n");
}
