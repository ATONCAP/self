/**
 * Security metrics collection and reporting.
 *
 * This module aggregates security-related metrics across all security
 * components for monitoring, alerting, and analysis.
 *
 * SECURITY: Metrics are essential for detecting anomalies and tracking
 * the effectiveness of security controls.
 */

export type SecurityMetricType =
  | "injection_attempt"
  | "credential_leak_blocked"
  | "rate_limit_triggered"
  | "abuse_detected"
  | "canary_detected"
  | "memory_blocked"
  | "output_blocked"
  | "tool_result_suspicious";

export type SecurityEvent = {
  type: SecurityMetricType;
  timestamp: number;
  sessionKey?: string;
  severity: "low" | "medium" | "high" | "critical";
  details: Record<string, unknown>;
};

export type MetricsSummary = {
  /** Total events in the collection period */
  totalEvents: number;
  /** Events by type */
  eventsByType: Record<SecurityMetricType, number>;
  /** Events by severity */
  eventsBySeverity: Record<string, number>;
  /** Unique sessions with security events */
  uniqueSessions: number;
  /** Time range of collected metrics */
  timeRange: {
    start: number;
    end: number;
    durationMs: number;
  };
  /** Top sessions by event count */
  topSessions: Array<{ sessionKey: string; eventCount: number }>;
  /** Event rate per hour */
  eventsPerHour: number;
};

export type MetricsConfig = {
  /** Enable metrics collection */
  enabled: boolean;
  /** Maximum events to retain */
  maxEvents: number;
  /** Maximum age of events to retain (ms) */
  maxEventAge: number;
  /** Callback for real-time event streaming */
  onEvent?: (event: SecurityEvent) => void;
  /** Alert thresholds */
  alertThresholds: {
    criticalEventsPerHour: number;
    highEventsPerHour: number;
    totalEventsPerHour: number;
  };
};

export const DEFAULT_METRICS_CONFIG: MetricsConfig = {
  enabled: true,
  maxEvents: 10_000,
  maxEventAge: 24 * 60 * 60 * 1000, // 24 hours
  onEvent: undefined,
  alertThresholds: {
    criticalEventsPerHour: 5,
    highEventsPerHour: 20,
    totalEventsPerHour: 100,
  },
};

/**
 * Security metrics collector.
 */
export class SecurityMetrics {
  private events: SecurityEvent[] = [];
  private config: MetricsConfig;
  private eventCounters = new Map<SecurityMetricType, number>();
  private sessionEventCounts = new Map<string, number>();
  private lastPruneTime = Date.now();
  private pruneInterval = 60_000; // 1 minute

  constructor(config?: Partial<MetricsConfig>) {
    this.config = { ...DEFAULT_METRICS_CONFIG, ...config };
    this.initializeCounters();
  }

  /**
   * Record a security event.
   */
  recordEvent(
    type: SecurityMetricType,
    severity: SecurityEvent["severity"],
    details: Record<string, unknown> = {},
    sessionKey?: string,
  ): void {
    if (!this.config.enabled) {
      return;
    }

    const event: SecurityEvent = {
      type,
      timestamp: Date.now(),
      sessionKey,
      severity,
      details,
    };

    this.events.push(event);

    // Update counters
    this.eventCounters.set(type, (this.eventCounters.get(type) ?? 0) + 1);

    if (sessionKey) {
      this.sessionEventCounts.set(
        sessionKey,
        (this.sessionEventCounts.get(sessionKey) ?? 0) + 1
      );
    }

    // Trigger callback
    if (this.config.onEvent) {
      this.config.onEvent(event);
    }

    // Periodic pruning
    this.maybePrune();
  }

  /**
   * Record an injection attempt.
   */
  recordInjectionAttempt(
    sessionKey: string,
    score: number,
    categories: string[],
  ): void {
    this.recordEvent(
      "injection_attempt",
      score >= 50 ? "high" : score >= 25 ? "medium" : "low",
      { score, categories },
      sessionKey
    );
  }

  /**
   * Record a blocked credential leak.
   */
  recordCredentialLeakBlocked(
    sessionKey: string,
    credentialType: string,
  ): void {
    this.recordEvent(
      "credential_leak_blocked",
      "critical",
      { credentialType },
      sessionKey
    );
  }

  /**
   * Record a rate limit trigger.
   */
  recordRateLimitTriggered(
    sessionKey: string,
    limitType: string,
  ): void {
    this.recordEvent(
      "rate_limit_triggered",
      "medium",
      { limitType },
      sessionKey
    );
  }

  /**
   * Record abuse detection.
   */
  recordAbuseDetected(
    sessionKey: string,
    patterns: string[],
    action: string,
  ): void {
    this.recordEvent(
      "abuse_detected",
      "high",
      { patterns, action },
      sessionKey
    );
  }

  /**
   * Record canary detection.
   */
  recordCanaryDetected(
    canaryName: string,
    location: string,
    source: string,
  ): void {
    this.recordEvent(
      "canary_detected",
      "critical",
      { canaryName, location, source }
    );
  }

  /**
   * Record blocked memory content.
   */
  recordMemoryBlocked(
    source: string,
    filePath: string | undefined,
    score: number,
  ): void {
    this.recordEvent(
      "memory_blocked",
      "high",
      { source, filePath, score }
    );
  }

  /**
   * Record blocked output.
   */
  recordOutputBlocked(
    sessionKey: string,
    issueTypes: string[],
  ): void {
    this.recordEvent(
      "output_blocked",
      "critical",
      { issueTypes },
      sessionKey
    );
  }

  /**
   * Record suspicious tool result.
   */
  recordSuspiciousToolResult(
    sessionKey: string,
    toolName: string,
    score: number,
  ): void {
    this.recordEvent(
      "tool_result_suspicious",
      score >= 50 ? "high" : "medium",
      { toolName, score },
      sessionKey
    );
  }

  /**
   * Get summary of collected metrics.
   */
  getSummary(timeWindowMs?: number): MetricsSummary {
    const now = Date.now();
    const windowStart = timeWindowMs ? now - timeWindowMs : 0;

    const filteredEvents = this.events.filter((e) => e.timestamp >= windowStart);

    // Count by type
    const eventsByType: Record<SecurityMetricType, number> = {} as any;
    for (const type of this.eventCounters.keys()) {
      eventsByType[type] = 0;
    }
    for (const event of filteredEvents) {
      eventsByType[event.type] = (eventsByType[event.type] ?? 0) + 1;
    }

    // Count by severity
    const eventsBySeverity: Record<string, number> = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    };
    for (const event of filteredEvents) {
      eventsBySeverity[event.severity]++;
    }

    // Unique sessions
    const uniqueSessions = new Set(
      filteredEvents.map((e) => e.sessionKey).filter(Boolean)
    ).size;

    // Time range
    const timestamps = filteredEvents.map((e) => e.timestamp);
    const start = timestamps.length > 0 ? Math.min(...timestamps) : now;
    const end = timestamps.length > 0 ? Math.max(...timestamps) : now;
    const durationMs = end - start || 1;

    // Top sessions
    const sessionCounts = new Map<string, number>();
    for (const event of filteredEvents) {
      if (event.sessionKey) {
        sessionCounts.set(
          event.sessionKey,
          (sessionCounts.get(event.sessionKey) ?? 0) + 1
        );
      }
    }
    const topSessions = Array.from(sessionCounts.entries())
      .map(([sessionKey, eventCount]) => ({ sessionKey, eventCount }))
      .sort((a, b) => b.eventCount - a.eventCount)
      .slice(0, 10);

    // Events per hour
    const hoursInWindow = durationMs / (60 * 60 * 1000);
    const eventsPerHour = hoursInWindow > 0
      ? filteredEvents.length / hoursInWindow
      : filteredEvents.length;

    return {
      totalEvents: filteredEvents.length,
      eventsByType,
      eventsBySeverity,
      uniqueSessions,
      timeRange: { start, end, durationMs },
      topSessions,
      eventsPerHour,
    };
  }

  /**
   * Check if alert thresholds are exceeded.
   */
  checkAlertThresholds(): {
    alertTriggered: boolean;
    alerts: string[];
  } {
    const hourMs = 60 * 60 * 1000;
    const summary = this.getSummary(hourMs);
    const alerts: string[] = [];

    const criticalEvents =
      (summary.eventsBySeverity.critical ?? 0);
    const highEvents =
      (summary.eventsBySeverity.high ?? 0);

    if (criticalEvents >= this.config.alertThresholds.criticalEventsPerHour) {
      alerts.push(
        `Critical events threshold exceeded: ${criticalEvents} in last hour ` +
        `(threshold: ${this.config.alertThresholds.criticalEventsPerHour})`
      );
    }

    if (highEvents >= this.config.alertThresholds.highEventsPerHour) {
      alerts.push(
        `High severity events threshold exceeded: ${highEvents} in last hour ` +
        `(threshold: ${this.config.alertThresholds.highEventsPerHour})`
      );
    }

    if (summary.totalEvents >= this.config.alertThresholds.totalEventsPerHour) {
      alerts.push(
        `Total events threshold exceeded: ${summary.totalEvents} in last hour ` +
        `(threshold: ${this.config.alertThresholds.totalEventsPerHour})`
      );
    }

    return {
      alertTriggered: alerts.length > 0,
      alerts,
    };
  }

  /**
   * Get recent events.
   */
  getRecentEvents(
    limit: number = 100,
    filter?: {
      type?: SecurityMetricType;
      severity?: SecurityEvent["severity"];
      sessionKey?: string;
    },
  ): SecurityEvent[] {
    let filtered = [...this.events];

    if (filter?.type) {
      filtered = filtered.filter((e) => e.type === filter.type);
    }
    if (filter?.severity) {
      filtered = filtered.filter((e) => e.severity === filter.severity);
    }
    if (filter?.sessionKey) {
      filtered = filtered.filter((e) => e.sessionKey === filter.sessionKey);
    }

    return filtered.slice(-limit);
  }

  /**
   * Get events for a specific session.
   */
  getSessionEvents(sessionKey: string, limit?: number): SecurityEvent[] {
    const events = this.events.filter((e) => e.sessionKey === sessionKey);
    return limit ? events.slice(-limit) : events;
  }

  /**
   * Get all-time counters.
   */
  getCounters(): Record<SecurityMetricType, number> {
    return Object.fromEntries(this.eventCounters) as Record<SecurityMetricType, number>;
  }

  /**
   * Clear all metrics.
   */
  clear(): void {
    this.events = [];
    this.sessionEventCounts.clear();
    this.initializeCounters();
  }

  /**
   * Export metrics for persistence.
   */
  export(): {
    events: SecurityEvent[];
    counters: Record<SecurityMetricType, number>;
  } {
    return {
      events: [...this.events],
      counters: Object.fromEntries(this.eventCounters) as Record<SecurityMetricType, number>,
    };
  }

  /**
   * Import metrics from persistence.
   */
  import(data: {
    events?: SecurityEvent[];
    counters?: Record<SecurityMetricType, number>;
  }): void {
    if (data.events) {
      this.events = [...data.events];
    }
    if (data.counters) {
      for (const [type, count] of Object.entries(data.counters)) {
        this.eventCounters.set(type as SecurityMetricType, count);
      }
    }
  }

  /**
   * Update configuration.
   */
  updateConfig(config: Partial<MetricsConfig>): void {
    this.config = { ...this.config, ...config };
  }

  private initializeCounters(): void {
    const types: SecurityMetricType[] = [
      "injection_attempt",
      "credential_leak_blocked",
      "rate_limit_triggered",
      "abuse_detected",
      "canary_detected",
      "memory_blocked",
      "output_blocked",
      "tool_result_suspicious",
    ];
    for (const type of types) {
      if (!this.eventCounters.has(type)) {
        this.eventCounters.set(type, 0);
      }
    }
  }

  private maybePrune(): void {
    const now = Date.now();
    if (now - this.lastPruneTime < this.pruneInterval) {
      return;
    }

    this.lastPruneTime = now;
    this.prune();
  }

  private prune(): void {
    const now = Date.now();
    const cutoff = now - this.config.maxEventAge;

    // Remove old events
    this.events = this.events.filter((e) => e.timestamp > cutoff);

    // Trim to max size
    if (this.events.length > this.config.maxEvents) {
      this.events = this.events.slice(-this.config.maxEvents);
    }
  }
}

/**
 * Create a security metrics instance.
 */
export function createSecurityMetrics(
  config?: Partial<MetricsConfig>,
): SecurityMetrics {
  return new SecurityMetrics(config);
}

/**
 * Global security metrics instance.
 */
let globalMetrics: SecurityMetrics | null = null;

/**
 * Get the global security metrics instance.
 */
export function getGlobalSecurityMetrics(): SecurityMetrics {
  if (!globalMetrics) {
    globalMetrics = new SecurityMetrics();
  }
  return globalMetrics;
}

/**
 * Initialize global security metrics with custom config.
 */
export function initGlobalSecurityMetrics(
  config: Partial<MetricsConfig>,
): SecurityMetrics {
  globalMetrics = new SecurityMetrics(config);
  return globalMetrics;
}

/**
 * Format metrics summary for logging.
 */
export function formatMetricsSummary(summary: MetricsSummary): string {
  const lines: string[] = [
    "=== Security Metrics Summary ===",
    `Total Events: ${summary.totalEvents}`,
    `Events/Hour: ${summary.eventsPerHour.toFixed(1)}`,
    `Unique Sessions: ${summary.uniqueSessions}`,
    "",
    "By Severity:",
    `  Critical: ${summary.eventsBySeverity.critical}`,
    `  High: ${summary.eventsBySeverity.high}`,
    `  Medium: ${summary.eventsBySeverity.medium}`,
    `  Low: ${summary.eventsBySeverity.low}`,
    "",
    "By Type:",
  ];

  for (const [type, count] of Object.entries(summary.eventsByType)) {
    if (count > 0) {
      lines.push(`  ${type}: ${count}`);
    }
  }

  if (summary.topSessions.length > 0) {
    lines.push("", "Top Sessions:");
    for (const session of summary.topSessions.slice(0, 5)) {
      lines.push(`  ${session.sessionKey}: ${session.eventCount} events`);
    }
  }

  lines.push("===============================");

  return lines.join("\n");
}
