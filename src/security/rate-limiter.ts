/**
 * Per-session rate limiting for abuse prevention.
 *
 * This module provides rate limiting on a per-session basis to prevent:
 * - Message flooding
 * - Tool call abuse
 * - Token exhaustion attacks
 *
 * SECURITY: Rate limiting is a defense-in-depth measure against DoS and abuse.
 */

export type RateLimitConfig = {
  /** Maximum messages per minute per session */
  messagesPerMinute: number;
  /** Maximum tool calls per minute per session */
  toolCallsPerMinute: number;
  /** Maximum tokens per hour per session */
  tokensPerHour: number;
  /** Cooldown duration after limit hit (milliseconds) */
  cooldownMs: number;
  /** Session keys exempt from rate limiting (e.g., admin/owner sessions) */
  exemptSessions: string[];
  /** Enable rate limiting */
  enabled: boolean;
};

export const DEFAULT_RATE_LIMIT_CONFIG: RateLimitConfig = {
  messagesPerMinute: 30,
  toolCallsPerMinute: 60,
  tokensPerHour: 500_000,
  cooldownMs: 60_000, // 1 minute cooldown
  exemptSessions: [],
  enabled: true,
};

type RateLimitState = {
  sessionKey: string;
  /** Timestamps of recent messages */
  messageTimestamps: number[];
  /** Timestamps of recent tool calls */
  toolCallTimestamps: number[];
  /** Token usage by hour (ISO hour string -> count) */
  tokenUsageByHour: Map<string, number>;
  /** Cooldown end time (null if not in cooldown) */
  cooldownUntil: number | null;
  /** Number of times rate limit has been triggered */
  limitTriggerCount: number;
  /** Last limit trigger timestamp */
  lastLimitTrigger: number | null;
};

export type RateLimitCheckResult = {
  /** Whether the action is allowed */
  allowed: boolean;
  /** Reason for rejection (if not allowed) */
  reason?: string;
  /** Seconds until allowed (if in cooldown) */
  retryAfterSeconds?: number;
  /** Current usage stats */
  usage: {
    messagesInLastMinute: number;
    toolCallsInLastMinute: number;
    tokensInLastHour: number;
  };
};

export type RateLimitEvent = {
  type: "message" | "tool_call" | "token_usage";
  sessionKey: string;
  timestamp: number;
  /** For tool_call events */
  toolName?: string;
  /** For token_usage events */
  tokenCount?: number;
};

/**
 * Session-based rate limiter.
 */
export class SessionRateLimiter {
  private states = new Map<string, RateLimitState>();
  private config: RateLimitConfig;
  private eventLog: RateLimitEvent[] = [];
  private maxEventLogSize = 10_000;

  constructor(config: Partial<RateLimitConfig> = {}) {
    this.config = { ...DEFAULT_RATE_LIMIT_CONFIG, ...config };
  }

  /**
   * Check if a message is allowed for this session.
   */
  checkMessage(sessionKey: string): RateLimitCheckResult {
    if (!this.config.enabled) {
      return this.createAllowedResult(sessionKey);
    }

    if (this.isExempt(sessionKey)) {
      return this.createAllowedResult(sessionKey);
    }

    const state = this.getOrCreateState(sessionKey);
    const now = Date.now();

    // Check cooldown
    if (state.cooldownUntil && now < state.cooldownUntil) {
      const retryAfterSeconds = Math.ceil((state.cooldownUntil - now) / 1000);
      return {
        allowed: false,
        reason: `Rate limit cooldown active`,
        retryAfterSeconds,
        usage: this.getUsageStats(state),
      };
    }

    // Clear expired cooldown
    if (state.cooldownUntil && now >= state.cooldownUntil) {
      state.cooldownUntil = null;
    }

    // Check message rate
    const recentMessages = this.getRecentTimestamps(
      state.messageTimestamps,
      60_000,
    );

    if (recentMessages.length >= this.config.messagesPerMinute) {
      this.triggerCooldown(state, now);
      return {
        allowed: false,
        reason: `Message rate limit exceeded (${this.config.messagesPerMinute}/min)`,
        retryAfterSeconds: Math.ceil(this.config.cooldownMs / 1000),
        usage: this.getUsageStats(state),
      };
    }

    return {
      allowed: true,
      usage: this.getUsageStats(state),
    };
  }

  /**
   * Record a message for rate limiting purposes.
   */
  recordMessage(sessionKey: string): void {
    if (!this.config.enabled || this.isExempt(sessionKey)) {
      return;
    }

    const state = this.getOrCreateState(sessionKey);
    const now = Date.now();

    state.messageTimestamps.push(now);
    this.pruneTimestamps(state.messageTimestamps, 60_000);

    this.logEvent({
      type: "message",
      sessionKey,
      timestamp: now,
    });
  }

  /**
   * Check if a tool call is allowed for this session.
   */
  checkToolCall(sessionKey: string, toolName: string): RateLimitCheckResult {
    if (!this.config.enabled) {
      return this.createAllowedResult(sessionKey);
    }

    if (this.isExempt(sessionKey)) {
      return this.createAllowedResult(sessionKey);
    }

    const state = this.getOrCreateState(sessionKey);
    const now = Date.now();

    // Check cooldown
    if (state.cooldownUntil && now < state.cooldownUntil) {
      const retryAfterSeconds = Math.ceil((state.cooldownUntil - now) / 1000);
      return {
        allowed: false,
        reason: `Rate limit cooldown active`,
        retryAfterSeconds,
        usage: this.getUsageStats(state),
      };
    }

    // Check tool call rate
    const recentToolCalls = this.getRecentTimestamps(
      state.toolCallTimestamps,
      60_000,
    );

    if (recentToolCalls.length >= this.config.toolCallsPerMinute) {
      this.triggerCooldown(state, now);
      return {
        allowed: false,
        reason: `Tool call rate limit exceeded (${this.config.toolCallsPerMinute}/min)`,
        retryAfterSeconds: Math.ceil(this.config.cooldownMs / 1000),
        usage: this.getUsageStats(state),
      };
    }

    return {
      allowed: true,
      usage: this.getUsageStats(state),
    };
  }

  /**
   * Record a tool call for rate limiting purposes.
   */
  recordToolCall(sessionKey: string, toolName: string): void {
    if (!this.config.enabled || this.isExempt(sessionKey)) {
      return;
    }

    const state = this.getOrCreateState(sessionKey);
    const now = Date.now();

    state.toolCallTimestamps.push(now);
    this.pruneTimestamps(state.toolCallTimestamps, 60_000);

    this.logEvent({
      type: "tool_call",
      sessionKey,
      timestamp: now,
      toolName,
    });
  }

  /**
   * Check if token usage is within limits.
   */
  checkTokenUsage(sessionKey: string, tokenCount: number): RateLimitCheckResult {
    if (!this.config.enabled) {
      return this.createAllowedResult(sessionKey);
    }

    if (this.isExempt(sessionKey)) {
      return this.createAllowedResult(sessionKey);
    }

    const state = this.getOrCreateState(sessionKey);
    const now = Date.now();
    const currentHour = this.getHourKey(now);

    // Get current hour's token usage
    const currentUsage = state.tokenUsageByHour.get(currentHour) ?? 0;

    if (currentUsage + tokenCount > this.config.tokensPerHour) {
      this.triggerCooldown(state, now);
      return {
        allowed: false,
        reason: `Token rate limit exceeded (${this.config.tokensPerHour}/hour)`,
        retryAfterSeconds: Math.ceil(this.config.cooldownMs / 1000),
        usage: this.getUsageStats(state),
      };
    }

    return {
      allowed: true,
      usage: this.getUsageStats(state),
    };
  }

  /**
   * Record token usage for rate limiting purposes.
   */
  recordTokenUsage(sessionKey: string, tokenCount: number): void {
    if (!this.config.enabled || this.isExempt(sessionKey)) {
      return;
    }

    const state = this.getOrCreateState(sessionKey);
    const now = Date.now();
    const currentHour = this.getHourKey(now);

    // Update token usage
    const current = state.tokenUsageByHour.get(currentHour) ?? 0;
    state.tokenUsageByHour.set(currentHour, current + tokenCount);

    // Prune old hour entries
    this.pruneTokenUsageByHour(state.tokenUsageByHour);

    this.logEvent({
      type: "token_usage",
      sessionKey,
      timestamp: now,
      tokenCount,
    });
  }

  /**
   * Get current rate limit state for a session.
   */
  getSessionState(sessionKey: string): RateLimitState | undefined {
    return this.states.get(sessionKey);
  }

  /**
   * Get rate limit statistics for a session.
   */
  getSessionStats(sessionKey: string): {
    messagesInLastMinute: number;
    toolCallsInLastMinute: number;
    tokensInLastHour: number;
    inCooldown: boolean;
    cooldownRemainingMs: number | null;
    limitTriggerCount: number;
  } {
    const state = this.states.get(sessionKey);
    if (!state) {
      return {
        messagesInLastMinute: 0,
        toolCallsInLastMinute: 0,
        tokensInLastHour: 0,
        inCooldown: false,
        cooldownRemainingMs: null,
        limitTriggerCount: 0,
      };
    }

    const now = Date.now();
    const usage = this.getUsageStats(state);
    const inCooldown = !!(state.cooldownUntil && now < state.cooldownUntil);
    const cooldownRemainingMs = inCooldown
      ? state.cooldownUntil! - now
      : null;

    return {
      ...usage,
      inCooldown,
      cooldownRemainingMs,
      limitTriggerCount: state.limitTriggerCount,
    };
  }

  /**
   * Reset rate limit state for a session.
   */
  resetSession(sessionKey: string): void {
    this.states.delete(sessionKey);
  }

  /**
   * Clear all rate limit states.
   */
  clearAll(): void {
    this.states.clear();
    this.eventLog = [];
  }

  /**
   * Add a session to the exempt list.
   */
  addExemptSession(sessionKey: string): void {
    if (!this.config.exemptSessions.includes(sessionKey)) {
      this.config.exemptSessions.push(sessionKey);
    }
  }

  /**
   * Remove a session from the exempt list.
   */
  removeExemptSession(sessionKey: string): void {
    const index = this.config.exemptSessions.indexOf(sessionKey);
    if (index !== -1) {
      this.config.exemptSessions.splice(index, 1);
    }
  }

  /**
   * Get recent rate limit events.
   */
  getRecentEvents(limit = 100): RateLimitEvent[] {
    return this.eventLog.slice(-limit);
  }

  /**
   * Get global rate limit statistics.
   */
  getGlobalStats(): {
    activeSessions: number;
    sessionsInCooldown: number;
    totalLimitTriggers: number;
    eventsInLog: number;
  } {
    const now = Date.now();
    let sessionsInCooldown = 0;
    let totalLimitTriggers = 0;

    for (const state of this.states.values()) {
      if (state.cooldownUntil && now < state.cooldownUntil) {
        sessionsInCooldown++;
      }
      totalLimitTriggers += state.limitTriggerCount;
    }

    return {
      activeSessions: this.states.size,
      sessionsInCooldown,
      totalLimitTriggers,
      eventsInLog: this.eventLog.length,
    };
  }

  /**
   * Update configuration at runtime.
   */
  updateConfig(config: Partial<RateLimitConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Get current configuration.
   */
  getConfig(): Readonly<RateLimitConfig> {
    return { ...this.config };
  }

  // Private helpers

  private isExempt(sessionKey: string): boolean {
    return this.config.exemptSessions.includes(sessionKey);
  }

  private getOrCreateState(sessionKey: string): RateLimitState {
    let state = this.states.get(sessionKey);
    if (!state) {
      state = {
        sessionKey,
        messageTimestamps: [],
        toolCallTimestamps: [],
        tokenUsageByHour: new Map(),
        cooldownUntil: null,
        limitTriggerCount: 0,
        lastLimitTrigger: null,
      };
      this.states.set(sessionKey, state);
    }
    return state;
  }

  private getRecentTimestamps(timestamps: number[], windowMs: number): number[] {
    const cutoff = Date.now() - windowMs;
    return timestamps.filter((ts) => ts > cutoff);
  }

  private pruneTimestamps(timestamps: number[], windowMs: number): void {
    const cutoff = Date.now() - windowMs;
    // Remove timestamps older than the window
    while (timestamps.length > 0 && timestamps[0]! < cutoff) {
      timestamps.shift();
    }
  }

  private pruneTokenUsageByHour(usage: Map<string, number>): void {
    const now = Date.now();
    const currentHour = this.getHourKey(now);
    const prevHour = this.getHourKey(now - 3600_000);

    // Keep only current and previous hour
    for (const key of usage.keys()) {
      if (key !== currentHour && key !== prevHour) {
        usage.delete(key);
      }
    }
  }

  private getHourKey(timestamp: number): string {
    const date = new Date(timestamp);
    return date.toISOString().slice(0, 13); // "2024-01-15T14"
  }

  private triggerCooldown(state: RateLimitState, now: number): void {
    state.cooldownUntil = now + this.config.cooldownMs;
    state.limitTriggerCount++;
    state.lastLimitTrigger = now;
  }

  private getUsageStats(state: RateLimitState): {
    messagesInLastMinute: number;
    toolCallsInLastMinute: number;
    tokensInLastHour: number;
  } {
    const now = Date.now();
    const currentHour = this.getHourKey(now);

    return {
      messagesInLastMinute: this.getRecentTimestamps(state.messageTimestamps, 60_000).length,
      toolCallsInLastMinute: this.getRecentTimestamps(state.toolCallTimestamps, 60_000).length,
      tokensInLastHour: state.tokenUsageByHour.get(currentHour) ?? 0,
    };
  }

  private createAllowedResult(sessionKey: string): RateLimitCheckResult {
    const state = this.states.get(sessionKey);
    return {
      allowed: true,
      usage: state
        ? this.getUsageStats(state)
        : { messagesInLastMinute: 0, toolCallsInLastMinute: 0, tokensInLastHour: 0 },
    };
  }

  private logEvent(event: RateLimitEvent): void {
    this.eventLog.push(event);

    // Prune old events
    if (this.eventLog.length > this.maxEventLogSize) {
      this.eventLog = this.eventLog.slice(-Math.floor(this.maxEventLogSize / 2));
    }
  }
}

/**
 * Create a rate limiter with default configuration.
 */
export function createRateLimiter(
  config?: Partial<RateLimitConfig>,
): SessionRateLimiter {
  return new SessionRateLimiter(config);
}

/**
 * Singleton rate limiter instance for global use.
 */
let globalRateLimiter: SessionRateLimiter | null = null;

/**
 * Get the global rate limiter instance.
 */
export function getGlobalRateLimiter(): SessionRateLimiter {
  if (!globalRateLimiter) {
    globalRateLimiter = new SessionRateLimiter();
  }
  return globalRateLimiter;
}

/**
 * Initialize the global rate limiter with custom configuration.
 */
export function initGlobalRateLimiter(
  config: Partial<RateLimitConfig>,
): SessionRateLimiter {
  globalRateLimiter = new SessionRateLimiter(config);
  return globalRateLimiter;
}
