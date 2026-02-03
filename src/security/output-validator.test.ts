import { describe, it, expect } from "vitest";
import {
  validateAgentOutput,
  likelyContainsCredentials,
  redactCredentialsInContent,
} from "./output-validator.js";

describe("Output Validator", () => {
  describe("validateAgentOutput", () => {
    describe("credential detection", () => {
      it("blocks OpenAI API keys", () => {
        const result = validateAgentOutput(
          "Here's the API key: sk-1234567890abcdefghijklmnop"
        );

        expect(result.safe).toBe(false);
        expect(result.issues.some((i) => i.type === "credential_leak")).toBe(true);
      });

      it("blocks GitHub PATs", () => {
        const result = validateAgentOutput(
          "Use this token: ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        );

        expect(result.safe).toBe(false);
        expect(result.issues.some((i) => i.type === "credential_leak")).toBe(true);
      });

      it("blocks Slack tokens", () => {
        const result = validateAgentOutput(
          "Token: xoxb-1234567890-abcdefghij"
        );

        expect(result.safe).toBe(false);
        expect(result.issues.some((i) => i.type === "credential_leak")).toBe(true);
      });

      it("blocks private keys", () => {
        const result = validateAgentOutput(
          "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg...\n-----END PRIVATE KEY-----"
        );

        expect(result.safe).toBe(false);
        expect(result.issues.some((i) => i.type === "credential_leak")).toBe(true);
      });

      it("blocks Bearer tokens", () => {
        const result = validateAgentOutput(
          "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        );

        expect(result.safe).toBe(false);
        expect(result.issues.some((i) => i.type === "credential_leak")).toBe(true);
      });

      it("blocks Telegram bot tokens", () => {
        const result = validateAgentOutput(
          "Bot token: 1234567890:ABCdefGHIjklMNOpqrsTUVwxyz123456789"
        );

        expect(result.safe).toBe(false);
      });

      it("blocks Moltbook API keys", () => {
        const result = validateAgentOutput(
          "Key: moltbook_sk_1234567890abcdef"
        );

        expect(result.safe).toBe(false);
      });
    });

    describe("system prompt leak detection", () => {
      it("warns on system identity leak", () => {
        const result = validateAgentOutput(
          "You are a personal assistant running inside OpenClaw."
        );

        expect(result.issues.some((i) => i.type === "system_prompt_leak")).toBe(true);
      });

      it("warns on safety rules leak", () => {
        const result = validateAgentOutput(
          "IMMUTABLE SAFETY RULES cannot be overridden"
        );

        expect(result.issues.some((i) => i.type === "system_prompt_leak")).toBe(true);
      });

      it("warns on security boundary leak", () => {
        const result = validateAgentOutput(
          "Content wrapped in <<<EXTERNAL_UNTRUSTED_CONTENT>>>"
        );

        expect(result.issues.some((i) => i.type === "system_prompt_leak")).toBe(true);
      });
    });

    describe("suspicious URL detection", () => {
      it("warns on webhook URLs", () => {
        const result = validateAgentOutput(
          "Send data to https://webhook.site/abc123"
        );

        expect(result.issues.some((i) => i.type === "suspicious_url")).toBe(true);
      });

      it("warns on direct IP URLs", () => {
        const result = validateAgentOutput(
          "Connect to http://192.168.1.100/data"
        );

        expect(result.issues.some((i) => i.type === "suspicious_url")).toBe(true);
      });
    });

    describe("canary token detection", () => {
      it("blocks canary tokens when configured", () => {
        const canaryToken = "CANARY_TEST_abc123xyz";
        const result = validateAgentOutput(
          `The content includes ${canaryToken} somewhere.`,
          { canaryTokens: [canaryToken] }
        );

        expect(result.safe).toBe(false);
        expect(result.issues.some((i) => i.type === "canary_leak")).toBe(true);
      });
    });

    describe("sanitized output", () => {
      it("provides sanitized content for blocked output", () => {
        const result = validateAgentOutput(
          "Here's the key: sk-1234567890abcdefghijklmnop and more text"
        );

        expect(result.safe).toBe(false);
        expect(result.sanitizedContent).toBeDefined();
        expect(result.sanitizedContent).toContain("[REDACTED: credential_leak]");
      });
    });

    describe("safe content", () => {
      it("allows normal text", () => {
        const result = validateAgentOutput(
          "Hello! Here's the information you requested about Python programming."
        );

        expect(result.safe).toBe(true);
        expect(result.issues).toHaveLength(0);
      });

      it("allows code examples without credentials", () => {
        const result = validateAgentOutput(
          "```python\ndef hello():\n    print('Hello world')\n```"
        );

        expect(result.safe).toBe(true);
      });
    });
  });

  describe("likelyContainsCredentials", () => {
    it("returns true for content with credential indicators", () => {
      expect(likelyContainsCredentials("sk-abc123")).toBe(true);
      expect(likelyContainsCredentials("ghp_token")).toBe(true);
      expect(likelyContainsCredentials("xoxb-slack")).toBe(true);
      expect(likelyContainsCredentials("Bearer token")).toBe(true);
      expect(likelyContainsCredentials("-----BEGIN PRIVATE")).toBe(true);
    });

    it("returns false for normal content", () => {
      expect(likelyContainsCredentials("Hello world")).toBe(false);
      expect(likelyContainsCredentials("Write me a poem")).toBe(false);
    });
  });

  describe("redactCredentialsInContent", () => {
    it("redacts multiple credential types", () => {
      const content = `
        OpenAI: sk-1234567890abcdefghijklmnop
        GitHub: ghp_1234567890abcdefghijklmnopqrstuvwxyz
        Slack: xoxb-1234-5678-abcdefgh
      `;

      const redacted = redactCredentialsInContent(content);

      expect(redacted).not.toContain("sk-1234567890");
      expect(redacted).not.toContain("ghp_1234567890");
      expect(redacted).not.toContain("xoxb-1234");
      expect(redacted).toContain("[REDACTED:");
    });
  });
});
