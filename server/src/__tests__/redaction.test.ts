import { describe, expect, it } from "vitest";
import {
  REDACTED_EVENT_VALUE,
  findPlaintextCredentialEnvViolations,
  redactAgentAdapterConfig,
  redactEventPayload,
  redactSensitiveText,
  sanitizeRecord,
} from "../redaction.js";

describe("redaction", () => {
  it("redacts sensitive keys and nested secret values", () => {
    const input = {
      apiKey: "abc123",
      nested: {
        AUTH_TOKEN: "token-value",
        safe: "ok",
      },
      env: {
        OPENAI_API_KEY: "sk-openai",
        OPENAI_API_KEY_REF: {
          type: "secret_ref",
          secretId: "11111111-1111-1111-1111-111111111111",
        },
        OPENAI_API_KEY_PLAIN: {
          type: "plain",
          value: "sk-plain",
        },
        PAPERCLIP_API_URL: "http://localhost:3100",
      },
    };

    const result = sanitizeRecord(input);

    expect(result.apiKey).toBe(REDACTED_EVENT_VALUE);
    expect(result.nested).toEqual({
      AUTH_TOKEN: REDACTED_EVENT_VALUE,
      safe: "ok",
    });
    expect(result.env).toEqual({
      OPENAI_API_KEY: REDACTED_EVENT_VALUE,
      OPENAI_API_KEY_REF: {
        type: "secret_ref",
        secretId: "11111111-1111-1111-1111-111111111111",
      },
      OPENAI_API_KEY_PLAIN: {
        type: "plain",
        value: REDACTED_EVENT_VALUE,
      },
      PAPERCLIP_API_URL: "http://localhost:3100",
    });
  });

  it("redacts jwt-looking values even when key name is not sensitive", () => {
    const input = {
      session: "aaa.bbb.ccc",
      normal: "plain",
    };

    const result = sanitizeRecord(input);

    expect(result.session).toBe(REDACTED_EVENT_VALUE);
    expect(result.normal).toBe("plain");
  });

  it("redacts payload objects while preserving null", () => {
    expect(redactEventPayload(null)).toBeNull();
    expect(redactEventPayload({ password: "hunter2", safe: "value" })).toEqual({
      password: REDACTED_EVENT_VALUE,
      safe: "value",
    });
  });

  it("redacts common secret shapes from unstructured text", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const githubToken = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
    const input = [
      "Authorization: Bearer live-bearer-token-value",
      `payload {"apiKey":"json-secret-value"}`,
      `paperclip {"PAPERCLIP_API_KEY":"paperclip-json-secret"}`,
      `escaped {\\"apiKey\\":\\"escaped-json-secret\\"}`,
      `export PAPERCLIP_API_KEY='paperclip-shell-secret'`,
      `GITHUB_TOKEN=${githubToken}`,
      `session=${jwt}`,
    ].join("\n");

    const result = redactSensitiveText(input);

    expect(result).toContain(REDACTED_EVENT_VALUE);
    expect(result).not.toContain("live-bearer-token-value");
    expect(result).not.toContain("json-secret-value");
    expect(result).not.toContain("paperclip-json-secret");
    expect(result).not.toContain("escaped-json-secret");
    expect(result).not.toContain("paperclip-shell-secret");
    expect(result).not.toContain(githubToken);
    expect(result).not.toContain(jwt);
  });

  it("redacts inline secrets from command metadata without hiding safe command text", () => {
    const input = {
      command: "custom-acp --token ghp_example_secret env OPENAI_API_KEY=sk-live-example custom-acp",
      commandArgs: ["--safe", "ok", "--token", "ghp_arg_secret", "--api-key=sk-inline-example"],
      env: {
        PAPERCLIP_RESOLVED_COMMAND: "env OPENAI_API_KEY=sk-live-example custom-acp --token ghp_example_secret",
        SAFE_VALUE: "visible",
      },
    };

    const result = redactEventPayload(input);

    expect(result?.command).toBe(
      `custom-acp --token ${REDACTED_EVENT_VALUE} env OPENAI_API_KEY=${REDACTED_EVENT_VALUE} custom-acp`,
    );
    expect(result?.commandArgs).toEqual([
      "--safe",
      "ok",
      "--token",
      REDACTED_EVENT_VALUE,
      `--api-key=${REDACTED_EVENT_VALUE}`,
    ]);
    expect(result?.env).toEqual({
      PAPERCLIP_RESOLVED_COMMAND:
        `env OPENAI_API_KEY=${REDACTED_EVENT_VALUE} custom-acp --token ${REDACTED_EVENT_VALUE}`,
      SAFE_VALUE: "visible",
    });
  });

  it("redacts non-string command args after secret flags", () => {
    const result = redactEventPayload({
      commandArgs: ["--api-key", { nested: "secret-value" }, "safe-next"],
    });

    expect(result?.commandArgs).toEqual(["--api-key", REDACTED_EVENT_VALUE, "safe-next"]);
  });

  it("does not treat bare args payloads as command args", () => {
    const result = redactEventPayload({
      args: ["--api-key", "not-a-command-secret"],
      argv: ["--api-key", "command-secret"],
    });

    expect(result?.args).toEqual(["--api-key", "not-a-command-secret"]);
    expect(result?.argv).toEqual(["--api-key", REDACTED_EVENT_VALUE]);
  });

  it("redacts every plaintext agent env binding while preserving secret references", () => {
    const plaintextValue = "adapter-env-value-must-not-leak";

    const result = redactAgentAdapterConfig({
      command: "pnpm agent:run",
      env: {
        EXISTING_VALUE: plaintextValue,
        NEW_VALUE: { type: "plain", value: plaintextValue },
        SECRET_REFERENCE: {
          type: "secret_ref",
          secretId: "55555555-5555-4555-8555-555555555555",
          version: "latest",
        },
        USER_SECRET_REFERENCE: {
          type: "user_secret_ref",
          key: "GITHUB_TOKEN",
        },
      },
    });

    expect(result).toEqual({
      command: "pnpm agent:run",
      env: {
        EXISTING_VALUE: { type: "plain", value: REDACTED_EVENT_VALUE },
        NEW_VALUE: { type: "plain", value: REDACTED_EVENT_VALUE },
        SECRET_REFERENCE: {
          type: "secret_ref",
          secretId: "55555555-5555-4555-8555-555555555555",
          version: "latest",
        },
        USER_SECRET_REFERENCE: {
          type: "user_secret_ref",
          key: "GITHUB_TOKEN",
        },
      },
    });
    expect(JSON.stringify(result)).not.toContain(plaintextValue);
  });

  it("redacts non-env adapter keys while leaving env binding shapes intact", () => {
    const result = redactAgentAdapterConfig({
      command: "pnpm agent:run",
      apiKey: "adapter-level-secret",
      env: {
        API_KEY: "env-level-secret",
        AUTH_TOKEN: { type: "plain", value: "another-env-secret" },
      },
    });

    // Non-env keys still go through the shared payload sanitizer.
    expect(result.apiKey).toBe(REDACTED_EVENT_VALUE);
    expect(result.command).toBe("pnpm agent:run");

    // Env bindings keep their binding shape rather than collapsing to a bare
    // sentinel string, which is what a second sanitizer pass would produce for
    // these sensitive-looking key names.
    expect(result.env).toEqual({
      API_KEY: { type: "plain", value: REDACTED_EVENT_VALUE },
      AUTH_TOKEN: { type: "plain", value: REDACTED_EVENT_VALUE },
    });
  });

  it("redacts adapter configs that have no env block", () => {
    expect(redactAgentAdapterConfig({ command: "pnpm agent:run", apiKey: "secret" })).toEqual({
      command: "pnpm agent:run",
      apiKey: REDACTED_EVENT_VALUE,
    });
  });
});

describe("findPlaintextCredentialEnvViolations", () => {
  const plain = (value: string) => ({ type: "plain", value });

  // Stand-in for a credential value. Deliberately not a real token shape — no
  // secret material belongs in this repo (TEC-7063).
  const SAMPLE_CREDENTIAL = "***SAMPLE***";

  it("flags plaintext bindings whose env name matches a credential pattern", () => {
    const violations = findPlaintextCredentialEnvViolations({
      GITHUB_TOKEN: plain(SAMPLE_CREDENTIAL),
      OPENAI_API_KEY: plain(SAMPLE_CREDENTIAL),
      DB_PASSWORD: plain(SAMPLE_CREDENTIAL),
      CLIENT_SECRET: plain(SAMPLE_CREDENTIAL),
      GH_PAT: plain(SAMPLE_CREDENTIAL),
    });

    expect(violations.sort()).toEqual([
      "CLIENT_SECRET",
      "DB_PASSWORD",
      "GH_PAT",
      "GITHUB_TOKEN",
      "OPENAI_API_KEY",
    ]);
  });

  it("flags a long opaque plaintext value even under a neutral env name", () => {
    // 41 chars: one over the permissive lower bound.
    const opaque = "a".repeat(41);
    expect(opaque.length).toBe(41);

    expect(findPlaintextCredentialEnvViolations({ SESSION_BLOB: plain(opaque) })).toEqual([
      "SESSION_BLOB",
    ]);
  });

  it("leaves non-credential env entries alone", () => {
    expect(
      findPlaintextCredentialEnvViolations({
        NODE_ENV: plain("production"),
        LOG_LEVEL: plain("debug"),
      }),
    ).toEqual([]);
  });

  it("does not flag long values that are paths, URLs, or command lines", () => {
    // Each is over the length bound but is ordinary configuration, not a secret.
    // Without these carve-outs the control misfires on everyday env vars.
    expect(
      findPlaintextCredentialEnvViolations({
        PATH: plain("/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"),
        HOME_DIR: plain("~/paperclip/companies/acme/agents/codex-home"),
        PAPERCLIP_API_URL: plain("http://localhost:3100/api/companies/acme/agents"),
        RUN_COMMAND: plain("pnpm --filter server exec vitest run --reporter dot"),
      }),
    ).toEqual([]);
  });

  it("does not misclassify PATH-like names as Personal Access Tokens", () => {
    expect(
      findPlaintextCredentialEnvViolations({
        PATH: plain("/usr/bin"),
        COMPATIBILITY_MODE: plain("legacy"),
      }),
    ).toEqual([]);
  });

  it("skips redacted sentinels so a round-tripped GET response is not rejected", () => {
    // `restoreRedactedAgentEnv` maps these back to the stored value on PATCH;
    // the sentinel is not a real credential and must not trigger rejection.
    expect(
      findPlaintextCredentialEnvViolations({
        GITHUB_TOKEN: plain(REDACTED_EVENT_VALUE),
        OPENAI_API_KEY: plain(REDACTED_EVENT_VALUE),
      }),
    ).toEqual([]);
  });

  it("skips empty plaintext values, which clear rather than set a credential", () => {
    expect(findPlaintextCredentialEnvViolations({ GITHUB_TOKEN: plain("") })).toEqual([]);
  });

  it("allows secret_ref and user_secret_ref bindings for credential-shaped names", () => {
    expect(
      findPlaintextCredentialEnvViolations({
        GITHUB_TOKEN: {
          type: "secret_ref",
          secretId: "11111111-1111-1111-1111-111111111111",
        },
        OPENAI_API_KEY: { type: "user_secret_ref", key: "openai" },
      }),
    ).toEqual([]);
  });

  it("returns no violations for a missing or non-object env block", () => {
    expect(findPlaintextCredentialEnvViolations(undefined)).toEqual([]);
    expect(findPlaintextCredentialEnvViolations(null)).toEqual([]);
    expect(findPlaintextCredentialEnvViolations("env")).toEqual([]);
  });
});
