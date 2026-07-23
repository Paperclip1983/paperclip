import express from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Write-side counterpart to the response redaction covered by
// `agent-env-redaction-routes.test.ts` / `redaction.test.ts`: agent create and
// update must refuse to accept a *new* plaintext credential in
// `adapterConfig.env`, so redaction on read is not the only thing standing
// between a caller and a stored secret (TEC-7051, TEC-7063).

const AGENT_ID = "11111111-1111-4111-8111-111111111111";

// Stand-in for a credential value. Deliberately not a real token shape — no
// secret material belongs in this repo. Short enough (34 chars) that it only
// trips the *name* heuristic, keeping the two rules independently testable.
const SAMPLE_CREDENTIAL = "sample-not-a-real-credential-value";

const mockAgentService = vi.hoisted(() => ({
  create: vi.fn(),
  getById: vi.fn(),
  update: vi.fn(),
}));

const mockAccessService = vi.hoisted(() => ({
  canUser: vi.fn(),
  decide: vi.fn(),
  hasPermission: vi.fn(),
  ensureMembership: vi.fn(),
  setPrincipalPermission: vi.fn(),
}));

const mockCompanySkillService = vi.hoisted(() => ({
  listRuntimeSkillEntries: vi.fn(),
  resolveRequestedSkillKeys: vi.fn(),
}));

const mockSecretService = vi.hoisted(() => ({
  normalizeAdapterConfigForPersistence: vi.fn(async (_companyId: string, config: Record<string, unknown>) => config),
  resolveAdapterConfigForRuntime: vi.fn(async (_companyId: string, config: Record<string, unknown>) => ({ config })),
  syncEnvBindingsForTarget: vi.fn(),
}));

const mockAgentInstructionsService = vi.hoisted(() => ({
  materializeManagedBundle: vi.fn(),
  getBundle: vi.fn(),
  readFile: vi.fn(),
  updateBundle: vi.fn(),
  writeFile: vi.fn(),
  deleteFile: vi.fn(),
  exportFiles: vi.fn(),
  ensureManagedBundle: vi.fn(),
}));

const mockBudgetService = vi.hoisted(() => ({ upsertPolicy: vi.fn() }));
const mockHeartbeatService = vi.hoisted(() => ({ cancelActiveForAgent: vi.fn() }));
const mockIssueApprovalService = vi.hoisted(() => ({ linkManyForApproval: vi.fn() }));
const mockApprovalService = vi.hoisted(() => ({ create: vi.fn(), getById: vi.fn() }));
const mockInstanceSettingsService = vi.hoisted(() => ({
  getGeneral: vi.fn(async () => ({ censorUsernameInLogs: false })),
}));
const mockLogActivity = vi.hoisted(() => vi.fn());

function serviceModuleMock() {
  return {
    agentService: () => mockAgentService,
    agentInstructionsService: () => mockAgentInstructionsService,
    accessService: () => mockAccessService,
    approvalService: () => mockApprovalService,
    builtInAgentService: () => ({ ensureCompanyDefaultAgentGrants: vi.fn() }),
    companySkillService: () => mockCompanySkillService,
    budgetService: () => mockBudgetService,
    heartbeatService: () => mockHeartbeatService,
    issueApprovalService: () => mockIssueApprovalService,
    issueService: () => ({}),
    logActivity: mockLogActivity,
    secretService: () => mockSecretService,
    syncInstructionsBundleConfigFromFilePath: vi.fn((_agent: unknown, config: unknown) => config),
    workspaceOperationService: () => ({}),
  };
}

vi.mock("../services/index.js", () => serviceModuleMock());

vi.mock("../services/instance-settings.js", () => ({
  instanceSettingsService: () => mockInstanceSettingsService,
}));

vi.mock("../services/secrets.js", () => ({
  secretService: () => mockSecretService,
}));

function registerModuleMocks() {
  vi.doMock("../services/index.js", () => serviceModuleMock());
  vi.doMock("../services/instance-settings.js", () => ({
    instanceSettingsService: () => mockInstanceSettingsService,
  }));
  vi.doMock("../services/secrets.js", () => ({
    secretService: () => mockSecretService,
  }));
}

function storedAgent(adapterConfig: Record<string, unknown> = {}) {
  return {
    id: AGENT_ID,
    companyId: "company-1",
    name: "Codex",
    urlKey: "codex",
    role: "engineer",
    title: null,
    icon: null,
    status: "idle",
    reportsTo: null,
    capabilities: null,
    adapterType: "codex_local",
    adapterConfig,
    runtimeConfig: {},
    budgetMonthlyCents: 0,
    spentMonthlyCents: 0,
    pauseReason: null,
    pausedAt: null,
    permissions: { canCreateAgents: false },
    lastHeartbeatAt: null,
    metadata: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
}

async function createApp() {
  const [{ agentRoutes }, { errorHandler }] = await Promise.all([
    vi.importActual<typeof import("../routes/agents.js")>("../routes/agents.js"),
    vi.importActual<typeof import("../middleware/index.js")>("../middleware/index.js"),
  ]);
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    (req as any).actor = {
      type: "board",
      userId: "local-board",
      companyIds: ["company-1"],
      source: "local_implicit",
      isInstanceAdmin: false,
    };
    next();
  });
  const db = {
    select: vi.fn(() => ({
      from: vi.fn(() => ({
        where: vi.fn(async () => [{ id: "company-1", requireBoardApprovalForNewAgents: false }]),
      })),
    })),
  };
  app.use("/api", agentRoutes(db as any));
  app.use(errorHandler);
  return app;
}

async function requestApp(
  app: express.Express,
  buildRequest: (baseUrl: string) => request.Test,
) {
  const { createServer } = await vi.importActual<typeof import("node:http")>("node:http");
  const server = createServer(app);
  try {
    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("Expected HTTP server to listen on a TCP port");
    }
    return await buildRequest(`http://127.0.0.1:${address.port}`);
  } finally {
    if (server.listening) {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
  }
}

describe("agent routes plaintext credential rejection", () => {
  beforeEach(async () => {
    vi.resetModules();
    vi.doUnmock("../routes/agents.js");
    vi.doUnmock("../routes/authz.js");
    vi.doUnmock("../middleware/index.js");
    registerModuleMocks();
    vi.clearAllMocks();

    mockCompanySkillService.listRuntimeSkillEntries.mockResolvedValue([]);
    mockCompanySkillService.resolveRequestedSkillKeys.mockResolvedValue([]);
    mockAccessService.canUser.mockResolvedValue(true);
    mockAccessService.decide.mockResolvedValue({
      allowed: true,
      reason: "allow_explicit_grant",
      explanation: "Allowed by test grant",
    });
    mockAccessService.hasPermission.mockResolvedValue(true);
    mockAccessService.ensureMembership.mockResolvedValue(undefined);
    mockAccessService.setPrincipalPermission.mockResolvedValue(undefined);
    mockLogActivity.mockResolvedValue(undefined);
    mockSecretService.syncEnvBindingsForTarget.mockResolvedValue(undefined);
    mockSecretService.normalizeAdapterConfigForPersistence.mockImplementation(
      async (_companyId: string, config: Record<string, unknown>) => config,
    );
    mockAgentInstructionsService.materializeManagedBundle.mockImplementation(
      async (agent: { adapterConfig: unknown }) => ({ adapterConfig: agent.adapterConfig }),
    );
    mockAgentService.create.mockImplementation(async (_companyId: string, input: Record<string, unknown>) => ({
      ...storedAgent((input.adapterConfig as Record<string, unknown> | undefined) ?? {}),
      id: String(input.id ?? AGENT_ID),
      name: String(input.name ?? "Agent"),
      adapterType: String(input.adapterType ?? "codex_local"),
    }));
    mockAgentService.getById.mockResolvedValue(storedAgent({}));
    mockAgentService.update.mockImplementation(async (_id: string, patch: Record<string, unknown>) => ({
      ...storedAgent({}),
      ...patch,
    }));
  });

  it("rejects agent creation carrying a plaintext credential env binding", async () => {
    const app = await createApp();
    const res = await requestApp(app, (baseUrl) =>
      request(baseUrl)
        .post("/api/companies/company-1/agents")
        .send({
          name: "Injecting Agent",
          adapterType: "codex_local",
          adapterConfig: {
            env: { GITHUB_TOKEN: { type: "plain", value: SAMPLE_CREDENTIAL } },
          },
        }),
    );

    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(res.body.code).toBe("plaintext_credential_rejected");
    expect(res.body.error).toContain("GITHUB_TOKEN");
    expect(res.body.error).toContain("secret_ref");
    expect(mockAgentService.create).not.toHaveBeenCalled();
  });

  it("rejects an update carrying a plaintext credential env binding", async () => {
    const app = await createApp();
    const res = await requestApp(app, (baseUrl) =>
      request(baseUrl)
        .patch(`/api/agents/${AGENT_ID}`)
        .send({
          adapterConfig: {
            env: { OPENAI_API_KEY: { type: "plain", value: SAMPLE_CREDENTIAL } },
          },
        }),
    );

    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(res.body.code).toBe("plaintext_credential_rejected");
    expect(res.body.error).toContain("OPENAI_API_KEY");
    expect(mockAgentService.update).not.toHaveBeenCalled();
  });

  it("names every offending env entry without echoing any rejected value", async () => {
    const app = await createApp();
    const res = await requestApp(app, (baseUrl) =>
      request(baseUrl)
        .patch(`/api/agents/${AGENT_ID}`)
        .send({
          adapterConfig: {
            env: {
              NODE_ENV: { type: "plain", value: "production" },
              GITHUB_TOKEN: { type: "plain", value: SAMPLE_CREDENTIAL },
              DB_PASSWORD: { type: "plain", value: SAMPLE_CREDENTIAL },
            },
          },
        }),
    );

    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(res.body.details?.envNames).toEqual(["GITHUB_TOKEN", "DB_PASSWORD"]);
    // The whole response — message, details, remediation — must be safe to log.
    expect(JSON.stringify(res.body)).not.toContain(SAMPLE_CREDENTIAL);
  });

  it("accepts secret_ref bindings on create", async () => {
    const app = await createApp();
    const res = await requestApp(app, (baseUrl) =>
      request(baseUrl)
        .post("/api/companies/company-1/agents")
        .send({
          name: "Referencing Agent",
          adapterType: "codex_local",
          adapterConfig: {
            env: {
              GITHUB_TOKEN: {
                type: "secret_ref",
                secretId: "22222222-2222-4222-8222-222222222222",
              },
            },
          },
        }),
    );

    expect(res.status, JSON.stringify(res.body)).toBe(201);
    expect(mockAgentService.create).toHaveBeenCalled();
  });

  it("accepts user_secret_ref bindings on update", async () => {
    const app = await createApp();
    const res = await requestApp(app, (baseUrl) =>
      request(baseUrl)
        .patch(`/api/agents/${AGENT_ID}`)
        .send({
          adapterConfig: {
            env: { OPENAI_API_KEY: { type: "user_secret_ref", key: "openai" } },
          },
        }),
    );

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(mockAgentService.update).toHaveBeenCalled();
  });

  it("accepts non-credential plaintext env entries", async () => {
    const app = await createApp();
    const res = await requestApp(app, (baseUrl) =>
      request(baseUrl)
        .patch(`/api/agents/${AGENT_ID}`)
        .send({
          adapterConfig: {
            env: {
              NODE_ENV: { type: "plain", value: "production" },
              LOG_LEVEL: { type: "plain", value: "debug" },
            },
          },
        }),
    );

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const patch = mockAgentService.update.mock.calls.at(-1)?.[1] as Record<string, unknown>;
    const env = (patch.adapterConfig as Record<string, unknown>).env as Record<string, unknown>;
    expect(env.NODE_ENV).toEqual({ type: "plain", value: "production" });
  });

  it("preserves the redacted round-trip: a sentinel PATCH restores the stored binding", async () => {
    // A client GETs the agent (env redacted to `{ type: "plain", value: "***REDACTED***" }`),
    // edits an unrelated field, and PATCHes the whole config back. That must not
    // be mistaken for a plaintext credential write.
    const storedBinding = {
      type: "secret_ref",
      secretId: "33333333-3333-4333-8333-333333333333",
    };
    mockAgentService.getById.mockResolvedValue(storedAgent({ env: { GITHUB_TOKEN: storedBinding } }));

    const { REDACTED_EVENT_VALUE } = await vi.importActual<typeof import("../redaction.js")>(
      "../redaction.js",
    );

    const app = await createApp();
    const res = await requestApp(app, (baseUrl) =>
      request(baseUrl)
        .patch(`/api/agents/${AGENT_ID}`)
        .send({
          adapterConfig: {
            model: "gpt-5.4",
            env: { GITHUB_TOKEN: { type: "plain", value: REDACTED_EVENT_VALUE } },
          },
        }),
    );

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const patch = mockAgentService.update.mock.calls.at(-1)?.[1] as Record<string, unknown>;
    const env = (patch.adapterConfig as Record<string, unknown>).env as Record<string, unknown>;
    expect(env.GITHUB_TOKEN).toEqual(storedBinding);
  });
});
