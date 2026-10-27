import { dirname, join, resolve } from "node:path";
import { z } from "zod";
import {
  createAnalysisExecution,
  type AnalysisClient,
  type AnalysisOperation,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisProtocolError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisProfileCommitment } from "../domain/analysisProfile.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { createEvidence, type EvidenceLocation } from "../domain/evidence.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { err, ok, type Result } from "../domain/result.js";
import type { ProviderOperationHealth } from "../domain/providerOperationHealth.js";
import type { IdaConfiguration } from "./IdaConfiguration.js";
import {
  IdaMcpRequestTimeoutError,
  type IdaMcpConnection,
} from "./IdaMcpConnection.js";
import { parseIdaInput } from "./IdaInput.js";
import {
  IDA_LIMITATIONS,
  IDA_OPERATIONS,
  HEX_RAYS_PROVIDER_IDENTITY,
} from "./IdaProviderCapabilities.js";
import {
  idaFileDigest,
  IdaWorkspace,
  sameIdaHostPath,
} from "./IdaWorkspace.js";
import { HexRaysOperations } from "./HexRaysOperations.js";
import {
  loadHexRaysQueryBundle,
  runHexRaysQuery,
  type HexRaysObservation,
  type HexRaysQuery,
} from "./HexRaysQueries.js";

const openedSchema = z.object({
  instance_id: z.string().min(1),
  backend: z.literal("idalib"),
  status: z.enum(["current", "attached"]),
});
const inventorySchema = z.object({
  instances: z.array(
    z.object({
      path: z.string(),
      backend: z.string(),
      instance_id: z.string().nullable(),
      status: z.string(),
    }),
  ),
});
const metadataSchema = z.object({
  input_path: z.string(),
  idb_path: z.string(),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  processor: z.string(),
  imagebase: z.string(),
  kernel_version: z.string(),
  sdk_version: z.number().int(),
  auto_analysis_ready: z.boolean(),
  package_versions: z.record(z.string(), z.string().nullable()),
});
type Metadata = z.infer<typeof metadataSchema>;
const requiredTools = [
  "open_database",
  "execute_python",
  "reference",
  "list_databases",
  "close_database",
];
const limits = [
  ...IDA_LIMITATIONS,
  "Official IDA MCP may flush or save its private working database; the original input is never overwritten.",
  "Fixed query requests retain their JSON parameters and implementation/code digests; upstream result bodies are retained verbatim.",
];

class HexRaysCleanupError extends ProviderAdapterError {
  override readonly cleanupIncomplete = true;
  constructor(workspace: string, cause: unknown) {
    super("ida", "close", {
      cause,
      diagnostics: {
        reason:
          "Official IDA lease or private workspace release remains unverified",
        workspace,
        failure_reason: cause instanceof Error ? cause.message : String(cause),
      },
    });
    this.setCleanupResources([workspace]);
  }
}

/** One serial official-MCP lease; recovery never discards the enclosing investigation ledger. */
export class HexRaysSessionClient implements AnalysisClient {
  private tail: Promise<void> = Promise.resolve();
  private connection: IdaMcpConnection | undefined;
  private connectedConfig: IdaConfiguration | undefined;
  private workspace: IdaWorkspace | undefined;
  private instance: string | undefined;
  private metadata: Metadata | undefined;
  private initialIdentity: string | undefined;
  private environmentIdentity: string | undefined;
  private recoveryBlocked: AnalysisError | undefined;
  private readonly cleanupFailures = new Set<AnalysisError>();
  private openAttempted = false;
  private openSettled = false;
  private leaseVerified = false;
  private releaseRequested = false;
  private releaseSettled = false;
  private ready = false;
  private transportUnavailable = false;
  private recoveryEvents: JsonValue[] = [];
  private closed = false;
  private closing = false;
  private closePending: Promise<Result<null, AnalysisError>> | undefined;
  private deadline = 0;
  private currentOperation: string | null = null;
  private requestId = 0;
  private raw: HexRaysObservation[] = [];
  private attestation: JsonValue = null;
  private readonly bundle = loadHexRaysQueryBundle();

  constructor(
    private readonly config: IdaConfiguration,
    private readonly target: BinaryTarget,
    private readonly environment: Readonly<NodeJS.ProcessEnv>,
    private readonly connectionFactory: (
      config: IdaConfiguration,
      environment: Readonly<NodeJS.ProcessEnv>,
    ) => IdaMcpConnection,
    private readonly profile?: AnalysisProfileCommitment,
  ) {}

  execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options?: ExecutionOptions,
  ) {
    const call = this.tail.then(() =>
      this.executeSerial(operation, parameters, options),
    );
    this.tail = call.then(
      () => undefined,
      () => undefined,
    );
    return call;
  }

  private remaining(signal?: AbortSignal): number {
    if (signal?.aborted)
      throw new AnalysisCancelledError(this.currentOperation ?? "ida", {
        cause: signal.reason,
      });
    const value = Math.ceil(this.deadline - performance.now());
    if (value <= 0)
      throw new AnalysisTimeoutError(
        this.currentOperation ?? "ida",
        this.config.timeoutMs,
      );
    return value;
  }

  private async call(
    name: string,
    args: Readonly<Record<string, JsonValue>>,
    signal?: AbortSignal,
  ): Promise<JsonValue> {
    if (this.connection === undefined)
      throw new AnalysisProtocolError("Official IDA connection is absent");
    const result = await this.connection.call(name, args, {
      timeoutMs: this.remaining(signal),
      ...(signal === undefined ? {} : { signal }),
    });
    this.raw.push({ tool: name, arguments: args, result });
    return result;
  }

  private query(
    operation: HexRaysQuery,
    parameters: Readonly<Record<string, JsonValue>>,
    signal?: AbortSignal,
  ) {
    if (this.connection === undefined || this.instance === undefined)
      throw new AnalysisProtocolError("Official IDA instance is absent");
    return runHexRaysQuery({
      connection: this.connection,
      instanceId: this.instance,
      operation,
      parameters,
      timeoutMs: this.remaining(signal),
      observations: this.raw,
      bundle: this.bundle,
      signal,
    });
  }

  private insideWorkspace(path: string): boolean {
    return (
      this.workspace !== undefined &&
      sameIdaHostPath(dirname(resolve(path)), this.workspace.directory)
    );
  }

  private async observe(signal?: AbortSignal): Promise<Metadata> {
    const reply = await this.query("metadata", {}, signal);
    if (reply.status !== "ok")
      throw new AnalysisProtocolError("Official IDA metadata was unavailable");
    const metadata = metadataSchema.parse(reply.result);
    if (
      this.workspace === undefined ||
      !sameIdaHostPath(metadata.input_path, this.workspace.inputPath) ||
      metadata.sha256 !== this.workspace.inputSha256 ||
      !this.insideWorkspace(metadata.idb_path) ||
      (await idaFileDigest(this.workspace.inputPath)) !==
        this.workspace.inputSha256 ||
      (this.target.format === "s-record" &&
        metadata.processor.toLowerCase() !== "rl78")
    )
      throw new AnalysisProtocolError(
        "Official IDA target identity, processor, or private input changed",
      );
    if (!metadata.auto_analysis_ready)
      throw new AnalysisProtocolError(
        "Official IDA automatic analysis is not complete",
      );
    const environmentIdentity = JSON.stringify([
      metadata.processor,
      metadata.kernel_version,
      metadata.sdk_version,
      Object.entries(metadata.package_versions).sort(),
    ]);
    if (
      this.environmentIdentity !== undefined &&
      environmentIdentity !== this.environmentIdentity
    )
      throw new AnalysisProtocolError(
        "Official IDA engine or dependency environment changed during recovery",
      );
    this.environmentIdentity = environmentIdentity;
    const identity = JSON.stringify([
      metadata.input_path,
      metadata.idb_path,
      metadata.sha256,
      metadata.processor,
      metadata.imagebase,
      metadata.kernel_version,
      metadata.sdk_version,
    ]);
    if (this.initialIdentity !== undefined && identity !== this.initialIdentity)
      throw new AnalysisProtocolError(
        "Official IDA database identity changed during the session",
      );
    this.initialIdentity = identity;
    this.metadata = metadata;
    return metadata;
  }

  private async start(signal?: AbortSignal): Promise<void> {
    if (this.ready) return;
    if (this.workspace !== undefined)
      throw new AnalysisProtocolError(
        "Previous official IDA startup requires verified cleanup before retry",
      );
    if (
      this.profile !== undefined &&
      this.profile.parameters.query_implementation_sha256 !== this.bundle.sha256
    )
      throw new AnalysisProtocolError(
        "Official query implementation changed after profile commitment; rebuild or reopen",
      );
    this.workspace = await IdaWorkspace.allocate(
      this.target,
      this.config.workspaceRoot,
    );
    await this.workspace.copyInput();
    if (!("command" in this.config))
      throw new AnalysisProtocolError("Official IDA requires stdio transport");
    const configured: IdaConfiguration = {
      ...this.config,
      env: {
        ...("env" in this.config ? this.config.env : {}),
        IDA_NEXUS_STATE_DIR: join(this.workspace.directory, "nexus"),
        IDA_MCP_STATE_DIR: join(this.workspace.directory, "mcp"),
        IDA_NEXUS_IDALIB_ONLY: "1",
      },
    };
    this.connectedConfig = configured;
    this.connection = this.connectionFactory(configured, this.environment);
    this.remaining(signal);
    const catalog = await this.connection.connect({
      timeoutMs: this.remaining(signal),
      ...(signal === undefined ? {} : { signal }),
    });
    const missing = requiredTools.filter((name) => !catalog.includes(name));
    if (missing.length)
      throw new AnalysisProtocolError(
        `Official IDA MCP catalog is missing: ${missing.join(", ")}`,
      );
    await this.call(
      "reference",
      {
        query:
          "Database metadata, functions, instructions, strings, references and decompiler availability",
      },
      signal,
    );
    this.openAttempted = true;
    const raw = await this.call(
      "open_database",
      {
        path: this.workspace.inputPath,
        set_current: false,
        load_options:
          this.target.format === "s-record" ? { processor: "rl78" } : {},
      },
      signal,
    );
    this.openSettled = true;
    const opened = openedSchema.parse(raw);
    this.instance = opened.instance_id;
    const inventory = inventorySchema.parse(
      await this.call("list_databases", {}, signal),
    );
    const entry = inventory.instances.find(
      (item) => item.instance_id === this.instance,
    );
    if (
      entry?.backend !== "idalib" ||
      !this.insideWorkspace(entry.path) ||
      !["current", "attached"].includes(entry.status)
    )
      throw new AnalysisProtocolError(
        "Official MCP did not bind a held private idalib lease",
      );
    this.leaseVerified = true;
    await this.observe(signal);
    if (this.target.format === "s-record") {
      const reply = await this.query(
        "attest",
        { ranges: this.target.sRecord.summary.ranges },
        signal,
      );
      const loaded = z
        .object({
          ranges: z.array(
            z.object({
              start: z.string(),
              end: z.string(),
              sha256: z.string(),
            }),
          ),
          gaps_empty: z.boolean(),
          engine_segments: z.array(jsonValueSchema),
        })
        .parse(reply.result);
      if (
        reply.status !== "ok" ||
        !loaded.gaps_empty ||
        JSON.stringify(loaded.ranges) !==
          JSON.stringify(this.target.sRecord.summary.ranges)
      )
        throw new AnalysisProtocolError(
          "Official IDA loaded bytes or sparse gaps differ from the admitted S-record",
        );
      this.attestation = jsonValueSchema.parse({
        source: this.target.sRecord.summary,
        loaded,
      });
    }
    this.ready = true;
  }

  private async executeSerial(
    operation: AnalysisOperation,
    input: Readonly<Record<string, JsonValue>>,
    options?: ExecutionOptions,
  ) {
    if (this.recoveryBlocked !== undefined) return err(this.recoveryBlocked);
    if (this.closed || this.closing)
      return err(
        new AnalysisProtocolError("Official IDA session is closing or closed"),
      );
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(operation, { cause: options.signal.reason }),
      );
    if (
      operation !== "health" &&
      !(IDA_OPERATIONS as readonly string[]).includes(operation)
    )
      return err(
        new AnalysisCapabilityUnavailableError(
          "ida",
          operation,
          "Read-only compatibility operations only",
        ),
      );
    let parameters = input;
    if (operation !== "health") {
      const parsed = parseIdaInput(operation, input);
      if (!parsed.ok) return parsed;
      parameters = parsed.value;
    }
    if (
      parameters.document !== undefined &&
      (typeof parameters.document !== "string" ||
        (!sameIdaHostPath(parameters.document, this.target.path) &&
          !sameIdaHostPath(
            parameters.document,
            this.target.sourcePath ?? this.target.path,
          )))
    )
      return err(
        new AnalysisInputError(operation, {
          userMessage: "document must identify the admitted target",
        }),
      );
    this.currentOperation = operation;
    this.requestId++;
    this.deadline = performance.now() + this.config.timeoutMs;
    this.raw = [];
    this.recoveryEvents = [];
    for (let attempt = 0; ; attempt++) {
      this.currentOperation = operation;
      let before: Metadata | undefined;
      let runner: HexRaysOperations | undefined;
      try {
        await this.start(options?.signal);
        before = await this.observe(options?.signal);
        runner = new HexRaysOperations(
          (name, args) => this.query(name, args, options?.signal),
          this.target.path,
          options?.selectorOrigin,
        );
        const result =
          operation === "health"
            ? jsonValueSchema.parse({
                ready: true,
                mode: "headless",
                database: this.instance!,
                upstream: this.connection!.serverInfo(),
                metadata: before,
                load_attestation: this.attestation,
              })
            : await runner.run(operation, parameters);
        const after = await this.observe(options?.signal);
        this.remaining(options?.signal);
        const locations: EvidenceLocation[] = [
          { kind: "artifact-path", path: this.target.path },
        ];
        if (typeof parameters.address === "string")
          locations.push({ kind: "address", address: parameters.address });
        this.transportUnavailable = false;
        return ok(
          createAnalysisExecution(result, HEX_RAYS_PROVIDER_IDENTITY, {
            ...(this.profile === undefined
              ? {}
              : { analysisProfile: this.profile }),
            rawResult: {
              upstream: this.connection!.serverInfo(),
              metadata_before: before,
              metadata_after: after,
              load_attestation: this.attestation,
              recovery_events: this.recoveryEvents,
              observations: jsonValueSchema.parse(this.raw),
            },
            limitations: [...limits, ...runner.limitations],
            locations,
            ...(runner.relationshipCoverage === undefined
              ? {}
              : { relationshipCoverage: runner.relationshipCoverage }),
            ...(runner.referencesTruncated === undefined
              ? {}
              : { referencesTruncated: runner.referencesTruncated }),
          }),
        );
      } catch (cause) {
        if (
          attempt === 0 &&
          this.ready &&
          !this.closing &&
          !options?.signal?.aborted &&
          cause instanceof ProviderAdapterError &&
          cause.operation === "transport" &&
          performance.now() < this.deadline
        ) {
          const oldInstance = this.instance;
          const released = await this.release(false);
          if (released.ok) {
            this.recoveryEvents.push({
              previous_instance_id: oldInstance ?? null,
              reason: cause.message,
              action: "verified_release_then_reconnect",
              attempt: 1,
            });
            this.connectedConfig = undefined;
            this.connection = undefined;
            this.workspace = undefined;
            this.instance = undefined;
            this.metadata = undefined;
            this.initialIdentity = undefined;
            this.openAttempted = false;
            this.openSettled = false;
            this.leaseVerified = false;
            this.releaseRequested = false;
            this.releaseSettled = false;
            this.closed = false;
            this.ready = false;
            this.attestation = null;
            continue;
          }
          this.recoveryBlocked = released.error;
          cause = analysisErrorWithCleanupFailure(
            cause,
            released.error,
            operation,
          )
            .bindCleanupDependencies([released.error])
            .bindCleanupResourceOwner(released.error);
        }
        // An SDK timeout drops the pending response, so subsequent reads must wait
        // for an explicit, verified close rather than racing the old Python call.
        if (cause instanceof IdaMcpRequestTimeoutError && this.openAttempted)
          this.recoveryBlocked = cause;
        this.transportUnavailable =
          cause instanceof ProviderAdapterError &&
          cause.operation === "transport";
        const failure = options?.signal?.aborted
          ? new AnalysisCancelledError(operation, {
              cause,
              ...(cause instanceof AnalysisError
                ? {
                    capturedOutput: cause.capturedOutput,
                    diagnostics: cause.diagnostics,
                    partialObservation: cause.partialObservation,
                    cleanup:
                      cause.cleanup ??
                      (cause.cleanupIncomplete
                        ? {
                            reason: cause.message,
                            resources: cause.cleanupResources,
                          }
                        : undefined),
                  }
                : {}),
            })
          : cause instanceof AnalysisError
            ? cause
            : new AnalysisOutputError(
                operation,
                cause instanceof Error ? cause.message : String(cause),
                { cause },
              );
        if (failure !== cause && cause instanceof AnalysisError)
          failure
            .bindCleanupDependencies([cause])
            .bindCleanupResourceOwner(cause);
        if (before !== undefined && this.raw.length > 0)
          failure.retainPartialObservation(
            createEvidence(this.target, HEX_RAYS_PROVIDER_IDENTITY, {
              operation,
              parameters,
              ...(this.profile === undefined
                ? {}
                : { analysisProfile: this.profile }),
              locations: [{ kind: "artifact-path", path: this.target.path }],
              result: {
                status: "partial",
                target_binding: "not_post_verified",
              },
              rawResult: {
                metadata_before: before,
                observations: jsonValueSchema.parse(this.raw),
              },
              limitations: [
                ...limits,
                "The operation failed; these replies do not establish a complete result.",
              ],
            }),
          );
        return err(failure);
      } finally {
        this.currentOperation = null;
      }
    }
  }

  operationHealthSnapshot(): ProviderOperationHealth {
    return {
      state:
        this.currentOperation === null
          ? this.closed || this.instance === undefined
            ? "not_started"
            : this.recoveryBlocked !== undefined
              ? "unknown"
              : this.transportUnavailable
                ? "unreachable"
                : "idle"
          : "busy",
      stage: this.currentOperation === null ? null : "analysis",
      retryAction:
        this.currentOperation === null
          ? this.transportUnavailable
            ? "restart_provider"
            : null
          : "wait",
      exitCode: null,
      requests:
        this.currentOperation === null
          ? []
          : [
              {
                requestId: this.requestId,
                operation: this.currentOperation,
                stage: "analysis",
              },
            ],
    };
  }

  close(): Promise<Result<null, AnalysisError>> {
    if (this.closePending !== undefined) return this.closePending;
    this.closing = true;
    const pending = this.tail.then(() => this.release());
    this.closePending = pending.finally(() => {
      this.closePending = undefined;
    });
    return this.closePending;
  }

  private released(): void {
    for (const failure of this.cleanupFailures) failure.resolveCleanup();
    this.cleanupFailures.clear();
    this.recoveryBlocked = undefined;
    this.ready = false;
    this.closed = true;
  }

  private async verifyExitedTransport(): Promise<void> {
    const previous = this.connection;
    if (
      !previous?.ownedProcessExited?.() ||
      !this.leaseVerified ||
      !this.openSettled ||
      this.connectedConfig === undefined
    )
      throw new AnalysisProtocolError(
        "Lost transport does not prove that its database was released",
      );
    await previous.close();
    // This sibling only discovers owners in the same private namespace. It never opens an IDB.
    this.connection = this.connectionFactory(
      this.connectedConfig,
      this.environment,
    );
    await this.connection.connect({ timeoutMs: this.remaining() });
    const inventory = inventorySchema.parse(
      await this.call("list_databases", {}),
    );
    if (inventory.instances.some((item) => this.insideWorkspace(item.path)))
      throw new AnalysisProtocolError(
        "Exited MCP owner still has a registered private IDB worker",
      );
    this.releaseRequested = true;
    this.releaseSettled = true;
    await this.connection.close();
    await this.workspace?.remove();
    this.released();
  }

  private async release(
    resetDeadline = true,
  ): Promise<Result<null, AnalysisError>> {
    if (this.closed) return ok(null);
    if (resetDeadline)
      this.deadline = performance.now() + this.config.timeoutMs;
    try {
      if (this.connection !== undefined && this.openAttempted) {
        if (this.instance === undefined) {
          const inventory = inventorySchema.parse(
            await this.call("list_databases", {}),
          );
          const held = inventory.instances.filter((item) =>
            this.insideWorkspace(item.path),
          );
          const own = held.find(
            (item) =>
              item.backend === "idalib" &&
              item.instance_id !== null &&
              ["current", "attached"].includes(item.status),
          );
          if (own?.instance_id) {
            this.instance = own.instance_id;
            this.leaseVerified = true;
          } else if (!this.openSettled || held.length > 0)
            throw new AnalysisProtocolError(
              "Startup ownership remains unverified",
            );
        }
        if (this.instance !== undefined) {
          if (!this.leaseVerified) {
            const inventory = inventorySchema.parse(
              await this.call("list_databases", {}),
            );
            if (
              !inventory.instances.some(
                (item) =>
                  item.instance_id === this.instance &&
                  item.backend === "idalib" &&
                  this.insideWorkspace(item.path) &&
                  ["current", "attached"].includes(item.status),
              )
            )
              throw new AnalysisProtocolError(
                "Cannot release an unverified or foreign IDA lease",
              );
            this.leaseVerified = true;
          }
          if (!this.releaseSettled) {
            this.releaseRequested = true;
            try {
              const raw = await this.call("close_database", {
                instance_id: this.instance,
              });
              this.releaseSettled = true;
              z.object({ closed: z.literal(true) }).parse(raw);
            } catch (cause) {
              // A completed producer error may follow lease removal. A timeout is not completion.
              if (cause instanceof AnalysisProtocolError)
                this.releaseSettled = true;
              else throw cause;
            }
          }
          const inventory = inventorySchema.parse(
            await this.call("list_databases", {}),
          );
          if (
            inventory.instances.some(
              (item) =>
                item.instance_id === this.instance ||
                this.insideWorkspace(item.path),
            )
          )
            throw new AnalysisProtocolError(
              "Official IDA private input or database remains discoverable after lease release",
            );
          if (!this.releaseRequested || !this.releaseSettled)
            throw new AnalysisProtocolError(
              "Official IDA release was not acknowledged",
            );
        }
      }
      await this.connection?.close();
      await this.workspace?.remove();
      this.released();
      return ok(null);
    } catch (cause) {
      let failure = cause;
      if (
        this.connection?.ownedProcessExited?.() &&
        this.leaseVerified &&
        this.openSettled
      ) {
        try {
          await this.verifyExitedTransport();
          return ok(null);
        } catch (verification) {
          failure = new AnalysisProtocolError(
            `Exited transport cleanup could not be verified: ${verification instanceof Error ? verification.message : String(verification)}`,
            { cause },
          );
        }
      }
      this.connection?.detach();
      const cleanup = new HexRaysCleanupError(
        this.workspace?.directory ?? "Official IDA MCP connection",
        failure,
      );
      this.cleanupFailures.add(cleanup);
      return err(cleanup);
    }
  }
}
