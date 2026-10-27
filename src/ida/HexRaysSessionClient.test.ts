import { createHash } from "node:crypto";
import { access, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { createIdaTarget } from "../../tests/fixtures/idaMcp.js";
import { parseBinaryTarget } from "../application/BinaryTargetResolver.js";
import {
  AnalysisProtocolError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { IdaConfiguration } from "./IdaConfiguration.js";
import type { IdaMcpConnection } from "./IdaMcpConnection.js";
import { HexRaysSessionClient } from "./HexRaysSessionClient.js";

interface Request {
  operation: string;
  request_id: string;
  parameters: Record<string, JsonValue>;
}
class OfficialFixture implements IdaMcpConnection {
  readonly calls: {
    name: string;
    args: Readonly<Record<string, JsonValue>>;
  }[] = [];
  readonly queries: Request[] = [];
  input = "";
  sha256 = "";
  instance = "test-instance";
  active = false;
  keepPath = false;
  foreign = false;
  corrupt = "";
  badPage = false;
  closeTimeout = false;
  closeCalls = 0;
  closes = 0;
  transportFault = false;
  exited = false;
  dieOnAssembly = false;
  pseudoError = false;
  onQuery: ((request: Request) => void) | undefined;
  constructor(private readonly processor = "metapc") {}
  async connect() {
    return [
      "open_database",
      "execute_python",
      "reference",
      "list_databases",
      "close_database",
    ];
  }
  serverInfo() {
    return { name: "ida", version: "20261008.0.1" };
  }
  async close() {
    this.closes++;
  }
  detach() {}
  ownedProcessExited() {
    return this.exited;
  }
  private fn(index = 0) {
    return {
      address: `0x${(0x1000 + index * 4).toString(16)}`,
      name: `fixture_${index}`,
      size: "4",
    };
  }
  private inventory(): JsonValue {
    return {
      instances:
        this.active || this.keepPath
          ? [
              {
                path: this.foreign
                  ? "/foreign/user.i64"
                  : this.keepPath
                    ? join(dirname(this.input), "working.i64")
                    : this.input,
                backend: "idalib",
                instance_id: this.active ? this.instance : null,
                status: this.active ? "current" : "available",
              },
            ]
          : [],
    };
  }

  async call(
    name: string,
    args: Readonly<Record<string, JsonValue>>,
  ): Promise<JsonValue> {
    this.calls.push({ name, args });
    if (this.exited)
      throw new ProviderAdapterError("ida", "transport", {
        diagnostics: { reason: "owned process exited" },
      });
    if (name === "reference") return "IDA reference is plain text";
    if (name === "open_database") {
      this.input = String(args.path);
      this.sha256 = createHash("sha256")
        .update(await readFile(this.input))
        .digest("hex");
      this.active = true;
      return {
        instance_id: this.instance,
        backend: "idalib",
        status: "current",
      };
    }
    if (name === "list_databases") return this.inventory();
    if (name === "close_database") {
      this.closeCalls++;
      if (this.closeTimeout) {
        this.closeTimeout = false;
        this.active = false;
        throw new AnalysisTimeoutError(name, 10);
      }
      if (!this.active)
        throw new AnalysisProtocolError("unknown database instance");
      this.active = false;
      return { closed: true };
    }
    if (name !== "execute_python" || args.instance_id !== this.instance)
      throw new Error("Unexpected fixture request");
    const encoded = /bytes\.fromhex\("([a-f0-9]+)"\)/u.exec(
      String(args.code),
    )?.[1];
    if (encoded === undefined)
      throw new Error("Query parameters are not hex-encoded JSON");
    const request: Request = JSON.parse(Buffer.from(encoded, "hex").toString());
    this.queries.push(request);
    this.onQuery?.(request);
    const response = {
      version: 1,
      operation: request.operation,
      request_id: request.request_id,
      status: "ok",
      reason: null as string | null,
      result: null as JsonValue,
    };
    const offset = Number(request.parameters.offset ?? 0);
    const page = (items: JsonValue[]) => ({
      items: items.slice(offset, offset + 100),
      total: items.length,
      next_offset: this.badPage
        ? offset
        : offset + 100 < items.length
          ? offset + 100
          : null,
    });
    switch (request.operation) {
      case "metadata":
        response.result = {
          input_path: this.input,
          idb_path: join(dirname(this.input), "working.i64"),
          sha256: this.corrupt === "sha" ? "0".repeat(64) : this.sha256,
          processor: this.corrupt === "processor" ? "wrong" : this.processor,
          imagebase: "0x0",
          kernel_version: "9.5",
          sdk_version: 950,
          auto_analysis_ready: true,
          package_versions: {},
        };
        break;
      case "attest":
        response.result = {
          ranges: request.parameters.ranges!,
          gaps_empty: true,
          engine_segments: [],
        };
        break;
      case "functions":
        response.result = page(
          Array.from({ length: 201 }, (_, index) => this.fn(index)),
        );
        break;
      case "strings":
        response.result = page([
          { address: "0x2000", value: "Hello 世界" },
          { address: "0x2010", value: "literal.*" },
        ]);
        break;
      case "resolve":
        if (request.parameters.query === "missing") {
          response.status = "missing";
          response.reason = "Not a function";
        } else response.result = this.fn();
        break;
      case "assembly":
        if (this.dieOnAssembly) {
          this.exited = true;
          this.active = false;
          throw new ProviderAdapterError("ida", "transport", {
            diagnostics: { reason: "owned process exited" },
          });
        }
        if (this.transportFault) {
          this.transportFault = false;
          throw new ProviderAdapterError("ida", "transport", {
            diagnostics: { reason: "socket reset" },
          });
        }
        response.result = {
          ...page([
            { address: "0x1000", instruction: "nop" },
            { address: "0x1001", instruction: "ret" },
          ]),
          function: this.fn(),
        };
        break;
      case "pseudocode":
        response.status = this.pseudoError ? "error" : "unavailable";
        response.reason = "Decompiler unavailable";
        break;
      case "callees":
        response.result = page([this.fn(1)]);
        break;
      case "xrefs":
        response.result = page([{ address: "0x1100", type: 17 }]);
        break;
      case "contains":
        response.result = { function: this.fn(), in_segment: true };
        break;
      default:
        throw new Error("Unknown fixture query");
    }
    if (this.corrupt === "request" && request.operation === "assembly")
      response.request_id = "foreign-request";
    return jsonValueSchema.parse({ result: response, stdout: "", stderr: "" });
  }
}

const withClient = async (
  test: (
    client: HexRaysSessionClient,
    fixture: OfficialFixture,
    target: BinaryTarget,
  ) => Promise<void>,
  sRecord = false,
) => {
  const created = await createIdaTarget();
  let target: BinaryTarget = created.target;
  if (sRecord) {
    const path = join(created.root, "input.s19");
    await writeFile(path, "S10501000011E8\nS9030000FC\n");
    const parsed = await parseBinaryTarget(path, {
      formatHint: "s-record",
      architecture: "rl78",
    });
    if (!parsed.ok) throw parsed.error;
    target = parsed.value;
  }
  const config: IdaConfiguration = {
    command: "fixture",
    args: [],
    env: {},
    mode: "headless",
    protocol: "hex-rays",
    timeoutMs: 5000,
    workspaceRoot: created.root,
  };
  const fixture = new OfficialFixture(sRecord ? "rl78" : "metapc");
  const client = new HexRaysSessionClient(config, target, {}, () => fixture);
  try {
    await test(client, fixture, target);
  } finally {
    await client.close();
    await rm(created.root, { recursive: true, force: true });
  }
};

describe("official IDA read-only compatibility session", () => {
  it("opens a private RL78 lease, attests bytes, pages inventories and returns a dossier without a decompiler", () =>
    withClient(async (client, fixture, target) => {
      expect((await client.execute("health", {})).ok).toBe(true);
      expect(fixture.input).not.toBe(target.path);
      expect(
        fixture.calls.find((call) => call.name === "open_database")?.args
          .load_options,
      ).toEqual({ processor: "rl78" });
      const listed = await client.execute("list_procedures", {});
      expect(listed.ok).toBe(true);
      if (listed.ok) expect(listed.value.result).toHaveLength(201);
      expect(
        fixture.queries
          .filter((q) => q.operation === "functions")
          .map((q) => q.parameters.offset),
      ).toEqual([0, 100, 200]);
      const analyzed = await client.execute("analyze_function", {
        procedure: "0x1000",
      });
      expect(analyzed.ok).toBe(true);
      if (analyzed.ok)
        expect(analyzed.value.result).toMatchObject({
          assembly: ["0x1000: nop", "0x1001: ret"],
          pseudocode: "",
          facet_availability: {
            pseudocode: { available: false },
            assembly: { available: true },
          },
        });
      expect((await client.execute("list_strings", {})).ok).toBe(true);
      expect(
        (await client.execute("procedure_pseudo_code", { procedure: "0x1000" }))
          .ok,
      ).toBe(true);
      expect((await client.close()).ok).toBe(true);
      await expect(access(dirname(fixture.input))).rejects.toThrow();
      expect(await readFile(target.path, "utf8")).toContain("S105");
    }, true));
  it("preserves successful facets after a function query failure and keeps subsequent reads usable", () =>
    withClient(async (client, fixture) => {
      fixture.pseudoError = true;
      const result = await client.execute("analyze_function", {
        procedure: "0x1000",
      });
      expect(result.ok).toBe(true);
      if (result.ok)
        expect(result.value.result).toMatchObject({
          assembly: ["0x1000: nop", "0x1001: ret"],
          facet_availability: {
            pseudocode: { available: false },
            callees: { available: true },
          },
        });
      fixture.pseudoError = false;
      expect((await client.execute("list_procedures", {})).ok).toBe(true);
    }));
  it("rejects malformed request identities and nonadvancing pages without ending the session", () =>
    withClient(async (client, fixture) => {
      fixture.corrupt = "request";
      expect(
        (await client.execute("analyze_function", { procedure: "0x1000" })).ok,
      ).toBe(false);
      fixture.corrupt = "";
      fixture.badPage = true;
      expect((await client.execute("list_procedures", {})).ok).toBe(false);
      fixture.badPage = false;
      expect((await client.execute("list_procedures", {})).ok).toBe(true);
    }));
});

describe("official IDA ownership, cleanup and cancellation", () => {
  it("does not close a foreign lease claimed by a bad open reply", () =>
    withClient(async (client, fixture) => {
      fixture.foreign = true;
      expect((await client.execute("health", {})).ok).toBe(false);
      const close = await client.close();
      expect(close.ok).toBe(false);
      expect(fixture.closeCalls).toBe(0);
    }));
  it("retains a workspace when an unheld private database still appears after release", () =>
    withClient(async (client, fixture) => {
      expect((await client.execute("health", {})).ok).toBe(true);
      fixture.keepPath = true;
      const closed = await client.close();
      expect(closed.ok).toBe(false);
      if (!closed.ok) expect(closed.error.cleanupIncomplete).toBe(true);
      await expect(access(dirname(fixture.input))).resolves.toBeUndefined();
      fixture.keepPath = false;
      expect((await client.close()).ok).toBe(true);
      expect(fixture.closeCalls).toBe(1);
    }));
  it("does not equate a close timeout and absent instance ID with completed cleanup", () =>
    withClient(async (client, fixture) => {
      expect((await client.execute("health", {})).ok).toBe(true);
      fixture.closeTimeout = true;
      expect((await client.close()).ok).toBe(false);
      await expect(access(dirname(fixture.input))).resolves.toBeUndefined();
      expect((await client.close()).ok).toBe(true);
      expect(fixture.closeCalls).toBe(2);
    }));
  it.each(["sha", "processor"])(
    "refuses wrong startup %s without admitting analysis",
    (corrupt) =>
      withClient(async (client, fixture) => {
        fixture.corrupt = corrupt;
        expect((await client.execute("health", {})).ok).toBe(false);
        expect(fixture.queries.some((q) => q.operation === "functions")).toBe(
          false,
        );
      }, true),
  );
  it("retains partial replies on late cancellation and leaves later work available", () =>
    withClient(async (client, fixture) => {
      expect((await client.execute("health", {})).ok).toBe(true);
      const controller = new AbortController();
      fixture.onQuery = (request) => {
        if (request.operation === "assembly") controller.abort("stop");
      };
      const result = await client.execute(
        "analyze_function",
        { procedure: "0x1000" },
        { signal: controller.signal },
      );
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error._tag).toBe("AnalysisCancelledError");
        expect(result.error.partialObservation).toBeDefined();
      }
      fixture.onQuery = undefined;
      expect((await client.execute("list_procedures", {})).ok).toBe(true);
    }));
  it("reconnects only after verified old-lease cleanup and retries a read once", async () => {
    const { root, target } = await createIdaTarget();
    const peers: OfficialFixture[] = [];
    const config: IdaConfiguration = {
      command: "fixture",
      args: [],
      env: {},
      mode: "headless",
      protocol: "hex-rays",
      timeoutMs: 5000,
      workspaceRoot: root,
    };
    const client = new HexRaysSessionClient(config, target, {}, () => {
      const fixture = new OfficialFixture();
      fixture.transportFault = peers.length === 0;
      peers.push(fixture);
      return fixture;
    });
    try {
      const result = await client.execute("analyze_function", {
        procedure: "0x1000",
      });
      expect(result.ok).toBe(true);
      expect(peers).toHaveLength(2);
      expect(peers[0]?.closeCalls).toBe(1);
      expect((await client.close()).ok).toBe(true);
    } finally {
      await client.close();
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("official IDA request and recovery boundaries", () => {
  it("does not report success when cancellation arrives with final metadata", () =>
    withClient(async (client, fixture) => {
      expect((await client.execute("health", {})).ok).toBe(true);
      const controller = new AbortController();
      let metadata = 0;
      fixture.onQuery = (request) => {
        if (request.operation === "metadata" && ++metadata === 2)
          controller.abort();
      };
      const result = await client.execute(
        "list_strings",
        {},
        { signal: controller.signal },
      );
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error._tag).toBe("AnalysisCancelledError");
      fixture.onQuery = undefined;
      expect((await client.execute("list_strings", {})).ok).toBe(true);
    }));
  it("shares a single deadline across page requests", () =>
    withClient(async (client, fixture) => {
      expect((await client.execute("health", {})).ok).toBe(true);
      let now = performance.now();
      const spy = vi.spyOn(performance, "now").mockImplementation(() => now);
      try {
        fixture.onQuery = (request) => {
          if (request.operation === "functions") now += 3000;
        };
        const result = await client.execute("list_procedures", {});
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.error._tag).toBe("AnalysisTimeoutError");
        expect(
          fixture.queries.filter((q) => q.operation === "functions"),
        ).toHaveLength(2);
      } finally {
        fixture.onQuery = undefined;
        spy.mockRestore();
      }
      expect((await client.execute("list_strings", {})).ok).toBe(false);
      expect((await client.close()).ok).toBe(true);
    }));
  it("transmits quoted and multiline selectors as JSON data", () =>
    withClient(async (client, fixture) => {
      const selector = "untrusted'\n__import__('os').system('do_not_run')";
      expect(
        (await client.execute("procedure_address", { procedure: selector })).ok,
      ).toBe(true);
      expect(
        fixture.queries.find((q) => q.operation === "resolve")?.parameters
          .query,
      ).toBe(selector);
      for (const call of fixture.calls.filter(
        (c) => c.name === "execute_python",
      ))
        expect(String(call.args.code)).not.toContain(selector);
    }));
  it("does not create a third peer when the single recovered read also fails", async () => {
    const { root, target } = await createIdaTarget();
    const peers: OfficialFixture[] = [];
    const config: IdaConfiguration = {
      command: "fixture",
      args: [],
      env: {},
      mode: "headless",
      protocol: "hex-rays",
      timeoutMs: 5000,
      workspaceRoot: root,
    };
    const client = new HexRaysSessionClient(config, target, {}, () => {
      const f = new OfficialFixture();
      f.transportFault = true;
      peers.push(f);
      return f;
    });
    try {
      expect(
        (await client.execute("analyze_function", { procedure: "0x1000" })).ok,
      ).toBe(false);
      expect(peers).toHaveLength(2);
    } finally {
      await client.close();
      await rm(root, { recursive: true, force: true });
    }
  });
  it("blocks reconnect and further queries while old cleanup remains unverified", async () => {
    const { root, target } = await createIdaTarget();
    const fixture = new OfficialFixture();
    fixture.transportFault = true;
    fixture.keepPath = true;
    let connections = 0;
    const config: IdaConfiguration = {
      command: "fixture",
      args: [],
      env: {},
      mode: "headless",
      protocol: "hex-rays",
      timeoutMs: 5000,
      workspaceRoot: root,
    };
    const client = new HexRaysSessionClient(config, target, {}, () => {
      connections++;
      return fixture;
    });
    try {
      expect(
        (await client.execute("analyze_function", { procedure: "0x1000" })).ok,
      ).toBe(false);
      const calls = fixture.calls.length;
      expect((await client.execute("list_strings", {})).ok).toBe(false);
      expect(fixture.calls).toHaveLength(calls);
      expect(connections).toBe(1);
      fixture.keepPath = false;
      expect((await client.close()).ok).toBe(true);
    } finally {
      await client.close();
      await rm(root, { recursive: true, force: true });
    }
  });
});

it("uses a discovery-only peer after a positively observed transport exit", async () => {
  const { root, target } = await createIdaTarget();
  const peers: OfficialFixture[] = [];
  const config: IdaConfiguration = {
    command: "fixture",
    args: [],
    env: {},
    mode: "headless",
    protocol: "hex-rays",
    timeoutMs: 5000,
    workspaceRoot: root,
  };
  const client = new HexRaysSessionClient(config, target, {}, () => {
    const peer = new OfficialFixture();
    peer.dieOnAssembly = peers.length === 0;
    peers.push(peer);
    return peer;
  });
  try {
    expect(
      (await client.execute("analyze_function", { procedure: "0x1000" })).ok,
    ).toBe(true);
    expect(peers).toHaveLength(3);
    expect(peers[1]?.calls.map((c) => c.name)).toEqual(["list_databases"]);
    expect(peers[1]?.queries).toHaveLength(0);
  } finally {
    await client.close();
    await rm(root, { recursive: true, force: true });
  }
});
