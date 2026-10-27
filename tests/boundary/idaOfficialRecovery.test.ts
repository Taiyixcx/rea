import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { describe, expect, it } from "vitest";
import { createIdaTarget } from "../fixtures/idaMcp.js";
import { createIdaMcpConnection } from "../../src/ida/IdaMcpConnection.js";
import { HexRaysSessionClient } from "../../src/ida/HexRaysSessionClient.js";

// A real stdio MCP peer keeps an execute_python request outstanding until the
// test releases it. It never loads IDA or executes the received Python string.
const peer = String.raw`
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const readline = require("node:readline");
const directory = process.argv[1];
const eventPath = path.join(directory, "events.jsonl");
const event = (value) => fs.appendFileSync(eventPath, JSON.stringify(value) + "\n");
const tools = ["reference", "open_database", "list_databases", "close_database", "execute_python"];
let input = "";
let active = false;
const fn = { address: "0x1000", name: "fixture", size: "2" };
const result = (id, value) => process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result: value }) + "\n");
const toolResult = (id, value) => result(id, { content: [{ type: "text", text: JSON.stringify(value) }], structuredContent: value });
readline.createInterface({ input: process.stdin }).on("line", async (line) => {
  const request = JSON.parse(line);
  if (request.id === undefined) return;
  if (request.method === "initialize") return result(request.id, { protocolVersion: request.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: "official-fixture", version: "1" } });
  if (request.method === "tools/list") return result(request.id, { tools: tools.map((name) => ({ name, inputSchema: { type: "object" } })) });
  const { name, arguments: args } = request.params;
  event({ request: name });
  if (name === "reference") return result(request.id, { content: [{ type: "text", text: "fixed reference" }] });
  if (name === "open_database") { input = args.path; active = true; return toolResult(request.id, { instance_id: "owned", backend: "idalib", status: "current" }); }
  if (name === "list_databases") return toolResult(request.id, { instances: active ? [{ instance_id: "owned", backend: "idalib", status: "current", path: input }] : [] });
  if (name === "close_database") { active = false; return toolResult(request.id, { closed: true }); }
  const encoded = /bytes\.fromhex\("([a-f0-9]+)"\)/u.exec(args.code)[1];
  const query = JSON.parse(Buffer.from(encoded, "hex").toString());
  event({ query: query.operation });
  let value;
  if (query.operation === "metadata") value = { input_path: input, idb_path: path.join(path.dirname(input), "working.i64"), sha256: crypto.createHash("sha256").update(fs.readFileSync(input)).digest("hex"), processor: "metapc", imagebase: "0x0", kernel_version: "9.5", sdk_version: 950, auto_analysis_ready: true, package_versions: {} };
  else if (query.operation === "resolve") value = fn;
  else if (query.operation === "functions") value = { items: [fn], total: 1, next_offset: null };
  else if (query.operation === "assembly") {
    fs.writeFileSync(path.join(directory, "assembly-started"), "started");
    await new Promise((resolve) => { const timer = setInterval(() => { if (fs.existsSync(path.join(directory, "release"))) { clearInterval(timer); resolve(); } }, 5); });
    value = { items: [{ address: "0x1000", instruction: "ret" }], total: 1, next_offset: null, function: fn };
  } else throw new Error("Unexpected fixture query");
  event({ responded: query.operation });
  toolResult(request.id, { result: { version: 1, operation: query.operation, request_id: query.request_id, status: "ok", reason: null, result: value }, stdout: "", stderr: "" });
});
`;

const waitForFile = async (path: string) => {
  const deadline = performance.now() + 5000;
  while (true) {
    try {
      return await readFile(path, "utf8");
    } catch {
      if (performance.now() > deadline) throw new Error(`Timed out: ${path}`);
      await delay(5);
    }
  }
};

describe("official IDA stdio request completion", () => {
  it.each([false, true])(
    "drains a cancelled native request before read/release (early close=%s)",
    async (earlyClose) => {
      const { root, target } = await createIdaTarget();
      const events = join(root, "events.jsonl");
      const client = new HexRaysSessionClient(
        {
          protocol: "hex-rays",
          mode: "headless",
          command: process.execPath,
          args: ["-e", peer, root],
          env: {},
          timeoutMs: 5000,
          workspaceRoot: root,
        },
        target,
        process.env,
        createIdaMcpConnection,
      );
      let pending: Promise<unknown> | undefined;
      try {
        expect((await client.execute("health", {})).ok).toBe(true);
        const controller = new AbortController();
        let completed = false;
        const cancelled = client.execute(
          "procedure_assembly",
          { procedure: "0x1000" },
          { signal: controller.signal },
        );
        pending = cancelled.finally(() => {
          completed = true;
        });
        await waitForFile(join(root, "assembly-started"));
        const before = await readFile(events, "utf8");
        controller.abort();
        const next = earlyClose
          ? undefined
          : client.execute("list_procedures", {});
        const closing = earlyClose ? client.close() : undefined;
        await delay(40);
        expect(completed).toBe(false);
        expect(await readFile(events, "utf8")).toBe(before);
        await writeFile(join(root, "release"), "released");
        expect(await cancelled).toMatchObject({
          ok: false,
          error: { _tag: "AnalysisCancelledError" },
        });
        if (next !== undefined) expect((await next).ok).toBe(true);
        expect((await (closing ?? client.close())).ok).toBe(true);
        const lines = (await readFile(events, "utf8"))
          .trim()
          .split("\n")
          .map((line) => JSON.parse(line));
        const responseIndex = lines.findIndex(
          (entry) => entry.responded === "assembly",
        );
        if (!earlyClose)
          expect(responseIndex).toBeLessThan(
            lines.findIndex((entry) => entry.query === "functions"),
          );
        expect(responseIndex).toBeLessThan(
          lines.findIndex((entry) => entry.request === "close_database"),
        );
      } finally {
        await writeFile(join(root, "release"), "released");
        await pending;
        await client.close();
        await rm(root, { recursive: true, force: true });
      }
    },
  );
});
