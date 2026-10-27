import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { setTimeout as delay } from "node:timers/promises";
import { idaBuildIdentity } from "./lib/ida-build-identity.mjs";
import { createRL78Fixture } from "./lib/rl78-fixture.mjs";

// This verifier closes only its own MCP transport after a completed read. The
// production adapter must discover lease release before opening a new database.
const { values } = parseArgs({
  options: {
    config: { type: "string" },
    report: { type: "string" },
    "package-root": { type: "string" },
  },
});
const packageRoot = resolve(
  values["package-root"] ?? fileURLToPath(new URL("../", import.meta.url)),
);
const configPath = resolve(
  values.config ?? process.env.REA_IDA_MCP_CONFIG ?? "",
);
assert(
  values.config || process.env.REA_IDA_MCP_CONFIG,
  "Set REA_IDA_MCP_CONFIG or --config",
);
const reportPath = resolve(values.report ?? "ida-recovery-report.json");
const load = (path) =>
  import(pathToFileURL(join(packageRoot, "dist", path)).href);
const [
  { IdaProvider },
  { createIdaMcpConnection },
  { composeBinarySession },
  { AnalysisProviderRegistry },
  { createAnalysisExecutionEvidence },
  { ProviderAdapterError },
] = await Promise.all([
  load("ida/IdaProvider.js"),
  load("ida/IdaMcpConnection.js"),
  load("application/binary/BinarySessionComposition.js"),
  load("application/binary/AnalysisProviderRegistry.js"),
  load("application/AnalysisProvider.js"),
  load("domain/providerAdapterError.js"),
]);
const directory = await mkdtemp(join(tmpdir(), "rea-ida-recovery-"));
const fixture = await createRL78Fixture(directory);
const report = {
  passed: false,
  build_identity: await idaBuildIdentity(packageRoot),
  scope:
    "real official IDA, production provider/session, controlled owned-transport closure after a completed read",
  started_at: new Date().toISOString(),
  checks: [],
  connections: [],
  evidence_ids: [],
  fixture_sha256: fixture.oracle.sha256,
};
let armed = false;
let injected = false;
const unwrap = (result) => {
  if (!result.ok) throw result.error;
  return result.value;
};
const factory = (config, environment) => {
  const inner = createIdaMcpConnection(config, environment);
  const log = { index: report.connections.length, calls: [], closed: false };
  report.connections.push(log);
  return {
    ...inner,
    async call(name, args, options) {
      const result = await inner.call(name, args, options);
      const operation =
        name === "execute_python" ? result?.result?.operation : null;
      log.calls.push({ tool: name, operation });
      if (armed && !injected && operation === "assembly") {
        injected = true;
        await inner.close();
        log.closed = true;
        for (let wait = 0; !inner.ownedProcessExited?.() && wait < 100; wait++)
          await delay(10);
        assert(
          inner.ownedProcessExited?.(),
          "Owned MCP process exit must be observed before recovery",
        );
        log.confirmed_process_exit = true;
        throw new ProviderAdapterError("ida", "transport", {
          userMessage:
            "Controlled verification: owned MCP process exited after its read completed",
        });
      }
      return result;
    },
    async close() {
      await inner.close();
      log.closed = true;
    },
  };
};
const provider = new IdaProvider(
  { idaMcpConfigPath: configPath },
  process.env,
  factory,
);
const session = composeBinarySession(
  new AnalysisProviderRegistry([provider], "ida"),
);
const observe = async (operation, parameters) => {
  const execution = unwrap(await session.execute(operation, parameters));
  const evidence = createAnalysisExecutionEvidence(
    operation,
    parameters,
    execution,
    "observed",
  );
  unwrap(session.recordEvidence(evidence));
  report.evidence_ids.push(evidence.evidence_id);
  return execution;
};
try {
  unwrap(
    await session.open(fixture.path, {
      formatHint: "s-record",
      architecture: "rl78",
      providerId: "ida",
    }),
  );
  const before = await observe("procedure_assembly", {
    procedure: fixture.oracle.root,
  });
  assert.equal(report.connections.length, 1);
  const saved = session.exportEvidenceBundle();
  assert(
    saved.records.some((item) => item.evidence_id === report.evidence_ids[0]),
  );
  const savedBytes = JSON.stringify(saved);
  await mkdir(dirname(reportPath), { recursive: true });
  await writeFile(
    reportPath.replace(/\.json$/u, "-before-evidence.json"),
    savedBytes + "\n",
  );
  report.checks.push(
    "completed observation retained and exportable before fault",
  );
  armed = true;
  const after = await observe("procedure_assembly", {
    procedure: fixture.oracle.root,
  });
  assert(injected, "Real transport closure was injected");
  assert.equal(
    after.result,
    before.result,
    "Read result must survive verified recovery",
  );
  assert.equal(after.rawResult.recovery_events.length, 1);
  assert.equal(
    report.connections.length,
    3,
    "Old owner, discovery-only peer, and replacement analysis owner",
  );
  assert.deepEqual(
    report.connections[1].calls.map(({ tool }) => tool),
    ["list_databases"],
  );
  assert.equal(
    report.connections
      .flatMap(({ calls }) => calls)
      .filter(({ tool }) => tool === "open_database").length,
    2,
  );
  report.checks.push(
    "one verified release and reconnect; discovery peer never opens a database",
  );
  const bundle = session.exportEvidenceBundle();
  for (const evidenceId of report.evidence_ids)
    assert(
      bundle.records.some(({ evidence_id }) => evidence_id === evidenceId),
    );
  const beforeRecord = saved.records.find(
    ({ evidence_id }) => evidence_id === report.evidence_ids[0],
  );
  assert.deepEqual(
    bundle.records.find(
      ({ evidence_id }) => evidence_id === report.evidence_ids[0],
    ),
    beforeRecord,
  );
  await writeFile(
    reportPath.replace(/\.json$/u, "-after-evidence.json"),
    JSON.stringify(bundle) + "\n",
  );
  report.checks.push(
    "both completed observations exported; original evidence content unchanged",
  );
  unwrap(await session.close());
  assert(
    report.connections.every(({ closed }) => closed),
    "All owned transports closed",
  );
  assert.equal(
    createHash("sha256")
      .update(await readFile(fixture.path))
      .digest("hex"),
    fixture.oracle.sha256,
  );
  report.checks.push("verified final release and unchanged source carrier");
  report.passed = true;
} catch (error) {
  report.failure = {
    name: error.name,
    message: error.message,
    stack: error.stack,
  };
  process.exitCode = 1;
} finally {
  const closed = await session.close();
  if (!closed.ok) {
    report.cleanup_failure = closed.error.message;
    report.passed = false;
    process.exitCode = 1;
  }
  report.finished_at = new Date().toISOString();
  await mkdir(dirname(reportPath), { recursive: true });
  await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n");
  if (report.passed) await rm(directory, { recursive: true });
  console.log(
    JSON.stringify({
      passed: report.passed,
      checks: report.checks.length,
      connections: report.connections.length,
      report: reportPath,
    }),
  );
}
