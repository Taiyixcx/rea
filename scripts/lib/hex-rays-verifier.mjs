import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFile,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { idaBuildIdentity } from "./ida-build-identity.mjs";
import { createRL78Fixture } from "./rl78-fixture.mjs";

const exec = promisify(execFile);
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const decode = (response) => {
  if (response.isError) throw new Error(JSON.stringify(response));
  if (response.structuredContent !== undefined)
    return response.structuredContent;
  const text = response.content.filter((block) => block.type === "text");
  assert.equal(text.length, 1);
  return JSON.parse(text[0].text);
};
const evidence = (value) => {
  assert.equal(value.provider.id, "ida");
  assert.equal(value.provider.version, "2");
  return value.normalized_result;
};
const mnemonic = (line) =>
  line
    .replace(/^0x[0-9a-f]+:\s*/u, "")
    .trim()
    .split(/\s/u)[0]
    .toLowerCase();

/** Read-only direct control: different enumeration/query implementation from the packaged bridge. */
const controlCode = (entries, dataAddress) => {
  const payload = Buffer.from(
    JSON.stringify({ entries, data: dataAddress }),
  ).toString("hex");
  return `import json, ida_auto, ida_bytes, ida_funcs, ida_idp, ida_lines, ida_nalt, ida_ua, ida_xref, idautils\nida_auto.auto_wait()\ndef run(db):\n    args=json.loads(bytes.fromhex("${payload}").decode())\n    result={'functions':[hex(ea) for ea in idautils.Functions()], 'dossiers':{}, 'strings':[{'address':hex(s.ea),'value':str(s)} for s in idautils.Strings()]}\n    for entry in args['entries']:\n        at=int(entry,16)\n        assembly=[]\n        callees=set()\n        for start,end in idautils.Chunks(at):\n            ea=start\n            while ea<end:\n                if ida_bytes.is_code(ida_bytes.get_full_flags(ea)):\n                    assembly.append(hex(ea)+': '+ida_lines.tag_remove(ida_lines.generate_disasm_line(ea,0)))\n                    instruction=ida_ua.insn_t()\n                    if ida_ua.decode_insn(instruction,ea) and instruction.get_canon_feature() & ida_idp.CF_CALL:\n                        for target in idautils.CodeRefsFrom(ea,False):\n                            fn=ida_funcs.get_func(target)\n                            if fn is not None: callees.add(hex(fn.start_ea))\n                ea=ida_bytes.next_head(ea,end)\n        result['dossiers'][entry]={'assembly':assembly,'callees':sorted(callees,key=lambda v:int(v,16))}\n    result['xrefs']={}\n    for target in [*args['entries'],args['data']]:\n        if target is None: continue\n        block=ida_xref.xrefblk_t()\n        found=block.first_to(int(target,16),0)\n        refs=[]\n        while found:\n            refs.append((block.frm,block.type))\n            found=block.next_to()\n        result['xrefs'][target]=[hex(ea) for ea,kind in sorted(set(refs))]\n    return result\nrun(db)`;
};

const directControl = async (
  config,
  target,
  entries,
  dataAddress,
  directory,
  events,
) => {
  await mkdir(directory, { recursive: true });
  const input = join(directory, "control.s19");
  await copyFile(target, input);
  const client = new Client({
    name: "rea-independent-ida-control",
    version: "1",
  });
  const transport = new StdioClientTransport({
    command: config.command,
    args: config.args,
    stderr: "pipe",
    env: {
      HOME: process.env.HOME ?? "",
      PATH: process.env.PATH ?? "",
      ...config.env,
      IDA_NEXUS_IDALIB_ONLY: "1",
      IDA_NEXUS_STATE_DIR: join(directory, "nexus"),
      IDA_MCP_STATE_DIR: join(directory, "mcp"),
    },
  });
  let instance;
  const call = async (name, args) => {
    const response = await client.callTool(
      { name, arguments: args },
      { timeout: config.timeoutMs },
    );
    events.push({ name, arguments: args, response });
    return name === "reference" ? response : decode(response);
  };
  try {
    await client.connect(transport, { timeout: config.timeoutMs });
    transport.stderr?.on("data", () => {});
    await call("reference", {
      query:
        "function chunks, instruction canonical features, code references, string list",
    });
    const opened = await call("open_database", {
      path: input,
      set_current: false,
      load_options: { processor: "rl78" },
    });
    assert.equal(opened.backend, "idalib");
    instance = opened.instance_id;
    const result = await call("execute_python", {
      code: controlCode(entries, dataAddress),
      instance_id: instance,
      timeout: config.timeoutMs / 1000,
    });
    assert.equal(result.stderr, "");
    assert(result.result && result.result.dossiers, JSON.stringify(result));
    await call("close_database", { instance_id: instance });
    const released = instance;
    instance = undefined;
    const inventory = await call("list_databases", {});
    assert(
      !inventory.instances.some(
        (item) =>
          item.instance_id === released ||
          resolve(item.path).startsWith(resolve(directory) + "/"),
      ),
      "direct-control lease/path remains registered",
    );
    return result.result;
  } finally {
    try {
      if (instance !== undefined)
        await call("close_database", { instance_id: instance });
    } finally {
      await client.close();
    }
  }
};

/** Best-effort Linux descendant accounting; missing process facts remain unavailable. */
const resourceSample = async (rootPid) => {
  if (process.platform !== "linux" || rootPid === null)
    return { available: false };
  const rows = [];
  for (const name of await readdir("/proc")) {
    if (!/^\d+$/u.test(name)) continue;
    try {
      const stat = await readFile(`/proc/${name}/stat`, "utf8");
      const tail = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
      const status = await readFile(`/proc/${name}/status`, "utf8");
      rows.push({
        pid: Number(name),
        parent: Number(tail[1]),
        ticks: Number(tail[11]) + Number(tail[12]),
        rss_kib: Number(/VmRSS:\s+(\d+)/u.exec(status)?.[1] ?? 0),
      });
    } catch {
      /* Process exited between the two observations. */
    }
  }
  const selected = new Set([rootPid]);
  for (let changed = true; changed;) {
    changed = false;
    for (const row of rows)
      if (selected.has(row.parent) && !selected.has(row.pid)) {
        selected.add(row.pid);
        changed = true;
      }
  }
  const family = rows.filter((row) => selected.has(row.pid));
  return {
    available: family.length > 0,
    process_count: family.length,
    rss_kib: family.reduce((sum, row) => sum + row.rss_kib, 0),
    observed_cpu_ticks: family.reduce((sum, row) => sum + row.ticks, 0),
    scope:
      "observed descendants of the REA MCP process; detached/reparented peers may be absent",
  };
};

export const verifyHexRaysIda = async ({
  packageRoot,
  config,
  environment,
  values,
}) => {
  assert.equal(config.protocol, "hex-rays");
  assert.equal(config.mode, "headless");
  assert.equal(typeof config.command, "string");
  const duration = Number(values["duration-seconds"] ?? 0);
  assert(Number.isFinite(duration) && duration >= 0);
  const directory = await mkdtemp(
    join(tmpdir(), "rea-hex-rays-qualification-"),
  );
  const output =
    values.report === undefined ? directory : dirname(resolve(values.report));
  await mkdir(output, { recursive: true });
  const reportPath = resolve(values.report ?? join(directory, "report.json"));
  const eventPath = reportPath.replace(/\.json$/u, "") + "-events.jsonl";
  const bundlePath = reportPath.replace(/\.json$/u, "") + "-evidence.json";
  const report = {
    passed: false,
    build_identity: await idaBuildIdentity(packageRoot),
    started_at: new Date().toISOString(),
    protocol: "hex-rays",
    platform: process.platform,
    duration_requested_seconds: duration,
    checks: [],
    observations: {},
    counters: { requests: 0, expected_errors: 0, functions: 0, checkpoints: 0 },
    resources: { samples: [], peak_rss_kib: 0 },
    unverified: [
      "Other operating systems and IDA releases",
      "Original target execution and dynamic semantics",
    ],
  };
  const entry = join(packageRoot, "scripts/rea.mjs");
  const client = new Client({
    name: "rea-real-hex-rays-verifier",
    version: "1",
  });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entry, "mcp"],
    env: environment,
    stderr: "pipe",
  });
  let opened = false;
  let target;
  let original;
  let fixture;
  const retained = new Set();
  const call = async (name, args = {}, expectError = false) => {
    const started = performance.now();
    const response = await client.callTool(
      { name, arguments: args },
      { timeout: config.timeoutMs },
    );
    report.counters.requests++;
    await appendFile(
      eventPath,
      JSON.stringify({
        name,
        arguments: args,
        elapsed_ms: performance.now() - started,
        response,
      }) + "\n",
    );
    if (expectError) {
      assert.equal(response.isError, true, `expected ${name} to fail`);
      report.counters.expected_errors++;
      return response;
    }
    const result = decode(response);
    if (result.evidence_id) retained.add(result.evidence_id);
    return result;
  };
  const checkDossier = (response) => {
    const value = evidence(response);
    assert(Array.isArray(value.assembly));
    assert.equal(value.procedure.body.available, false);
    assert.equal(value.facet_availability.cfg.available, false);
    assert(
      !value.limitations.some((reason) => /query failed:/u.test(reason)),
      JSON.stringify(value.limitations),
    );
    const expectation = values["pseudocode-expectation"] ?? "unavailable";
    if (expectation === "unavailable") {
      assert.equal(value.pseudocode, "");
      assert.equal(value.facet_availability.pseudocode.available, false);
      assert(value.facet_availability.pseudocode.reason);
    } else if (expectation === "available") {
      assert(value.pseudocode.length > 0);
      assert.equal(value.facet_availability.pseudocode.available, true);
    } else assert.equal(expectation, "either");
    return value;
  };
  const checkpoint = async () => {
    await call("export_evidence_bundle", { path: bundlePath, overwrite: true });
    report.counters.checkpoints++;
    const bundle = JSON.parse(await readFile(bundlePath, "utf8"));
    const ids = new Set(bundle.records.map((record) => record.evidence_id));
    for (const id of retained)
      assert(ids.has(id), "completed Evidence is missing from exported bundle");
  };
  try {
    if (values.fixture) {
      fixture = await createRL78Fixture(join(directory, "fixture"));
      target = fixture.path;
      report.observations.fixture_oracle = fixture.oracle;
      if (output !== directory)
        await copyFile(
          target,
          reportPath.replace(/\.json$/u, "") + "-fixture.s19",
        );
    } else {
      assert(values.target);
      target = resolve(values.target);
    }
    original = sha(await readFile(target));
    const format = values["target-format"] ?? "s-record",
      architecture = values.architecture ?? "rl78";
    assert.equal(format, "s-record");
    assert.equal(architecture, "rl78");
    await client.connect(transport, { timeout: config.timeoutMs });
    transport.stderr?.on("data", () => {});
    const openedResult = await call("open_binary", {
      path: target,
      format,
      architecture,
      provider_id: "ida",
    });
    opened = true;
    assert.equal(openedResult.result.sha256, original);
    assert.equal(openedResult.result.architecture, "rl78");
    report.checks.push("explicit target admission and original carrier digest");
    const inventory = evidence(await call("list_procedures"));
    assert(inventory.length > 0);
    assert.equal(
      new Set(inventory.map((fn) => fn.address)).size,
      inventory.length,
    );
    report.observations.function_count = inventory.length;
    const selected =
      fixture?.oracle.root ?? values.procedure ?? inventory[0].address;
    const initial = checkDossier(
      await call("analyze_function", { procedure: selected }),
    );
    assert(initial.assembly.length > 0);
    report.observations.kernel_version = (
      await call("procedure_address", { procedure: selected })
    ).raw_result.metadata_before.kernel_version;
    assert.equal(report.observations.kernel_version, "9.5");
    const cliArgs = [
      entry,
      "function",
      target,
      selected,
      "--provider",
      "ida",
      "--target-format",
      format,
      "--architecture",
      architecture,
      "--json",
    ];
    const cli = await exec(process.execPath, cliArgs, {
      env: environment,
      timeout: config.timeoutMs,
      maxBuffer: 32 * 1024 * 1024,
    });
    const cliEvidence = JSON.parse(cli.stdout);
    const cliDossier = checkDossier(cliEvidence);
    assert.deepEqual(cliDossier.procedure, initial.procedure);
    assert.deepEqual(cliDossier.assembly, initial.assembly);
    assert.deepEqual(cliDossier.callees, initial.callees);
    report.checks.push("real CLI/MCP parity including unavailable pseudocode");
    const controlEvents = [];
    const entries = fixture
      ? [fixture.oracle.root, fixture.oracle.leaf]
      : [selected];
    const control = await directControl(
      config,
      target,
      entries,
      fixture?.oracle.data ?? null,
      join(directory, "control"),
      controlEvents,
    );
    await writeFile(
      reportPath.replace(/\.json$/u, "") + "-control.json",
      JSON.stringify(controlEvents, null, 2) + "\n",
    );
    assert.deepEqual(
      inventory.map((fn) => fn.address),
      control.functions,
    );
    for (const address of entries) {
      const dossier =
        address === selected
          ? initial
          : checkDossier(
              await call("analyze_function", { procedure: address }),
            );
      assert.deepEqual(dossier.assembly, control.dossiers[address].assembly);
      assert.deepEqual(
        dossier.callees.map((fn) => fn.address),
        control.dossiers[address].callees,
      );
      assert.deepEqual(
        evidence(await call("xrefs", { address })),
        control.xrefs[address],
      );
    }
    assert.deepEqual(evidence(await call("list_strings")), control.strings);
    report.checks.push(
      "independent direct-official-IDA control agrees on functions, assembly, strings, references and callees",
    );
    if (fixture) {
      const oracle = fixture.oracle;
      for (const address of entries)
        assert(control.functions.includes(address));
      assert.deepEqual(
        initial.assembly.map((line) => line.split(":")[0]),
        oracle.assembly_addresses,
      );
      assert.deepEqual(initial.assembly.map(mnemonic), oracle.mnemonics);
      assert.deepEqual(
        initial.callees.map((fn) => fn.address),
        [oracle.leaf],
      );
      assert(control.xrefs[oracle.leaf].includes(oracle.direct_call_site));
      assert(control.xrefs[oracle.data].includes(oracle.data_reference_site));
      const strings = evidence(
        await call("search_strings", { pattern: oracle.string_probe }),
      );
      assert(strings.length > 0, "the source string probe was not found");
      for (const item of strings) {
        const offset = Number(
          BigInt(item.address) - BigInt(oracle.string_address),
        );
        assert(
          offset >= 0 && offset < oracle.string.length,
          "string address lies outside its source bytes",
        );
        assert.equal(
          item.value,
          oracle.string.slice(offset),
          "returned string bytes do not match the independent source address",
        );
        assert.notEqual(
          item.value,
          oracle.string.slice(offset + 1),
          "negative address-shift oracle control",
        );
      }
      assert.deepEqual(
        evidence(await call("xrefs", { address: oracle.data })),
        control.xrefs[oracle.data],
      );
      report.checks.push(
        "independent RL78 source oracle: instruction boundaries, call/branch encodings, data xref and string address",
      );
    }
    const functions =
      values["all-functions"] || fixture ? inventory : [{ address: selected }];
    for (const fn of functions) {
      checkDossier(await call("analyze_function", { procedure: fn.address }));
      report.counters.functions++;
      if (report.counters.functions % 20 === 0) await checkpoint();
    }
    report.checks.push(
      "every selected discovered function yields a validated dossier with explicit unavailable facets",
    );
    await call(
      "procedure_address",
      { procedure: "__rea_nonexistent_qualification_symbol__" },
      true,
    );
    await call("search_strings", { pattern: "[", mode: "regex" }, true);
    checkDossier(await call("analyze_function", { procedure: selected }));
    report.checks.push(
      "expected invalid queries do not poison subsequent analysis",
    );
    const began = performance.now();
    let cycle = 0;
    while (performance.now() - began < duration * 1000) {
      const fn = inventory[cycle % inventory.length];
      checkDossier(await call("analyze_function", { procedure: fn.address }));
      report.counters.functions++;
      cycle++;
      if (cycle % 20 === 0) await checkpoint();
      if (cycle % 30 === 0) {
        const sample = {
          elapsed_seconds: (performance.now() - began) / 1000,
          ...(await resourceSample(transport.pid)),
        };
        report.resources.samples.push(sample);
        report.resources.peak_rss_kib = Math.max(
          report.resources.peak_rss_kib,
          sample.rss_kib ?? 0,
        );
        console.log(
          JSON.stringify({
            phase: "soak",
            elapsed_seconds: sample.elapsed_seconds,
            requests: report.counters.requests,
            cycles: cycle,
            rss_kib: sample.rss_kib,
          }),
        );
        await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n");
      }
      if (cycle % 100 === 0) {
        await call(
          "procedure_address",
          { procedure: "__rea_nonexistent_qualification_symbol__" },
          true,
        );
        checkDossier(await call("analyze_function", { procedure: selected }));
      }
      await delay(
        Math.min(
          2000,
          Math.max(0, duration * 1000 - (performance.now() - began)),
        ),
      );
    }
    report.observations.soak_elapsed_seconds =
      (performance.now() - began) / 1000;
    if (duration > 0) {
      assert(report.observations.soak_elapsed_seconds >= duration);
      report.checks.push(
        "requested wall-clock soak completed without unclassified failures",
      );
    }
    await checkpoint();
    const metadata = await call("binary_session", {});
    assert(metadata.result.open);
    await call("close_binary");
    opened = false;
    assert.equal(sha(await readFile(target)), original);
    report.checks.push(
      "complete Evidence checkpoint export, verified close and unchanged source",
    );
    report.passed = true;
  } catch (error) {
    report.failure = { message: error.message, stack: error.stack };
    throw error;
  } finally {
    if (opened) {
      try {
        await call("export_evidence_bundle", {
          path: bundlePath,
          overwrite: true,
        });
        await call("close_binary");
        opened = false;
      } catch (error) {
        report.cleanup_failure = error.message;
      }
    }
    try {
      await client.close();
    } catch (error) {
      report.cleanup_failure = error.message;
      report.passed = false;
    }
    report.finished_at = new Date().toISOString();
    report.observations.workspace = directory;
    report.observations.event_log = eventPath;
    report.observations.evidence_bundle = bundlePath;
    await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n");
    if (report.passed && output !== directory)
      await rm(directory, { recursive: true, force: true });
    console.log(
      JSON.stringify({
        passed: report.passed,
        checks: report.checks.length,
        functions: report.counters.functions,
        requests: report.counters.requests,
        report: reportPath,
      }),
    );
    if (!report.passed && !report.failure)
      throw new Error(
        report.cleanup_failure ?? "qualification did not complete",
      );
  }
};
