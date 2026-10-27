import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createIdaTarget } from "../../tests/fixtures/idaMcp.js";
import { readIdaConfiguration } from "./IdaConfiguration.js";
import { decodeIdaToolResult } from "./IdaMcpConnection.js";

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});

describe("IDA registration and MCP result boundaries", () => {
  it("reuses a direct or upstream mcpServers registration with no installation", async () => {
    const { root } = await createIdaTarget();
    roots.push(root);
    const path = join(root, "mcp.json");
    for (const input of [
      { command: "python", args: ["server.py"] },
      {
        mcpServers: {
          "ida-pro-mcp": { command: "python", args: ["server.py"] },
          unrelated: { command: "untouched" },
        },
      },
    ]) {
      await writeFile(path, JSON.stringify(input));
      expect(readIdaConfiguration(path)).toMatchObject({
        ok: true,
        value: { command: "python", args: ["server.py"], mode: "attached" },
      });
    }
  });
  it("validates local transport and lifecycle inputs without leaking auth into a profile", async () => {
    const { root } = await createIdaTarget();
    roots.push(root);
    const path = join(root, "mcp.json");
    for (const input of [
      { url: "https://example.com/mcp" },
      { url: "http://token@127.0.0.1/mcp" },
      { command: "python", mode: "force_gui" },
      { command: "python", workspaceRoot: "relative" },
      { command: "python", args: "server.py" },
    ]) {
      await writeFile(path, JSON.stringify(input));
      expect(readIdaConfiguration(path).ok).toBe(false);
    }
    await writeFile(
      path,
      JSON.stringify({
        url: "http://127.0.0.1:8745/mcp",
        mode: "headless",
        headers: { Authorization: "Bearer fixture-secret" },
      }),
    );
    expect(readIdaConfiguration(path).ok).toBe(true);
    await writeFile(path, "malformed");
    expect(readIdaConfiguration(path).ok).toBe(false);
    expect(readIdaConfiguration(join(root, "absent")).ok).toBe(false);
  });
  it("parses FastMCP wrappers, structured dictionaries, text, arrays, and explicit errors", () => {
    expect(
      decodeIdaToolResult({
        content: [],
        structuredContent: { result: [{ address: "0x1" }] },
      }),
    ).toEqual([{ address: "0x1" }]);
    expect(
      decodeIdaToolResult({
        content: [],
        structuredContent: { address: "0x1", name: "f" },
      }),
    ).toEqual({ address: "0x1", name: "f" });
    expect(
      decodeIdaToolResult({ content: [{ type: "text", text: "int f() {}" }] }),
    ).toBe("int f() {}");
    expect(
      decodeIdaToolResult({ content: [{ type: "text", text: '{"data":[]}' }] }),
    ).toEqual({ data: [] });
    expect(() =>
      decodeIdaToolResult({
        content: [{ type: "text", text: "No function at 0x1" }],
        isError: true,
      }),
    ).toThrow("No function at 0x1");
    expect(() => decodeIdaToolResult({ content: "invalid" })).toThrow();
  });
});

it("accepts only an explicit headless stdio official profile without startup targets", async () => {
  const { root } = await createIdaTarget();
  roots.push(root);
  const path = join(root, "official.json");
  for (const selection of [
    {
      command: "ida-mcp",
      args: ["stdio"],
      mode: "headless",
      protocol: "hex-rays",
    },
    {
      command: "ida-mcp",
      args: ["stdio"],
      mode: "attached",
      protocol: "hex-rays",
    },
    {
      url: "http://127.0.0.1:8737/mcp",
      mode: "headless",
      protocol: "hex-rays",
    },
    {
      command: "ida-mcp",
      args: ["stdio", "--database", "/tmp/user.elf"],
      mode: "headless",
      protocol: "hex-rays",
    },
  ]) {
    await writeFile(path, JSON.stringify(selection));
    expect(readIdaConfiguration(path).ok).toBe(
      "command" in selection &&
        selection.mode === "headless" &&
        !selection.args?.includes("--database"),
    );
  }
});
