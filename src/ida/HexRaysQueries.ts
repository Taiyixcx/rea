import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import {
  AnalysisOutputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import type { IdaMcpConnection } from "./IdaMcpConnection.js";

const queryPath = fileURLToPath(
  new URL("../../bridge/ida/rea_ida_queries.py", import.meta.url),
);
const source = (): string => readFileSync(queryPath, "utf8");
export const hexRaysQueryDigest = (): string =>
  createHash("sha256").update(source()).digest("hex");
export const loadHexRaysQueryBundle = () => {
  const text = source();
  return {
    source: text,
    sha256: createHash("sha256").update(text).digest("hex"),
  };
};

const envelopeSchema = z.object({
  version: z.literal(1),
  request_id: z.string(),
  operation: z.string(),
  status: z.enum(["ok", "unavailable", "missing", "error", "identity_error"]),
  result: jsonValueSchema,
  reason: z.string().nullable(),
});
export type HexRaysQueryReply = z.infer<typeof envelopeSchema>;
export interface HexRaysObservation {
  readonly tool: string;
  readonly arguments: Readonly<Record<string, JsonValue>>;
  readonly result: JsonValue;
}

/** Only this closed vocabulary is compiled into upstream Python requests. */
export type HexRaysQuery =
  | "metadata"
  | "attest"
  | "functions"
  | "strings"
  | "resolve"
  | "contains"
  | "xrefs"
  | "assembly"
  | "callees"
  | "pseudocode";

interface HexRaysQueryRequest {
  readonly connection: IdaMcpConnection;
  readonly instanceId: string;
  readonly operation: HexRaysQuery;
  readonly parameters: Readonly<Record<string, JsonValue>>;
  readonly timeoutMs: number;
  readonly observations: HexRaysObservation[];
  readonly bundle: ReturnType<typeof loadHexRaysQueryBundle>;
  readonly signal?: AbortSignal | undefined;
}

export const runHexRaysQuery = async ({
  connection,
  instanceId,
  operation,
  parameters,
  timeoutMs,
  observations,
  bundle,
  signal,
}: HexRaysQueryRequest): Promise<HexRaysQueryReply> => {
  const requestId = randomUUID();
  // Hexadecimal JSON data cannot terminate or inject a Python string literal.
  const request = { version: 1, request_id: requestId, operation, parameters };
  const payload = Buffer.from(JSON.stringify(request)).toString("hex");
  const code = `${bundle.source}\nimport json as _rea_json\nrea_query(_rea_json.loads(bytes.fromhex("${payload}").decode("utf-8")))`;
  const args = { code, instance_id: instanceId, timeout: timeoutMs / 1000 };
  const raw = await connection.call("execute_python", args, {
    timeoutMs,
    ...(signal === undefined ? {} : { signal }),
  });
  observations.push({
    tool: "execute_python",
    arguments: {
      instance_id: instanceId,
      timeout: timeoutMs / 1000,
      request_representation: "closed-query",
      query: request,
      implementation_sha256: bundle.sha256,
      code_sha256: createHash("sha256").update(code).digest("hex"),
    },
    result: raw,
  });
  const outer = z
    .object({ result: envelopeSchema, stdout: z.string(), stderr: z.string() })
    .parse(raw);
  const response = outer.result;
  if (response.operation !== operation || response.request_id !== requestId)
    throw new AnalysisProtocolError(
      "Official IDA query response does not match its request identity",
    );
  if (response.status === "identity_error")
    throw new AnalysisProtocolError(
      response.reason ?? "Official query identity changed",
    );
  if (response.status === "error")
    throw new AnalysisOutputError(
      operation,
      response.reason ?? "Official IDA query failed",
    );
  return response;
};
