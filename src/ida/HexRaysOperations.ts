import { z } from "zod";
import {
  analysisSearchPredicate,
  analysisSearchQuerySchema,
} from "../domain/analysisSearch.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import {
  functionDossierSchema,
  functionInstructionWindowSchema,
} from "../domain/hopperValues.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import type { RelationshipCoverage } from "../domain/relationshipCoverage.js";
import {
  idaAddressSchema,
  idaFunctionSchema,
  type IdaFunction,
} from "./IdaProtocolValues.js";
import { combineFunctionRelationshipCoverage } from "../domain/functionCallCoverage.js";
import { IDA_LIMITATIONS } from "./IdaProviderCapabilities.js";
import type { HexRaysQuery, HexRaysQueryReply } from "./HexRaysQueries.js";

export type HexRaysRead = (
  operation: HexRaysQuery,
  parameters: Readonly<Record<string, JsonValue>>,
) => Promise<HexRaysQueryReply>;
const identity = (fn: IdaFunction) => ({
  address: fn.address,
  name: fn.name,
  classification: null,
  body: {
    available: false as const,
    reason: "IDA adapter does not expose complete function body ranges.",
  },
});
const pageSchema = z
  .object({
    items: z.array(jsonValueSchema),
    next_offset: z.number().int().nonnegative().nullable(),
    total: z.number().int().nonnegative(),
  })
  .passthrough();
const assemblyRow = z.object({
  address: idaAddressSchema,
  instruction: z.string(),
});
const stringRow = z.object({ address: idaAddressSchema, value: z.string() });
const callersUnavailable = {
  available: false as const,
  reason: "Direct callers remain unavailable in this compatibility profile.",
};
const calleeLimitation =
  "Callees cover recognized function destinations of explicit call references; unresolved indirect calls and other destinations remain unknown.";

/** Translate the existing IDA operation surface without adding analyst capabilities. */
export class HexRaysOperations {
  readonly limitations: string[] = [];
  relationshipCoverage: RelationshipCoverage | undefined;
  referencesTruncated: boolean | undefined;
  constructor(
    private readonly read: HexRaysRead,
    private readonly document: string,
    private readonly selectorOrigin?: "provider",
  ) {}

  private async pages(
    operation: HexRaysQuery,
    parameters: Readonly<Record<string, JsonValue>> = {},
    initial?: HexRaysQueryReply,
  ): Promise<JsonValue[]> {
    const items: JsonValue[] = [];
    let offset: number | null = 0;
    let total: number | undefined;
    while (offset !== null) {
      const response =
        initial ?? (await this.read(operation, { ...parameters, offset }));
      initial = undefined;
      if (response.status !== "ok")
        throw new AnalysisOutputError(
          operation,
          response.reason ?? "Query unavailable",
        );
      const page = pageSchema.parse(response.result);
      if (operation === "assembly") {
        const fn = idaFunctionSchema.parse(page.function);
        if (fn.address !== parameters.entry || fn.name !== parameters.name)
          throw new AnalysisProtocolError(
            "Official IDA assembly identifies a different function",
          );
      }
      if (
        (total !== undefined && page.total !== total) ||
        page.items.length > 100 ||
        offset + page.items.length > page.total ||
        (page.next_offset === null
          ? offset + page.items.length !== page.total
          : page.next_offset !== offset + page.items.length ||
            page.next_offset <= offset ||
            page.next_offset >= page.total)
      )
        throw new AnalysisProtocolError(
          "Official IDA pagination is inconsistent or did not advance",
        );
      total = page.total;
      items.push(...page.items);
      offset = page.next_offset;
    }
    return items;
  }

  private async resolve(query: string): Promise<IdaFunction> {
    const response = await this.read("resolve", { query });
    if (response.status === "missing" && this.selectorOrigin === "provider")
      throw new AnalysisProtocolError(
        "IDA could not resolve its own reported function",
      );
    if (response.status === "missing")
      throw new AnalysisInputError("resolve_procedure", {
        userMessage: response.reason ?? "Not a function",
      });
    if (response.status !== "ok")
      throw new AnalysisOutputError(
        "resolve_procedure",
        response.reason ?? "Lookup unavailable",
      );
    return idaFunctionSchema.parse(response.result);
  }

  private async assembly(fn: IdaFunction): Promise<string[]> {
    const rows = await this.pages("assembly", {
      entry: fn.address,
      name: fn.name,
    });
    return rows.map((row) => {
      const item = assemblyRow.parse(row);
      return `${item.address}: ${item.instruction}`;
    });
  }

  private async pseudocode(fn: IdaFunction): Promise<string | null> {
    const first = await this.read("pseudocode", {
      entry: fn.address,
      offset: 0,
    });
    if (first.status === "unavailable") {
      this.limitations.push(first.reason ?? "Pseudocode unavailable");
      return null;
    }
    if (first.status !== "ok")
      throw new AnalysisOutputError(
        "pseudocode",
        first.reason ?? "Pseudocode failed",
      );
    return z
      .array(z.string())
      .parse(await this.pages("pseudocode", { entry: fn.address }, first))
      .join("\n");
  }

  private async callees(
    fn: IdaFunction,
  ): Promise<ReturnType<typeof identity>[]> {
    const rows = await this.pages("callees", { entry: fn.address });
    this.limitations.push(calleeLimitation);
    this.relationshipCoverage = {
      status: "complete",
      diagnostics: [calleeLimitation],
    };
    return rows.map((row) => identity(idaFunctionSchema.parse(row)));
  }

  private async dossier(fn: IdaFunction): Promise<JsonValue> {
    const availability: Record<
      string,
      { available: true } | { available: false; reason: string }
    > = {};
    const facet = async <T>(
      name: string,
      execute: () => Promise<T>,
      empty: T,
    ): Promise<T> => {
      try {
        const result = await execute();
        availability[name] = { available: true };
        return result;
      } catch (cause) {
        // Malformed wire data, identity failures, cancellation and transport faults are never softened.
        if (!(cause instanceof AnalysisOutputError)) throw cause;
        const reason = `${name} query failed: ${cause.userMessage ?? cause.message}`;
        this.limitations.push(reason);
        availability[name] = { available: false, reason };
        return empty;
      }
    };
    const assembly = await facet("assembly", () => this.assembly(fn), []);
    const pseudocode = await facet(
      "pseudocode",
      () => this.pseudocode(fn),
      null,
    );
    if (pseudocode === null && availability.pseudocode?.available)
      availability.pseudocode = {
        available: false,
        reason: this.limitations.at(-1) ?? "Pseudocode unavailable",
      };
    const callees = await facet("callees", () => this.callees(fn), []);
    this.relationshipCoverage = combineFunctionRelationshipCoverage(
      { status: "unknown", reason: callersUnavailable.reason },
      this.relationshipCoverage ?? {
        status: "unknown",
        reason: "Callee query unavailable",
      },
    );
    const unavailable = (reason: string) => ({
      available: false as const,
      reason,
    });
    return functionDossierSchema.parse({
      procedure: { ...identity(fn), signature: null, locals: [] },
      pseudocode: pseudocode ?? "",
      assembly,
      comments: [],
      callers: [],
      callees,
      incoming_references: [],
      outgoing_references: [],
      referenced_strings: [],
      referenced_names: [],
      basic_blocks: [],
      native_api: null,
      native_value_flow: null,
      facet_availability: {
        ...availability,
        callers: callersUnavailable,
        comments: unavailable("Typed comments remain unavailable."),
        references: unavailable("Typed reference edges remain unavailable."),
        strings_names: unavailable(
          "Function-referenced strings and names remain unavailable.",
        ),
        cfg: unavailable("Basic blocks remain unavailable."),
      },
      limitations: [...IDA_LIMITATIONS, ...this.limitations],
    });
  }

  async run(
    operation: string,
    parameters: Readonly<Record<string, JsonValue>>,
  ): Promise<JsonValue> {
    const matches =
      operation === "search_procedures" || operation === "search_strings"
        ? analysisSearchPredicate(analysisSearchQuerySchema.parse(parameters))
        : undefined;
    if (operation === "list_documents") return [this.document];
    if (operation === "list_procedures" || operation === "search_procedures") {
      const rows = z
        .array(idaFunctionSchema)
        .parse(await this.pages("functions"));
      if (new Set(rows.map((fn) => fn.address)).size !== rows.length)
        throw new AnalysisProtocolError(
          "Official IDA function inventory contains duplicate entries",
        );
      const items = rows.map((fn) => ({ address: fn.address, value: fn.name }));
      return operation === "list_procedures"
        ? items
        : items.filter((item) => matches!(item.value));
    }
    if (operation === "list_strings" || operation === "search_strings") {
      const items = z.array(stringRow).parse(await this.pages("strings"));
      if (operation === "search_strings")
        return items.filter((item) => matches!(item.value));
      return parameters.address === undefined
        ? items
        : items.filter(
            (item) =>
              item.address === idaAddressSchema.parse(parameters.address),
          );
    }
    if (operation === "resolve_containing_procedure") {
      const address = idaAddressSchema.parse(parameters.address);
      const reply = await this.read("contains", { address });
      const value = z
        .object({
          function: idaFunctionSchema.nullable(),
          in_segment: z.boolean(),
        })
        .parse(reply.result);
      return value.function === null
        ? {
            query_address: address,
            found: false,
            procedure: null,
            reason: value.in_segment ? "not_in_procedure" : "outside_segments",
          }
        : {
            query_address: address,
            found: true,
            procedure: identity(value.function),
          };
    }
    if (operation === "xrefs") {
      const rows = await this.pages("xrefs", {
        address: idaAddressSchema.parse(parameters.address),
      });
      this.referencesTruncated = false;
      return rows.map(
        (row) => z.object({ address: idaAddressSchema }).parse(row).address,
      );
    }
    if (operation === "procedure_callers")
      throw new AnalysisCapabilityUnavailableError(
        "ida",
        operation,
        callersUnavailable.reason,
      );
    const fn = await this.resolve(z.string().parse(parameters.procedure));
    switch (operation) {
      case "procedure_address":
        return fn.address;
      case "procedure_assembly":
        return (await this.assembly(fn)).join("\n");
      case "procedure_pseudo_code":
        return this.pseudocode(fn);
      case "read_function_instructions":
        return functionInstructionWindowSchema.parse({
          procedure: identity(fn),
          instructions: await this.assembly(fn),
          limitations: IDA_LIMITATIONS,
        });
      case "procedure_callees":
        return (await this.callees(fn)).map((item) => item.address);
      case "analyze_function":
        return this.dossier(fn);
      default:
        throw new AnalysisCapabilityUnavailableError(
          "ida",
          operation,
          "Operation is outside the official IDA compatibility surface",
        );
    }
  }
}
