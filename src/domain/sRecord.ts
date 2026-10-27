import { createHash } from "node:crypto";
import { z } from "zod";
import { err, ok, type Result } from "./result.js";

const digest = (bytes: Uint8Array | string): string =>
  createHash("sha256").update(bytes).digest("hex");
const hex = (value: number): string => `0x${value.toString(16)}`;
const widths: Readonly<Record<number, number>> = {
  0: 2,
  1: 2,
  2: 3,
  3: 4,
  5: 2,
  6: 3,
  7: 4,
  8: 3,
  9: 2,
};

export const sRecordSummarySchema = z.strictObject({
  parser_version: z.literal("1"),
  mapping_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  data_bytes: z.number().int().positive(),
  declared_start: z.string().nullable(),
  ranges: z
    .array(
      z.strictObject({
        start: z.string(),
        end: z.string(),
        sha256: z.string().regex(/^[a-f0-9]{64}$/u),
      }),
    )
    .min(1),
});
export type SRecordSummary = z.infer<typeof sRecordSummarySchema>;

/** Carrier coordinates are byte offsets in the ASCII file, never memory offsets. */
export interface SRecordSource {
  readonly type: number;
  readonly line: number;
  readonly fileOffset: number;
  readonly fileEnd: number;
  readonly address: string;
  readonly dataBytes: number;
}
export interface SRecordImage {
  readonly summary: SRecordSummary;
  readonly ranges: readonly {
    readonly start: number;
    readonly end: number;
    readonly dataHex: string;
  }[];
  readonly sources: readonly SRecordSource[];
}

/** Incremental, single-block S-record decoder; sparse addresses never allocate a flat image. */
export class SRecordParser {
  private readonly bytes = new Map<number, number>();
  private readonly sources: SRecordSource[] = [];
  private line = "";
  private lineNumber = 1;
  private offset = 0;
  private lineStart = 0;
  private trailingSpace = false;
  private failure: string | undefined;
  private dataRecords = 0;
  private count: number | undefined;
  private start: number | null = null;
  private terminated = false;
  private header = false;

  constructor(private readonly maxAddress = 0xffffffff) {}

  feed(chunk: Uint8Array): void {
    for (const byte of chunk) {
      if (this.failure !== undefined) return;
      if (byte === 10) {
        this.consumeLine();
        this.lineNumber++;
        this.line = "";
        this.trailingSpace = false;
        this.lineStart = this.offset + 1;
      } else if (byte === 32 || byte === 9 || byte === 13) {
        if (this.line.length === 0) this.lineStart = this.offset + 1;
        else this.trailingSpace = true;
      } else if (byte > 127 || this.trailingSpace) {
        this.reject("non-ASCII or whitespace inside a record");
      } else if (this.line.length >= 514) {
        this.reject("record exceeds its one-byte length field");
      } else this.line += String.fromCharCode(byte);
      this.offset++;
    }
  }

  private reject(reason: string): void {
    this.failure ??= `S-record line ${this.lineNumber}: ${reason}`;
  }

  private consumeLine(): void {
    if (this.line.length === 0 || this.failure !== undefined) return;
    const match = /^S([0-9])([0-9A-Fa-f]+)$/u.exec(this.line);
    if (match === null || (match[2]?.length ?? 1) % 2 !== 0) {
      this.reject("invalid record syntax");
      return;
    }
    const type = Number(match[1]);
    const width = widths[type];
    if (width === undefined) {
      this.reject("unsupported record type");
      return;
    }
    const raw = Buffer.from(match[2]!, "hex");
    if (raw[0] !== raw.length - 1 || raw.length < width + 2) {
      this.reject("record length mismatch");
      return;
    }
    if (raw.reduce((sum, byte) => sum + byte, 0) % 256 !== 255) {
      this.reject("checksum mismatch");
      return;
    }
    const address = raw.readUIntBE(1, width);
    const data = raw.subarray(width + 1, -1);
    this.sources.push({
      type,
      line: this.lineNumber,
      fileOffset: this.lineStart,
      fileEnd: this.lineStart + this.line.length,
      address: hex(address),
      dataBytes: data.length,
    });
    if (type === 0) {
      if (this.header || this.dataRecords > 0 || this.terminated)
        this.reject("multiple blocks are unsupported");
      this.header = true;
    } else if (type >= 1 && type <= 3) {
      if (this.terminated || this.count !== undefined) {
        this.reject("data after count or termination");
        return;
      }
      const end = address + data.length;
      if (
        end > 0x100000000 ||
        address > this.maxAddress ||
        end > this.maxAddress + 1
      ) {
        this.reject("data address exceeds selected architecture width");
        return;
      }
      this.dataRecords++;
      for (const [index, byte] of data.entries()) {
        const at = address + index;
        const previous = this.bytes.get(at);
        if (previous !== undefined && previous !== byte) {
          this.reject(`conflicting overlap at ${hex(at)}`);
          return;
        }
        this.bytes.set(at, byte);
      }
    } else if (type === 5 || type === 6) {
      if (data.length !== 0 || this.count !== undefined || this.terminated)
        this.reject("ambiguous or malformed count record");
      this.count = address;
    } else {
      if (data.length !== 0 || address > this.maxAddress)
        this.reject("invalid termination address or payload");
      if (this.terminated && this.start !== address)
        this.reject("conflicting start declarations");
      this.start = address;
      this.terminated = true;
    }
  }

  finish(): Result<SRecordImage, string> {
    this.consumeLine();
    if (this.failure !== undefined) return err(this.failure);
    if (this.bytes.size === 0) return err("S-record contains no data bytes");
    if (this.count !== undefined && this.count !== this.dataRecords)
      return err("S-record data-record count mismatch");
    const ranges: { start: number; end: number; dataHex: string }[] = [];
    let start = -1;
    let previous = -2;
    let data: number[] = [];
    const flush = () => {
      if (data.length > 0)
        ranges.push({
          start,
          end: previous + 1,
          dataHex: Buffer.from(data).toString("hex"),
        });
      data = [];
    };
    for (const address of [...this.bytes.keys()].sort((a, b) => a - b)) {
      if (address !== previous + 1) {
        flush();
        start = address;
      }
      data.push(this.bytes.get(address)!);
      previous = address;
    }
    flush();
    const summaries = ranges.map((range) => ({
      start: hex(range.start),
      end: hex(range.end),
      sha256: digest(Buffer.from(range.dataHex, "hex")),
    }));
    return ok({
      summary: {
        parser_version: "1",
        mapping_sha256: digest(JSON.stringify(summaries)),
        data_bytes: this.bytes.size,
        declared_start: this.start === null ? null : hex(this.start),
        ranges: summaries,
      },
      ranges,
      sources: this.sources,
    });
  }
}

/** Pure convenience decoder for format tests and in-memory callers. */
export const parseSRecord = (
  bytes: Uint8Array,
  maxAddress = 0xffffffff,
): Result<SRecordImage, string> => {
  const parser = new SRecordParser(maxAddress);
  parser.feed(bytes);
  return parser.finish();
};
