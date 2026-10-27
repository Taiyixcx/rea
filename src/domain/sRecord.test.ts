import { describe, expect, it } from "vitest";
import { parseSRecord, SRecordParser } from "./sRecord.js";

const record = (
  kind: number,
  address: number,
  data: readonly number[] = [],
) => {
  const width = (
    { 0: 2, 1: 2, 2: 3, 3: 4, 5: 2, 6: 3, 7: 4, 8: 3, 9: 2 } as Record<
      number,
      number
    >
  )[kind]!;
  const raw = Buffer.alloc(width);
  raw.writeUIntBE(address, 0, width);
  const body = [width + data.length + 1, ...raw, ...data];
  return `S${kind}${Buffer.from([...body, ~body.reduce((a, b) => a + b, 0) & 255]).toString("hex")}\n`;
};
describe("S-record admission", () => {
  it.each([
    [1, 9],
    [2, 8],
    [3, 7],
  ])("decodes S%i without mandatory count records", (kind, ending) => {
    const result = parseSRecord(
      Buffer.from(record(kind!, 0, [0, 17, 255]) + record(ending!, 0)),
    );
    expect(result.ok).toBe(true);
    if (result.ok)
      expect(result.value.summary).toMatchObject({
        data_bytes: 3,
        declared_start: "0x0",
        ranges: [{ start: "0x0", end: "0x3" }],
      });
  });
  it("preserves sparse, out-of-order, repeated source bytes and incremental coordinates", () => {
    const parser = new SRecordParser(0xfffff);
    const text =
      " \t" +
      record(2, 0x10000, [3, 4]).trim() +
      " \r\n" +
      record(2, 0x100, [1, 2]) +
      record(2, 0x101, [2]);
    for (const byte of Buffer.from(text)) parser.feed(Uint8Array.of(byte));
    const result = parser.finish();
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.ranges).toEqual([
        { start: 256, end: 258, dataHex: "0102" },
        { start: 65536, end: 65538, dataHex: "0304" },
      ]);
      expect(result.value.sources[0]).toMatchObject({ fileOffset: 2, line: 1 });
      expect(result.value.summary.declared_start).toBeNull();
    }
  });
  it.each([
    [record(1, 0, [1]).replace(/..\n$/u, "00\n"), "checksum"],
    [record(1, 0, [1]).slice(0, -3), "length"],
    [record(1, 0, [1]) + record(1, 0, [2]), "overlap"],
    [record(1, 0, [1]) + record(5, 2), "count"],
    [record(1, 0, [1]) + record(5, 1) + record(6, 1), "count"],
    [record(1, 0, [1]) + record(9, 0) + record(9, 1), "start"],
    [record(3, 0xffffffff, [1, 2]), "width"],
    ["S4030000fc\n", "unsupported"],
    ["", "no data"],
  ])("rejects malformed or ambiguous carrier %j", (text, reason) => {
    const result = parseSRecord(Buffer.from(text));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain(reason);
  });
  it("rejects RL78 overflow without truncating high bits", () => {
    const result = parseSRecord(Buffer.from(record(3, 0x100000, [1])), 0xfffff);
    expect(result.ok).toBe(false);
  });
  it("validates optional count and accepts the top RL78 address", () => {
    expect(
      parseSRecord(
        Buffer.from(
          record(2, 0xfffff, [1]) + record(6, 1) + record(8, 0xfffff),
        ),
        0xfffff,
      ).ok,
    ).toBe(true);
  });
});
