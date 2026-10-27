import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";

const width = { 0: 2, 1: 2, 2: 3, 3: 4, 5: 2, 6: 3, 7: 4, 8: 3, 9: 2 };
const record = (type, address, bytes = Buffer.alloc(0)) => {
  const encoded = Buffer.alloc(width[type]);
  encoded.writeUIntBE(address, 0, encoded.length);
  const values = [encoded.length + bytes.length + 1, ...encoded, ...bytes];
  return `S${type}${Buffer.from([
    ...values,
    ~values.reduce((sum, byte) => sum + byte, 0) & 255,
  ])
    .toString("hex")
    .toUpperCase()}`;
};

/** Semantic-free source program; numeric encodings independently checked against GNU's decoder. */
export const createRL78Fixture = async (directory) => {
  await mkdir(directory, { recursive: true });
  const string = "REA fixed query oracle";
  const regions = [
    { start: 0, bytes: Buffer.from("0001", "hex") },
    // CALL !0x120; MOV A,!0xF710 (near-data address 0xFF710); BZ $0x10B; NOP; BR $0x10C; NOP; RET.
    { start: 0x100, bytes: Buffer.from("fd20018f10f7dd0300ef0100d7", "hex") },
    { start: 0x120, bytes: Buffer.from("00d7", "hex") },
    { start: 0xff710, bytes: Buffer.from("01020304", "hex") },
    { start: 0x200, bytes: Buffer.from(string + "\0") },
    { start: 0x10000, bytes: Buffer.from("10325476", "hex") },
  ];
  const text =
    [
      record(0, 0, Buffer.from("REA-RL78-ORACLE")),
      ...regions.map((region) => record(2, region.start, region.bytes)),
      record(5, regions.length),
      record(8, 0x100),
    ].join("\n") + "\n";
  const path = join(directory, "rl78-oracle.s19");
  await writeFile(path, text, { flag: "wx" });
  return {
    path,
    oracle: {
      sha256: createHash("sha256").update(text).digest("hex"),
      root: "0x100",
      leaf: "0x120",
      direct_call_site: "0x100",
      data_reference_site: "0x103",
      data: "0xff710",
      string_address: "0x200",
      string,
      string_probe: "fixed query oracle",
      assembly_addresses: [
        "0x100",
        "0x103",
        "0x106",
        "0x108",
        "0x109",
        "0x10b",
        "0x10c",
      ],
      mnemonics: ["call", "mov", "bz", "nop", "br", "nop", "ret"],
      regions: regions.map((region) => ({
        start: `0x${region.start.toString(16)}`,
        hex: region.bytes.toString("hex"),
      })),
      addressing_source:
        "https://www.renesas.com/en/document/mah/rl78-family-users-manual-software-rev230#section-4.2.3",
      encoding_source:
        "https://gnu.googlesource.com/binutils-gdb/+/150bfae1d719a3b5c12edc780f0b360a1056b802/opcodes/rl78-decode.opc",
    },
  };
};
