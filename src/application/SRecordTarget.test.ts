import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseBinaryTarget } from "./BinaryTargetResolver.js";
import { openBinaryInputSchema } from "../contracts/sessionLifecycleInputs.js";
import { toolContract } from "../contracts/toolContracts.js";
import { binaryTargetSummary } from "./binary/BinaryTargetSummary.js";
import { createEvidence, evidenceSchema } from "../domain/evidence.js";
import {
  snapshotMatchesTarget,
  snapshotTarget,
} from "../domain/analysisSnapshot.js";

describe("S-record target through public contracts and persistence", () => {
  it("admits the explicit RL78 interpretation and preserves file versus image identity", async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-srec-target-"));
    try {
      const path = join(directory, "firmware.s19");
      await writeFile(path, "S10501000011E8\nS9030000FC\n");
      const input = {
        path,
        format: "s-record" as const,
        architecture: "rl78" as const,
      };
      expect(openBinaryInputSchema.safeParse(input).success).toBe(true);
      const parsed = await parseBinaryTarget(path, {
        formatHint: "s-record",
        architecture: "rl78",
      });
      expect(parsed.ok).toBe(true);
      if (!parsed.ok || parsed.value.format !== "s-record") return;
      const target = parsed.value;
      expect(target.sRecord.summary).toMatchObject({
        declared_start: "0x0",
        data_bytes: 2,
      });
      expect(target.sRecord.ranges).toEqual([
        { start: 256, end: 258, dataHex: "0011" },
      ]);
      expect(() =>
        toolContract("open_binary").outputSchema.parse({
          result: binaryTargetSummary(target),
        }),
      ).not.toThrow();
      const evidence = createEvidence(
        target,
        { id: "ida", name: "IDA", version: "1" },
        { operation: "list_procedures", parameters: {}, result: [] },
      );
      expect(evidence.subject).toMatchObject({
        format: "s-record",
        architecture: "rl78",
      });
      expect(
        evidenceSchema.safeParse({
          ...evidence,
          subject: { ...evidence.subject, format: "elf" },
        }).success,
      ).toBe(false);
      const snapshot = snapshotTarget(target);
      expect(snapshotMatchesTarget(snapshot, target)).toBe(true);
      expect(
        snapshotMatchesTarget(snapshot, {
          ...target,
          sRecord: {
            ...target.sRecord,
            summary: {
              ...target.sRecord.summary,
              mapping_sha256: "0".repeat(64),
            },
          },
        }),
      ).toBe(false);
      expect(
        (await parseBinaryTarget(path, { formatHint: "s-record" })).ok,
      ).toBe(false);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
  it.each([
    { format: "raw-binary", architecture: "rl78", entry_point: "0x0" },
    { architecture: "rl78" },
    { format: "s-record", architecture: "arm" },
    { format: "s-record", architecture: "rl78", entry_point: "0x0" },
  ])(
    "rejects CPU/format combinations outside the explicit lane %j",
    (selection) => {
      expect(
        openBinaryInputSchema.safeParse({
          path: "/tmp/fixture.s19",
          ...selection,
        }).success,
      ).toBe(false);
    },
  );
});
