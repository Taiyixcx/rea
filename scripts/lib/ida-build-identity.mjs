import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { readdir, readFile, realpath } from "node:fs/promises";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

const exec = promisify(execFile);
const sha = (value) => createHash("sha256").update(value).digest("hex");

/** Bind real-provider reports to the exact runtime, including fixed Python queries. */
export const idaBuildIdentity = async (root) => {
  const files = ["package.json", "scripts/rea.mjs"];
  const walk = async (relative) => {
    for (const entry of await readdir(join(root, relative), {
      withFileTypes: true,
    })) {
      const path = `${relative}/${entry.name}`;
      if (entry.isDirectory()) await walk(path);
      else if (entry.isFile()) files.push(path);
      else
        throw new Error(`Runtime identity refuses non-regular entry: ${path}`);
    }
  };
  for (const relative of ["dist", "bridge/ida", "skills"]) await walk(relative);
  const hashes = {};
  for (const file of files.sort())
    hashes[file] = sha(await readFile(join(root, file)));
  let commit = process.env.REA_BUILD_COMMIT ?? null;
  let dirty = null;
  try {
    const gitRoot = (
      await exec("git", ["rev-parse", "--show-toplevel"], { cwd: root })
    ).stdout.trim();
    if ((await realpath(gitRoot)) === (await realpath(resolve(root)))) {
      commit = (
        await exec("git", ["rev-parse", "HEAD"], { cwd: root })
      ).stdout.trim();
      dirty =
        (
          await exec("git", ["status", "--porcelain"], { cwd: root })
        ).stdout.trim() !== "";
    }
  } catch {
    /* An installed package has no source Git checkout. */
  }
  return {
    source_commit: commit,
    source_dirty: dirty,
    node_version: process.version,
    package_files_sha256: hashes,
    package_tree_sha256: sha(
      Object.entries(hashes)
        .map(([path, hash]) => `${path}\0${hash}\n`)
        .join(""),
    ),
  };
};
