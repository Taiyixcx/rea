#!/usr/bin/env python3
"""Audit a software archive without extracting it or reading an analysis target."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def audit(archive):
    pins = json.loads((ROOT / "deployment/software-pins.json").read_text())
    directories = {"dist", "bridge", "scripts", "skills", "licenses", "third_party", "native"}
    files = {"package.json", "README.md", "LICENSE", "DISCLAIMER.md", "THIRD_PARTY_NOTICES.md", "install.sh"}
    prohibited = {".git", "development", "logs", "runtime", "qualification", "manifests"}
    suffixes = {".s19", ".s28", ".s37", ".srec", ".i64", ".idb", ".id0", ".id1", ".hexlic"}
    hashes = {}
    seen = set()
    count = 0
    with tarfile.open(archive, "r:gz") as packed:
        for member in packed:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "package":
                raise ValueError(f"Unexpected archive path: {member.name}")
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError(f"Non-regular archive member: {member.name}")
            relative = path.relative_to("package")
            name = relative.as_posix()
            if name in seen:
                raise ValueError(f"Duplicate archive member: {name}")
            seen.add(name)
            if any(part in prohibited for part in relative.parts) or relative.suffix.lower() in suffixes:
                raise ValueError(f"Development/target artifact is forbidden: {name}")
            if relative.parts[0] not in directories and name not in files:
                raise ValueError(f"Member outside the software allowlist: {name}")
            count += 1
            if name in {"package.json", "scripts/rea.mjs"} or name.startswith(("dist/", "bridge/ida/", "skills/")):
                h = hashlib.sha256()
                with packed.extractfile(member) as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        h.update(block)
                hashes[name] = h.hexdigest()
    canonical = "".join(f"{name}\0{hashes[name]}\n" for name in sorted(hashes))
    core = hashlib.sha256(canonical.encode()).hexdigest()
    if core != pins["runtime_tree_sha256"]:
        raise ValueError("Archive runtime differs from the pinned software core; do not replace expected hashes")
    return {"passed": True, "scope": "software core identity and archive structure; not host or experiment isolation",
            "files": count, "runtime_tree_sha256": core}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(audit(args.archive)))
    except (OSError, ValueError, tarfile.TarError) as error:
        raise SystemExit(f"Archive refused: {error}") from error
