#!/usr/bin/env python3
"""Check pinned software and propose host-local MCP configurations; never analyze a target."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def absolute(value):
    # Preserve the venv executable spelling: resolving its symlink loses the venv.
    return Path(os.path.abspath(Path(value).expanduser()))


def executable(value):
    path = absolute(value)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError(f"Not an executable: {path}")
    return path


def run(arguments, cwd=None, env=None):
    return subprocess.check_output(arguments, cwd=cwd, env=env, text=True).strip()


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def inspect(args):
    pins = json.loads((ROOT / "deployment/software-pins.json").read_text())
    require(sys.platform == "linux" and platform.machine() in ("x86_64", "amd64"),
            "This deployment lane is Linux x86_64 only")
    node, npm, python = map(executable, (args.node, args.npm, args.python))
    ida = absolute(args.ida_dir)
    for relative in ("libida.so", "libidalib.so", "procs/rl78.so"):
        require((ida / relative).is_file(), f"Missing IDA component: {relative}")
    require(run([str(node), "--version"]) == pins["node_version"], "Wrong Node version")
    environment = dict(os.environ, PATH=f"{node.parent}:{os.environ.get('PATH', '')}")
    require(run([str(npm), "--version"], env=environment) == pins["npm_version"], "Wrong npm version")
    code = "import sys,importlib.metadata as m,json; print(json.dumps({'version':'.'.join(map(str,sys.version_info[:3])),'packages':{d.metadata['Name'].lower().replace('_','-'):d.version for d in m.distributions()}}))"
    info = json.loads(run([str(python), "-c", code]))
    require(info["version"] == pins["python_version"], "Wrong Python version")
    packages = dict(pins["python_packages"])
    for line in (ROOT / "deployment/requirements-ida.txt").read_text().splitlines():
        if line and not line.startswith("#"):
            name, version = line.split("==", 1)
            packages[name.lower().replace("_", "-")] = version
    for name, version in packages.items():
        require(info["packages"].get(name) == version, f"Python package pin differs: {name}")
    ida_mcp = executable(python.parent / "ida-mcp")
    shebang = ida_mcp.read_text().splitlines()[0]
    require(shebang.startswith("#!") and absolute(shebang[2:]).parent == python.parent,
            "IDA MCP entrypoint does not belong to this venv; rebuild it instead of relocating a venv")
    require(not run(["git", "status", "--porcelain"], cwd=ROOT),
            "Source checkout is dirty; preserve changes and use a clean deployment checkout")
    commit = run(["git", "rev-parse", "HEAD"], cwd=ROOT)
    helper = (ROOT / "scripts/lib/ida-build-identity.mjs").as_uri()
    code = "const m=await import(process.argv[1]); console.log(JSON.stringify(await m.idaBuildIdentity(process.argv[2])))"
    identity = json.loads(run([str(node), "--input-type=module", "-e", code, helper, str(ROOT)]))
    require(identity["package_tree_sha256"] == pins["runtime_tree_sha256"],
            "Built runtime differs from the pinned core; rebuild with the pinned toolchain, do not edit hashes")
    require(identity["package_files_sha256"]["bridge/ida/rea_ida_queries.py"] == pins["query_sha256"], "Query digest mismatch")
    require(identity["package_files_sha256"]["skills/reverse-engineer-anything/SKILL.md"] == pins["skill_sha256"], "Skill digest mismatch")
    return {"state": "configured-not-verified", "source_root": str(ROOT), "source_commit": commit,
            "analysis_core_reference": pins["analysis_core_reference"], "node": str(node),
            "npm": str(npm), "python": str(python), "ida_dir": str(ida),
            "ida_mcp": str(ida_mcp), "ida_kernel_version": "not-probed",
            "runtime_tree_sha256": identity["package_tree_sha256"],
            "software_files_sha256": {str(p): digest(p) for p in
                (node, python, ida_mcp, ida / "libida.so", ida / "libidalib.so", ida / "procs/rl78.so")},
            "required_python_packages": packages}


def toml_server(name, command, arguments, environment):
    quote = lambda value: json.dumps(value, ensure_ascii=False)
    text = f"[mcp_servers.{name}]\ncommand = {quote(command)}\nargs = {quote(arguments)}\nstartup_timeout_sec = 60\ntool_timeout_sec = 300\n\n[mcp_servers.{name}.env]\n"
    return text + "".join(f"{key} = {quote(value)}\n" for key, value in environment.items())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("node", "npm", "python", "ida-dir"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--output", type=absolute,
                        default=Path.home() / ".local/share/rea-rl78-host")
    parser.add_argument("--check", action="store_true", help="Read-only prerequisite and built-core check")
    args = parser.parse_args()
    host = inspect(args)
    output = args.output
    require(not output.resolve().is_relative_to(ROOT.resolve()),
            "Keep generated configuration, state and validation reports outside the source checkout")
    if args.check:
        print(json.dumps({"prerequisites_match": True, "state": "not-verified",
                          "source_commit": host["source_commit"], "ida_kernel_version": "not-probed"}))
        return
    common = {"IDADIR": host["ida_dir"], "IDAPYTHON_VENV_EXECUTABLE": host["python"],
              "IDA_NEXUS_IDALIB_ONLY": "1"}
    upstream = {"command": host["ida_mcp"], "args": ["stdio", "--agent=rea"],
                "mode": "headless", "protocol": "hex-rays", "timeoutMs": 300000,
                "workspaceRoot": str(output / "state/rea"), "env": common}
    rea = toml_server("rea", host["node"], [str(ROOT / "scripts/rea.mjs"), "mcp"],
                      {"REA_ANALYSIS_PROVIDER": "ida", "REA_IDA_MCP_CONFIG": str(output / "ida-official.json"),
                       "REA_BUILD_COMMIT": host["source_commit"]})
    native = toml_server("ida", host["ida_mcp"], ["stdio", "--agent=native"],
                         {**common, "IDA_NEXUS_STATE_DIR": str(output / "state/native/nexus"),
                          "IDA_MCP_STATE_DIR": str(output / "state/native/mcp")})
    tomllib.loads(rea)
    tomllib.loads(native)
    planned = {"host.json": json.dumps(host, indent=2) + "\n",
               "ida-official.json": json.dumps(upstream, indent=2) + "\n",
               "codex-a1.toml": rea, "codex-a0.toml": native}
    if output.exists():
        require(all((output / name).is_file() and (output / name).read_text() == text
                    for name, text in planned.items()),
                "Existing output is different or incomplete; preserve it and choose a new --output")
        skill = ROOT / "skills/reverse-engineer-anything"
        wanted = {str(path.relative_to(skill)): digest(path) for path in skill.rglob("*") if path.is_file()}
        actual = {str(path.relative_to(output / "rea-skill")): digest(path)
                  for path in (output / "rea-skill").rglob("*") if path.is_file()}
        require(wanted == actual and (output / "validation").is_dir(), "Existing output is incomplete or changed")
        print(json.dumps({"state": host["state"], "output": str(output), "changed": False}))
        return
    output.mkdir(parents=True, mode=0o700)
    for name, text in planned.items():
        with (output / name).open("x") as stream:
            stream.write(text)
        (output / name).chmod(0o600)
    shutil.copytree(ROOT / "skills/reverse-engineer-anything", output / "rea-skill")
    (output / "validation").mkdir(mode=0o700)
    print(json.dumps({"state": host["state"], "output": str(output), "changed": True,
                      "client_configuration_written": False, "target_loaded": False}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"Deployment check refused: {error}") from error
