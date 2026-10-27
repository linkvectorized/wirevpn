#!/usr/bin/env python3
"""Discover and bind the exact nonprivileged Darwin runtime toolchain."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys


HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parent.parent


class ToolchainError(RuntimeError):
    pass


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _inside(path, root):
    try:
        return os.path.commonpath([str(path), str(root)]) == str(root)
    except ValueError:
        return False


def _identity(path):
    resolved = Path(path).resolve(strict=True)
    mode = os.lstat(str(resolved)).st_mode
    if not stat.S_ISREG(mode) or stat.S_ISLNK(mode) or not os.access(str(resolved), os.X_OK):
        raise ToolchainError("toolchain executable is not a regular executable file")
    data = resolved.read_bytes()
    return {
        "path": str(resolved),
        "resolved_path": str(resolved),
        "bytes": len(data),
        "sha256": _digest(data),
    }


def _bash_identity(path="/bin/bash"):
    identity = _identity(path)
    result = subprocess.run(
        [identity["path"], "--version"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        raise ToolchainError("Bash version discovery failed")
    first = result.stdout.decode("utf-8", "strict").splitlines()[0]
    match = re.match(r"GNU bash, version ([^ ]+) \(([^)]+)\)$", first)
    if match is None:
        raise ToolchainError("unrecognized Bash version report")
    identity.update({
        "version": match.group(1).split("(", 1)[0],
        "release": match.group(1),
        "target": match.group(2),
        "selection": "runtime-discovered",
    })
    return identity


def _version_numbers(value):
    match = re.match(r"^(\d+(?:\.\d+)*)", value)
    if match is None:
        raise ToolchainError("invalid tool version")
    return tuple(int(part) for part in match.group(1).split("."))


def discover(repository_root, require_ci=False):
    if platform.system() != "Darwin":
        raise ToolchainError("behavior lanes require Darwin Seatbelt containment")
    document = copy.deepcopy(json.loads((Path(repository_root) / "tests/toolchain.json").read_text(encoding="utf-8")))
    python = _identity(sys.executable)
    python.update({
        "implementation": platform.python_implementation(),
        "version": platform.python_version(),
        "selection": "runtime-discovered",
    })
    if require_ci:
        expected = document["ci"]["python"]
        if python["implementation"] != expected["implementation"] or python["version"] != expected["version"]:
            raise ToolchainError("runtime Python does not match the exact CI requirement")
    minimum_bash = document["host"]["bash"]["minimum_version"]
    system_bash = _bash_identity("/bin/bash")
    system_bash["selection"] = "discovered-not-selected"
    current_bash = None
    for candidate in ("/opt/homebrew/bin/bash", "/usr/local/bin/bash"):
        if not Path(candidate).exists():
            continue
        identity = _bash_identity(candidate)
        if _version_numbers(identity["version"]) >= _version_numbers(minimum_bash):
            current_bash = identity
            break
    if current_bash is None:
        raise ToolchainError("no explicit Bash satisfying the required minimum is available")
    if require_ci:
        expected_bash = document["ci"]["bash"]
        if current_bash["version"] != expected_bash["version"]:
            raise ToolchainError("runtime Bash does not match the exact CI requirement")
    sandbox = _identity("/usr/bin/sandbox-exec")
    sandbox.update({
        "profile_version": "wirevpn.darwin-sandbox/1.0",
        "identity_requirement": "revalidate-path-size-and-sha256-before-behavior-lanes",
    })
    document["host"] = {
        "system": platform.system(),
        "system_version": platform.release(),
        "architecture": platform.machine(),
        "identity_scope": "runtime-evidence-only",
        "sandbox_exec": sandbox,
        "bash": {
            "minimum_version": minimum_bash,
            "minimum_reason": document["host"]["bash"]["minimum_reason"],
            "current": current_bash,
            "system": system_bash,
        },
        "python": {
            "minimum_version": document["host"]["python"]["minimum_version"],
            "minimum_reason": document["host"]["python"]["minimum_reason"],
            "current": python,
        },
    }
    return document


def write_discovery(repository_root, output, require_ci=False):
    output = Path(output)
    repository = Path(repository_root).resolve(strict=True)
    if not output.is_absolute():
        raise ToolchainError("runtime toolchain output must be absolute")
    parent = output.parent.resolve(strict=True)
    if _inside(parent, repository) or _inside(output, repository):
        raise ToolchainError("runtime toolchain output must be outside the public repository")
    if stat.S_IMODE(parent.stat().st_mode) & 0o077:
        raise ToolchainError("runtime toolchain parent must be owner-only")
    document = discover(repository, require_ci)
    data = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(str(output), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
    return _digest(data)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", default=str(REPOSITORY))
    parser.add_argument("--output", required=True)
    parser.add_argument("--require-ci", action="store_true")
    arguments = parser.parse_args(argv)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise ToolchainError("root execution is refused")
    digest = write_discovery(arguments.repository, arguments.output, arguments.require_ci)
    print(json.dumps({"discovered": True, "sha256": digest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ToolchainError, OSError, ValueError) as error:
        print("HARNESS_FAIL: %s" % error, file=sys.stderr)
        sys.exit(2)
