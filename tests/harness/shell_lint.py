#!/usr/bin/env python3
"""Provision and run the exact ShellCheck and shfmt release binaries."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Dict, List
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TOOLCHAIN = ROOT / "tests" / "toolchain.json"
ENTRYPOINTS = (
    "server_setup.sh",
    "adguard_setup.sh",
    "client_setup.sh",
    "mobile_peer.sh",
    "wirevpn.sh",
    "wirevpn-connect.sh",
)
MAX_ASSET_BYTES = 128 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class LintError(Exception):
    pass


class HttpsOnlyRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        if urlsplit(new_url).scheme != "https":
            raise LintError("refusing a non-HTTPS release-asset redirect")
        return super().redirect_request(
            request, file_pointer, code, message, headers, new_url
        )


def require_keys(value: Dict[str, Any], expected: set, label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise LintError(
            "{} has wrong fields (missing={}, unknown={})".format(
                label, missing, unknown
            )
        )


def load_pins(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        document = json.load(handle)
    pins = document["shell_lint"]
    require_keys(
        pins,
        {"schema", "version", "platform", "shellcheck", "shfmt"},
        "shell_lint",
    )
    if pins["schema"] != "wirevpn.shell-lint-toolchain/1.0":
        raise LintError("unsupported shell-lint toolchain schema")
    if pins["version"] != "1.0.0":
        raise LintError("unsupported shell-lint toolchain version")
    require_keys(pins["platform"], {"system", "architecture"}, "platform")
    for name in ("shellcheck", "shfmt"):
        tool = pins[name]
        require_keys(tool, {"version", "asset"}, name)
        if not isinstance(tool["version"], str) or not tool["version"]:
            raise LintError("{} has an invalid version".format(name))
        expected_asset_keys = {"url", "sha256", "format"}
        if name == "shellcheck":
            expected_asset_keys.update(("member", "allowed_members"))
        asset = tool["asset"]
        require_keys(asset, expected_asset_keys, "{} asset".format(name))
        if not HEX_SHA256.fullmatch(asset["sha256"]):
            raise LintError("{} has an invalid SHA-256".format(name))
        parsed = urlsplit(asset["url"])
        if (
            parsed.scheme != "https"
            or parsed.hostname != "github.com"
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise LintError("{} asset is not an official HTTPS URL".format(name))
    shellcheck = pins["shellcheck"]["asset"]
    if shellcheck["format"] != "tar.xz":
        raise LintError("ShellCheck asset must be tar.xz")
    members = shellcheck["allowed_members"]
    if (
        not isinstance(members, list)
        or not all(isinstance(member, str) for member in members)
        or len(members) != len(set(members))
        or shellcheck["member"] not in members
    ):
        raise LintError("ShellCheck archive member allowlist is invalid")
    if pins["shfmt"]["asset"]["format"] != "executable":
        raise LintError("shfmt asset must be a standalone executable")
    return pins


def require_platform(pins: Dict[str, Any]) -> None:
    expected = pins["platform"]
    architecture = platform.machine().lower()
    if architecture == "aarch64":
        architecture = "arm64"
    if (
        platform.system() != expected["system"]
        or architecture != expected["architecture"]
    ):
        raise LintError(
            "pinned shell-lint tools require {} {}, found {} {}".format(
                expected["system"],
                expected["architecture"],
                platform.system(),
                architecture,
            )
        )


def ensure_directory(path: Path) -> None:
    if os.path.lexists(str(path)):
        metadata = path.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise LintError("tool output is not a real directory: {}".format(path))
    else:
        path.mkdir(mode=0o700, parents=True)


def ensure_regular_file(path: Path, executable: bool = False) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        raise LintError("missing required file: {}".format(path))
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise LintError("not a regular non-symlink file: {}".format(path))
    if metadata.st_nlink != 1:
        raise LintError("multiply linked file is not accepted: {}".format(path))
    if executable and not metadata.st_mode & stat.S_IXUSR:
        raise LintError("tool is not executable: {}".format(path))


def download_asset(url: str, expected_sha256: str, destination: Path) -> None:
    digest = hashlib.sha256()
    total = 0
    request = Request(url, headers={"User-Agent": "wirevpn-shell-lint/1.0"})
    opener = build_opener(HttpsOnlyRedirect)
    with opener.open(request, timeout=60) as response:
        if response.getcode() != 200 or urlsplit(response.geturl()).scheme != "https":
            raise LintError("release asset did not return HTTPS 200: {}".format(url))
        length = response.headers.get("Content-Length")
        if length is not None and int(length) > MAX_ASSET_BYTES:
            raise LintError("release asset exceeds the size bound: {}".format(url))
        with destination.open("xb") as output:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ASSET_BYTES:
                    raise LintError("release asset exceeds the size bound")
                digest.update(chunk)
                output.write(chunk)
    actual = digest.hexdigest()
    if actual != expected_sha256:
        raise LintError(
            "release asset SHA-256 mismatch: expected {}, got {}".format(
                expected_sha256, actual
            )
        )
    ensure_regular_file(destination)


def validate_member_name(name: str) -> None:
    if (
        not name
        or "\x00" in name
        or "\\" in name
        or PurePosixPath(name).is_absolute()
        or any(part in ("", ".", "..") for part in name.split("/"))
    ):
        raise LintError("unsafe ShellCheck archive member: {!r}".format(name))


def extract_shellcheck(archive_path: Path, asset: Dict[str, Any], output: Path) -> None:
    expected_names = set(asset["allowed_members"])
    with tarfile.open(archive_path, mode="r:xz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if len(names) != len(set(names)) or set(names) != expected_names:
            raise LintError("ShellCheck archive has unexpected or duplicate members")
        selected = None
        for member in members:
            validate_member_name(member.name)
            if not member.isreg() or member.issym() or member.islnk():
                raise LintError(
                    "ShellCheck archive member is not a regular file: {}".format(
                        member.name
                    )
                )
            if member.name == asset["member"]:
                selected = member
        if selected is None or selected.size < 1 or selected.size > MAX_EXECUTABLE_BYTES:
            raise LintError("ShellCheck executable is missing or outside the size bound")
        source = archive.extractfile(selected)
        if source is None:
            raise LintError("ShellCheck executable cannot be read")
        with source, output.open("xb") as destination:
            remaining = selected.size
            while remaining:
                chunk = source.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise LintError("truncated ShellCheck executable")
                destination.write(chunk)
                remaining -= len(chunk)
            if source.read(1):
                raise LintError("ShellCheck executable exceeds its archive size")
    ensure_regular_file(output)


def run_process(
    arguments: List[str], timeout: int, input_text: str = None
) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            arguments,
            cwd=str(ROOT),
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            input=input_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise LintError("command timed out: {}".format(arguments[0]))


def assert_version(name: str, executable: Path, expected: str) -> None:
    ensure_regular_file(executable, executable=True)
    result = run_process([str(executable), "--version"], 30)
    output = result.stdout.strip()
    if result.returncode != 0:
        raise LintError("{} --version failed: {}".format(name, result.stderr.strip()))
    if name == "shellcheck":
        match = re.search(r"(?m)^version: ([^\r\n]+)$", result.stdout)
        actual = match.group(1) if match else None
    else:
        actual = output[1:] if output.startswith("v") else output
    if actual != expected:
        raise LintError(
            "{} version mismatch: expected {}, got {!r}".format(name, expected, output)
        )


def install_file(source: Path, destination: Path) -> None:
    source.chmod(0o700)
    ensure_regular_file(source, executable=True)
    if os.path.lexists(str(destination)):
        ensure_regular_file(destination)
    os.replace(str(source), str(destination))
    ensure_regular_file(destination, executable=True)


def provision(pins: Dict[str, Any], output_directory: Path) -> None:
    require_platform(pins)
    ensure_directory(output_directory)
    with tempfile.TemporaryDirectory(
        prefix=".shell-lint-provision-", dir=str(output_directory)
    ) as temporary:
        staging = Path(temporary)
        for name in ("shellcheck", "shfmt"):
            tool = pins[name]
            asset = tool["asset"]
            executable = staging / name
            if name == "shellcheck":
                archive = staging / "shellcheck.tar.xz"
                download_asset(asset["url"], asset["sha256"], archive)
                extract_shellcheck(archive, asset, executable)
            else:
                download_asset(asset["url"], asset["sha256"], executable)
            executable.chmod(0o700)
            assert_version(name, executable, tool["version"])
            install_file(executable, output_directory / name)
        print("provisioned ShellCheck {} and shfmt {} in {}".format(
            pins["shellcheck"]["version"],
            pins["shfmt"]["version"],
            output_directory,
        ))


def check(pins: Dict[str, Any], tool_directory: Path) -> None:
    require_platform(pins)
    ensure_directory(tool_directory)
    shellcheck = tool_directory / "shellcheck"
    shfmt = tool_directory / "shfmt"
    assert_version("shellcheck", shellcheck, pins["shellcheck"]["version"])
    assert_version("shfmt", shfmt, pins["shfmt"]["version"])
    for entrypoint in ENTRYPOINTS:
        ensure_regular_file(ROOT / entrypoint)
    result = run_process(
        [str(shellcheck), "--severity=error"] + list(ENTRYPOINTS), 120
    )
    if result.returncode != 0:
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise LintError("ShellCheck rejected one or more product entrypoints")
    for entrypoint in ENTRYPOINTS:
        source = (ROOT / entrypoint).read_text(encoding="utf-8")
        result = run_process(
            [str(shfmt), "-ln", "bash", "-to-json"], 60, input_text=source
        )
        if result.returncode != 0:
            sys.stderr.write(result.stderr)
            raise LintError("shfmt could not parse {} as Bash".format(entrypoint))
        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise LintError("shfmt returned invalid JSON for {}: {}".format(entrypoint, error))
        if not isinstance(parsed, dict):
            raise LintError("shfmt returned an invalid syntax tree for {}".format(entrypoint))
    print("ShellCheck {} passed all six entrypoints at severity=error".format(
        pins["shellcheck"]["version"]
    ))
    print("shfmt {} parsed all six entrypoints as Bash".format(
        pins["shfmt"]["version"]
    ))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", type=Path, default=DEFAULT_TOOLCHAIN)
    subcommands = parser.add_subparsers(dest="command", required=True)
    provision_parser = subcommands.add_parser("provision")
    provision_parser.add_argument("--output-dir", type=Path, required=True)
    check_parser = subcommands.add_parser("check")
    check_parser.add_argument("--tool-dir", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        pins = load_pins(arguments.toolchain)
        if arguments.command == "provision":
            provision(pins, arguments.output_dir)
        else:
            check(pins, arguments.tool_dir)
    except (LintError, OSError, ValueError, KeyError, tarfile.TarError) as error:
        print("shell-lint: error: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
