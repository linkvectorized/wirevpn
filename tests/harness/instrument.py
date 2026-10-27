#!/usr/bin/env python3
"""Hash-bound, enumerated instrumentation for the WireVPN Bash baseline."""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat


PROFILE_VERSION = "wirevpn-bash-instrumentation/1.0"


class InstrumentationError(RuntimeError):
    pass


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _relative_path(value):
    path = PurePosixPath(value)
    if not value or path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise InstrumentationError("unsafe relative path: %r" % value)
    if "\\" in value or "\x00" in value:
        raise InstrumentationError("invalid relative path: %r" % value)
    return path


def _regular_file_no_symlinks(root, relative):
    relative = _relative_path(relative)
    root = Path(root).resolve(strict=True)
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        mode = os.lstat(str(current)).st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise InstrumentationError("non-directory or symlink parent: %s" % relative)
    candidate = current / relative.parts[-1]
    mode = os.lstat(str(candidate)).st_mode
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise InstrumentationError("source is not a regular non-symlink file: %s" % relative)
    if root not in candidate.resolve(strict=True).parents:
        raise InstrumentationError("source escapes repository root: %s" % relative)
    return candidate


def verify_source(repository_root, binding):
    relative = binding["path"]
    source = _regular_file_no_symlinks(repository_root, relative)
    data = source.read_bytes()
    if len(data) != binding["size"]:
        raise InstrumentationError("source size mismatch: %s" % relative)
    digest = sha256_bytes(data)
    if digest != binding["sha256"]:
        raise InstrumentationError("source digest mismatch: %s" % relative)
    return data


# Counts are properties of the accepted 01143e0 baseline, not values inferred at run time.
_RULES = {
    "server_setup.sh": [
        ("etc-wireguard", "absolute-root", b"/etc/wireguard", "etc_wireguard", 30),
        ("sysctl-conf", "absolute-root", b"/etc/sysctl.conf", "sysctl_conf", 2),
        ("root-check", "euid", b"$EUID", "euid", 1),
    ],
    "adguard_setup.sh": [
        ("resolv-conf", "absolute-root", b"/etc/resolv.conf", "resolv_conf", 2),
        ("adguard-home", "absolute-root", b"/opt/AdGuardHome", "adguard_home", 1),
        ("root-check", "euid", b"$EUID", "euid", 1),
    ],
    "client_setup.sh": [
        ("etc-wireguard", "absolute-root", b"/etc/wireguard", "etc_wireguard", 18),
        ("launch-daemons", "absolute-root", b"/Library/LaunchDaemons", "launch_daemons", 2),
        ("local-root", "absolute-root", b"/usr/local", "local_root", 15),
        ("homebrew-root", "absolute-root", b"/opt/homebrew", "homebrew_root", 8),
        ("run", "absolute-root", b"/run", "run", 2),
        ("proc-ipv6", "absolute-root", b"/proc/sys/net/ipv6", "proc_ipv6", 1),
        ("var-log", "absolute-root", b"/var/log", "var_log", 6),
        ("dig", "absolute-executable", b"/usr/bin/dig", "dig", 2),
        ("bash", "absolute-executable", b"/bin/bash", "bash", 5),
    ],
    "mobile_peer.sh": [
        ("etc-wireguard", "absolute-root", b"/etc/wireguard", "etc_wireguard", 17),
        ("tmp", "absolute-root", b"/tmp", "tmp", 3),
    ],
    "wirevpn.sh": [
        ("etc-wireguard", "absolute-root", b"/etc/wireguard", "etc_wireguard", 3),
        ("launch-daemons", "absolute-root", b"/Library/LaunchDaemons", "launch_daemons", 1),
        ("local-root", "absolute-root", b"/usr/local", "local_root", 2),
        ("homebrew-root", "absolute-root", b"/opt/homebrew", "homebrew_root", 1),
        ("run", "absolute-root", b"/run", "run", 2),
        ("proc-ipv6", "absolute-root", b"/proc/sys/net/ipv6", "proc_ipv6", 1),
        ("dig", "absolute-executable", b"/usr/bin/dig", "dig", 1),
        ("bash", "absolute-executable", b"/bin/bash", "bash", 1),
    ],
    "wirevpn-connect.sh": [
        ("etc-wireguard", "absolute-root", b"/etc/wireguard", "etc_wireguard", 2),
        ("local-root", "absolute-root", b"/usr/local", "local_root", 2),
        ("homebrew-root", "absolute-root", b"/opt/homebrew", "homebrew_root", 1),
        ("var-log", "absolute-root", b"/var/log", "var_log", 1),
        ("dig", "absolute-executable", b"/usr/bin/dig", "dig", 1),
        ("bash", "absolute-executable", b"/bin/bash", "bash", 1),
    ],
}


def default_replacements(synthetic_root, fakebin, bash):
    root = Path(synthetic_root).resolve(strict=True)
    fakebin = Path(fakebin).resolve(strict=True)
    bash = Path(bash).resolve(strict=True)
    if not bash.is_file() or stat.S_ISLNK(os.lstat(str(bash)).st_mode):
        raise InstrumentationError("fixed Bash binary must be a regular non-symlink file")
    return {
        "etc_wireguard": str(root / "etc/wireguard"),
        "launch_daemons": str(root / "Library/LaunchDaemons"),
        "local_root": str(root / "usr/local"),
        "homebrew_root": str(root / "opt/homebrew"),
        "run": str(root / "run"),
        "proc_ipv6": str(root / "proc/sys/net/ipv6"),
        "resolv_conf": str(root / "etc/resolv.conf"),
        "sysctl_conf": str(root / "etc/sysctl.conf"),
        "adguard_home": str(root / "opt/AdGuardHome"),
        "tmp": str(root / "tmp"),
        "var_log": str(root / "var/log"),
        "dig": str(fakebin / "dig"),
        "bash": str(bash),
        "euid": "0",
    }


def _validated_replacement(value):
    if not isinstance(value, str) or not value or "\x00" in value or "\n" in value or "\r" in value:
        raise InstrumentationError("invalid instrumentation replacement")
    return value.encode("utf-8")


_HOST_PATH = re.compile(
    rb"(?<![A-Za-z0-9:])/(?:etc|var|opt|usr|bin|Library|run|proc|tmp)"
    rb"(?:/[A-Za-z0-9._@+-]+)*"
)
_ALLOWED_UNMAPPED = {b"/usr/bin/env"}


def _reject_unmapped_host_paths(source_path, original, specs):
    mapped = [old for _id, _kind, old, _key, _count in specs if old.startswith(b"/")]
    for match in _HOST_PATH.finditer(original):
        token = match.group(0)
        if token in _ALLOWED_UNMAPPED:
            continue
        if not any(token == old or token.startswith(old + b"/") for old in mapped):
            raise InstrumentationError(
                "unmapped host path in %s at byte %d: %s"
                % (source_path, match.start(), token.decode("ascii", "replace"))
            )


def transform(source_path, original, replacements):
    specs = _RULES.get(source_path)
    if specs is None:
        raise InstrumentationError("no reviewed instrumentation profile for %s" % source_path)
    _reject_unmapped_host_paths(source_path, original, specs)
    matches = []
    records = []
    for rule_id, kind, old, replacement_key, expected in specs:
        if replacement_key not in replacements:
            raise InstrumentationError("missing replacement %s for %s" % (replacement_key, source_path))
        new = _validated_replacement(replacements[replacement_key])
        found = list(re.finditer(re.escape(old), original))
        if len(found) != expected:
            raise InstrumentationError(
                "replacement count mismatch for %s/%s: expected %d, found %d"
                % (source_path, rule_id, expected, len(found))
            )
        records.append({
            "id": rule_id,
            "kind": kind,
            "old_sha256": sha256_bytes(old),
            "new_sha256": sha256_bytes(new),
            "replacements": expected,
        })
        matches.extend((match.start(), match.end(), new, rule_id) for match in found)
    matches.sort(key=lambda item: (item[0], item[1]))
    previous_end = -1
    output = bytearray()
    cursor = 0
    for start, end, new, rule_id in matches:
        if start < previous_end or start < cursor:
            raise InstrumentationError("overlapping instrumentation rule at %s/%s" % (source_path, rule_id))
        output.extend(original[cursor:start])
        output.extend(new)
        cursor = end
        previous_end = end
    output.extend(original[cursor:])
    transformed = bytes(output)
    return transformed, records


def instrument_source(repository_root, binding, instrumentation_root, replacements):
    source_path = binding["path"]
    original = verify_source(repository_root, binding)
    transformed, records = transform(source_path, original, replacements)
    destination_root = Path(instrumentation_root)
    if destination_root.exists():
        if destination_root.is_symlink() or not destination_root.is_dir():
            raise InstrumentationError("instrumentation root is not a real directory")
        if any(destination_root.iterdir()):
            raise InstrumentationError("instrumentation root must be fresh and empty")
    else:
        destination_root.mkdir(mode=0o700, parents=False)
    destination = destination_root / PurePosixPath(source_path).name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(str(destination), flags, 0o700)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(transformed)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    record = {
        "profile": PROFILE_VERSION,
        "source": {
            "path": source_path,
            "size": len(original),
            "sha256": sha256_bytes(original),
        },
        "transformed": {
            "path": destination.name,
            "size": len(transformed),
            "sha256": sha256_bytes(transformed),
        },
        "rules": records,
        "instrumenter_sha256": sha256_bytes(Path(__file__).read_bytes()),
    }
    record_path = destination_root / "transformation.json"
    descriptor = os.open(str(record_path), flags, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(canonical_json(record))
    return destination, record
