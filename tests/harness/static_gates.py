#!/usr/bin/env python3
"""Static source, embedded-payload, and public-artifact gates."""

import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat

import instrument


class StaticGateError(RuntimeError):
    pass


def _source_bytes(repository_root, identity):
    try:
        return instrument.verify_source(
            repository_root,
            {
                "path": identity["path"],
                "size": identity["bytes"],
                "sha256": identity["sha256"],
            },
        )
    except instrument.InstrumentationError as error:
        raise StaticGateError(str(error))


def verify_source_manifest(repository_root, project):
    identities = {}
    for identity in project["sources"]:
        path = identity["path"]
        if path in identities:
            raise StaticGateError("duplicate source identity: %s" % path)
        identities[path] = identity
        _source_bytes(repository_root, identity)
    for entrypoint in project["entrypoints"]:
        source = identities.get(entrypoint["source_path"])
        if source is None or source["sha256"] != entrypoint["source_sha256"]:
            raise StaticGateError("entrypoint is not bound to exact source: %s" % entrypoint["entrypoint_id"])
    specification = project["accepted_specification"]
    _source_bytes(repository_root, specification)
    return identities


def verify_embedded_payloads(repository_root, project, identities=None):
    identities = identities or verify_source_manifest(repository_root, project)
    seen = set()
    observations = []
    for payload in project["embedded_payloads"]:
        payload_id = payload["payload_id"]
        if payload_id in seen:
            raise StaticGateError("duplicate embedded payload: %s" % payload_id)
        seen.add(payload_id)
        source = _source_bytes(repository_root, identities[payload["container_source_path"]])
        lines = source.splitlines(keepends=True)
        if payload["content_end_line"] > len(lines) or payload["opening_line"] != payload["content_start_line"] - 1:
            raise StaticGateError("invalid payload line bounds: %s" % payload_id)
        opening = lines[payload["opening_line"] - 1].decode("utf-8", "strict")
        if payload["delimiter"] not in opening:
            raise StaticGateError("payload delimiter mismatch: %s" % payload_id)
        content = b"".join(lines[payload["content_start_line"] - 1:payload["content_end_line"]])
        if not content.endswith(b"\n"):
            raise StaticGateError("payload lacks required final newline: %s" % payload_id)
        digest = hashlib.sha256(content).hexdigest()
        if len(content) != payload["content"]["bytes"] or digest != payload["content"]["sha256"]:
            raise StaticGateError("embedded payload identity mismatch: %s" % payload_id)
        byte_equal = None
        if payload["standalone_source_path"] is not None:
            standalone = _source_bytes(repository_root, identities[payload["standalone_source_path"]])
            if payload["standalone_sha256"] != identities[payload["standalone_source_path"]]["sha256"]:
                raise StaticGateError("standalone payload digest binding mismatch: %s" % payload_id)
            byte_equal = content == standalone
            if payload["byte_equality_required"] and not byte_equal:
                raise StaticGateError("embedded payload drift: %s" % payload_id)
        if byte_equal != payload["baseline_byte_equal"]:
            raise StaticGateError("payload baseline equality record mismatch: %s" % payload_id)
        observations.append({"payload_id": payload_id, "sha256": digest, "byte_equal": byte_equal})
    return observations


def _artifact_span(lines, extraction, prefix):
    start_line = extraction[prefix + "_start_line"]
    start_column = extraction[prefix + "_start_column"]
    end_line = extraction[prefix + "_end_line"]
    end_column = extraction[prefix + "_end_column"]
    if not (1 <= start_line <= end_line <= len(lines)):
        raise StaticGateError("invalid generated-artifact line bounds")
    first = lines[start_line - 1]
    last = lines[end_line - 1]
    if start_column > len(first) or end_column > len(last):
        raise StaticGateError("invalid generated-artifact column bounds")
    if start_line == end_line:
        if start_column > end_column:
            raise StaticGateError("reversed generated-artifact span")
        return first[start_column - 1:end_column]
    return b"".join([first[start_column - 1:]] + lines[start_line:end_line - 1] + [last[:end_column]])


def _verify_artifact_identity(data, identity, label):
    if len(data) != identity["bytes"] or hashlib.sha256(data).hexdigest() != identity["sha256"]:
        raise StaticGateError("generated-artifact identity mismatch: %s" % label)


def _shell_double_quoted(raw):
    if len(raw) < 2 or raw[:1] != b'"' or raw[-1:] != b'"':
        raise StaticGateError("generated-artifact argument is not double-quoted")
    body = raw[1:-1]
    output = bytearray()
    index = 0
    while index < len(body):
        if body[index:index + 1] == b"\\" and index + 1 < len(body) and body[index + 1:index + 2] in (b'"', b"\\", b"$", b"`"):
            output.extend(body[index + 1:index + 2])
            index += 2
            continue
        output.extend(body[index:index + 1])
        index += 1
    return bytes(output)


def _printf_single_quoted(raw):
    if len(raw) < 2 or raw[:1] != b"'" or raw[-1:] != b"'":
        raise StaticGateError("generated-artifact format is not single-quoted")
    body = raw[1:-1]
    escapes = {ord("a"): 7, ord("b"): 8, ord("t"): 9, ord("n"): 10, ord("v"): 11, ord("f"): 12, ord("r"): 13, ord("\\"): 92}
    output = bytearray()
    index = 0
    while index < len(body):
        if body[index:index + 1] == b"\\":
            if index + 1 >= len(body) or body[index + 1] not in escapes:
                raise StaticGateError("unsupported printf escape in generated-artifact binding")
            output.append(escapes[body[index + 1]])
            index += 2
            continue
        output.extend(body[index:index + 1])
        index += 1
    return bytes(output)


def _configuration_destination(raw):
    destination = raw.decode("utf-8", "strict")
    if len(destination) >= 2 and destination[:1] == destination[-1:] == '"':
        destination = destination[1:-1]
    destination = destination.replace("\\$", "$")
    replacements = {
        "$PLIST_DEST": "/Library/LaunchDaemons/com.wirevpn.startup.plist",
        "$CONF_DEST": "/etc/wireguard/client.conf",
        "${CONF_DEST}": "/etc/wireguard/client.conf",
    }
    for variable, expanded in replacements.items():
        if destination.startswith(variable):
            destination = expanded + destination[len(variable):]
            break
    if destination.startswith((
        "/etc/wireguard/",
        "/Library/LaunchDaemons/",
        "$HOME/WireVPN/",
        "$WIREVPN_DIR/",
    )) or destination in ("/etc/sysctl.conf", "/etc/resolv.conf"):
        return destination
    return None


def _discover_generated_write_sites(lines):
    sites = set()
    copy_command = re.compile(rb'^\s*(?:sudo\s+)?(?:cp|scp)\s+.*?("[^"]+"|\S+)\s*$')
    tee_target = re.compile(rb'\btee\s+("[^"]+"|\S+)')
    redirect_target = re.compile(rb'(?<![0-9&])>>?\s*("[^"]+"|[^\s]+)')
    for number, raw in enumerate(lines, 1):
        if raw.lstrip().startswith(b"#"):
            continue
        candidates = []
        copied = copy_command.search(raw.rstrip(b"\r\n"))
        if copied:
            candidates.append(copied.group(1))
        candidates.extend(match.group(1) for match in tee_target.finditer(raw))
        candidates.extend(match.group(1) for match in redirect_target.finditer(raw))
        start_line = number
        while start_line > 1 and lines[start_line - 2].rstrip(b"\r\n").endswith(b"\\"):
            start_line -= 1
        for candidate in candidates:
            destination = _configuration_destination(candidate)
            if destination is not None:
                sites.add((start_line, destination))
    return sites


def verify_generated_artifacts(repository_root, project, identities=None):
    identities = identities or verify_source_manifest(repository_root, project)
    payloads = {payload["payload_id"]: payload for payload in project["embedded_payloads"]}
    seen = set()
    declared_write_sites = set()
    discovered_write_sites = set()
    source_lines = {}
    for entrypoint in project["entrypoints"]:
        source_path = entrypoint["source_path"]
        lines = _source_bytes(repository_root, identities[source_path]).splitlines(keepends=True)
        source_lines[source_path] = lines
        discovered_write_sites.update(
            (source_path, line, destination)
            for line, destination in _discover_generated_write_sites(lines)
        )
    observations = []
    for artifact in project["generated_artifacts"]:
        artifact_id = artifact["artifact_id"]
        if artifact_id in seen:
            raise StaticGateError("duplicate generated artifact: %s" % artifact_id)
        seen.add(artifact_id)
        source_path = artifact["source_path"]
        lines = source_lines[source_path]
        extraction = artifact["extraction"]
        kind = extraction["kind"]
        raw_source = _artifact_span(lines, extraction, "source")
        raw_content = _artifact_span(lines, extraction, "content")
        _verify_artifact_identity(raw_source, artifact["source"], artifact_id + " source")
        if kind == "heredoc":
            delimiter = extraction["delimiter"]
            if delimiter is None or extraction["content_start_line"] != extraction["source_start_line"] + 1 or extraction["content_end_line"] != extraction["source_end_line"] - 1:
                raise StaticGateError("invalid heredoc generated-artifact bounds: %s" % artifact_id)
            opening = lines[extraction["source_start_line"] - 1].decode("utf-8", "strict")
            closing = lines[extraction["source_end_line"] - 1].decode("utf-8", "strict").strip()
            if not re.search(r"<<-?\s*%s(?:\s|$)" % re.escape(delimiter), opening) or closing != delimiter:
                raise StaticGateError("generated-artifact heredoc delimiter mismatch: %s" % artifact_id)
            content = raw_content
        else:
            if extraction["delimiter"] is not None or extraction["content_start_line"] != extraction["content_end_line"]:
                raise StaticGateError("invalid argument generated-artifact bounds: %s" % artifact_id)
            prefix = raw_source.split(raw_content, 1)[0]
            if kind == "echo-double-quoted":
                if not prefix.endswith(b"echo "):
                    raise StaticGateError("generated-artifact echo binding mismatch: %s" % artifact_id)
                content = _shell_double_quoted(raw_content) + b"\n"
            elif kind == "shell-double-quoted-argument":
                if not prefix.endswith(b"-d "):
                    raise StaticGateError("generated-artifact request argument mismatch: %s" % artifact_id)
                content = _shell_double_quoted(raw_content)
            elif kind == "shell-single-quoted-argument":
                if not prefix.endswith(b"-d ") or len(raw_content) < 2 or raw_content[:1] != b"'" or raw_content[-1:] != b"'":
                    raise StaticGateError("generated-artifact request argument mismatch: %s" % artifact_id)
                content = raw_content[1:-1]
            elif kind == "printf-single-quoted-format":
                if not prefix.endswith(b"printf "):
                    raise StaticGateError("generated-artifact printf binding mismatch: %s" % artifact_id)
                content = _printf_single_quoted(raw_content)
            elif kind == "command-output":
                if prefix.strip() and not prefix.rstrip().endswith(b"|"):
                    raise StaticGateError("generated-artifact command-output binding mismatch: %s" % artifact_id)
                content = raw_content + b"\n"
            elif kind == "file-copy":
                if not re.search(rb"\b(?:cp|scp)(?:\s+[^\s]+)*\s*$", prefix):
                    raise StaticGateError("generated-artifact file-copy binding mismatch: %s" % artifact_id)
                content = raw_content[1:-1] if raw_content[:1] == raw_content[-1:] == b'"' else raw_content
            else:
                raise StaticGateError("unknown generated-artifact extraction kind: %s" % artifact_id)
        _verify_artifact_identity(content, artifact["content"], artifact_id + " content")
        final_newline = extraction["includes_final_newline"]
        if final_newline is not None and content.endswith(b"\n") != final_newline:
            raise StaticGateError("generated-artifact final-newline record mismatch: %s" % artifact_id)
        nested_id = artifact["nested_payload_id"]
        if nested_id is not None:
            nested = payloads.get(nested_id)
            if nested is None or nested["container_source_path"] != source_path or not (nested["content_start_line"] <= extraction["source_start_line"] <= extraction["source_end_line"] <= nested["content_end_line"]):
                raise StaticGateError("generated-artifact nested payload mismatch: %s" % artifact_id)
        if artifact["framing"] != "request-body":
            destination = _configuration_destination(artifact["destination"].encode("utf-8"))
            if destination is not None:
                write_site = (source_path, extraction["source_start_line"], destination)
                if write_site in declared_write_sites:
                    raise StaticGateError("duplicate generated-artifact write site: %s" % (write_site,))
                declared_write_sites.add(write_site)
        observations.append({
            "artifact_id": artifact_id,
            "source_sha256": artifact["source"]["sha256"],
            "content_sha256": artifact["content"]["sha256"],
        })
    if declared_write_sites != discovered_write_sites:
        missing = sorted(discovered_write_sites - declared_write_sites)
        extra = sorted(declared_write_sites - discovered_write_sites)
        raise StaticGateError(
            "generated-artifact write-site inventory mismatch: missing=%r extra=%r" % (missing, extra)
        )
    return observations


def verify_bash_syntax(repository_root, project, bash_path):
    import subprocess

    for entrypoint in project["entrypoints"]:
        path = entrypoint["source_path"]
        result = subprocess.run(
            [bash_path, "-n", str(Path(repository_root) / path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            raise StaticGateError("Bash syntax failed for %s: %s" % (path, result.stderr.decode("utf-8", "replace")[:500]))


def verify_ignore_rules(repository_root):
    path = Path(repository_root) / ".gitignore"
    text = path.read_text(encoding="utf-8")
    required = ["*.conf", "*.key", "*.bak", "*.state", "*.live_backup", "*.log"]
    missing = [pattern for pattern in required if pattern not in text.splitlines()]
    return {"required_patterns": required, "missing_patterns": missing, "complete": not missing}


def scan_public_bytes(data, label, canary=None):
    denied = [
        (re.compile(rb"-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----"), "private-key-block"),
        (re.compile(rb"/U\x73ers/[^/\s]+"), "real-local-path"),
        (re.compile(rb"(?i)WIREVPN[_ -]?(?:SECRET|TOKEN|PASSWORD)[_ -]?CANARY"), "secret-canary"),
    ]
    if canary:
        denied.append((re.compile(re.escape(canary.encode("utf-8"))), "test-secret-canary"))
    for pattern, reason in denied:
        if pattern.search(data):
            raise StaticGateError("public-artifact sanitization failed for %s: %s" % (label, reason))


def scan_public_files(repository_root, paths):
    for relative in paths:
        path = Path(repository_root) / PurePosixPath(relative)
        mode = os.lstat(str(path)).st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise StaticGateError("public artifact is not a regular non-symlink file: %s" % relative)
        scan_public_bytes(path.read_bytes(), relative)


def _acceptance_links(text, source_path):
    rules = [
        (r"public.?ip|ifconfig|exit ip", ["WVA-01"]),
        (r"key|public derivation", ["WVA-02"]),
        (r"existing peer|rerun|preserve", ["WVA-03", "WVA-08"]),
        (r"backup|restart|active.state", ["WVA-04"]),
        (r"peer name|traversal|metachar", ["WVA-05"]),
        (r"address|allocation|exhaust", ["WVA-06"]),
        (r"peer|qr|qrencode", ["WVA-07"]),
        (r"adguard|blocklist|password", ["WVA-08", "WVA-09", "WVA-10"]),
        (r"client|homebrew|launchd|autostart", ["WVA-11", "WVA-12", "WVA-26"]),
        (r"dns|adguard|resolver|cache", ["WVA-13", "WVA-14", "WVA-15"]),
        (r"ipv6|leak", ["WVA-16", "WVA-17"]),
        (r"race|concurr|owned interface", ["WVA-18", "WVA-28"]),
        (r"secret|credential|private|mode|permission|ssh|scp|log", ["WVA-19"]),
        (r"embedded|heredoc|python", ["WVA-21"]),
        (r"package|firewall|forward|route|server", ["WVA-23"]),
        (r"boot|signal|shutdown|resident|network.wait", ["WVA-24"]),
        (r"usage|argument|status|wirevpn up|wirevpn down", ["WVA-25"]),
        (r"download|install|curl|wget|package|brew", ["WVA-26"]),
        (r"ignore|generated|state|backup|log", ["WVA-27"]),
    ]
    links = set()
    lowered = text.lower()
    for pattern, identifiers in rules:
        if re.search(pattern, lowered):
            links.update(identifiers)
    if not links:
        fallback = {
            "server_setup.sh": ["WVA-23"],
            "adguard_setup.sh": ["WVA-08"],
            "client_setup.sh": ["WVA-11"],
            "mobile_peer.sh": ["WVA-07"],
            "wirevpn.sh": ["WVA-25"],
            "wirevpn-connect.sh": ["WVA-24"],
            "README.md": ["WVA-20"],
        }
        links.update(fallback.get(source_path, ["WVA-20"]))
    return sorted(links)


def documentation_history_inventory(repository_root, project):
    records = []
    readme = Path(repository_root) / "README.md"
    lines = readme.read_bytes().splitlines(keepends=True)
    blocks = []
    current = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            if current:
                blocks.append(current)
                current = []
            continue
        current.append((number, line))
    if current:
        blocks.append(current)
    for index, block in enumerate(blocks, 1):
        content = b"".join(line for _number, line in block)
        text = content.decode("utf-8", "strict")
        records.append({
            "claim_id": "README-BLOCK-%03d" % index,
            "source_path": "README.md",
            "start_line": block[0][0],
            "end_line": block[-1][0],
            "source_sha256": hashlib.sha256(content).hexdigest(),
            "acceptance_ids": _acceptance_links(text, "README.md"),
            "disposition": "inventory-only-w2-fresh-evidence-required",
        })
    marker = re.compile(r"(?i)fix|crash|preserv|restor|stale|fail.?closed|regress|legacy|leak|duplicate|atomic|prior|safety")
    historical = 0
    for identity in project["sources"]:
        if identity["role"] != "product-script":
            continue
        source_path = identity["path"]
        for number, line in enumerate((Path(repository_root) / source_path).read_bytes().splitlines(keepends=True), 1):
            text = line.decode("utf-8", "strict")
            if "#" not in text or not marker.search(text):
                continue
            historical += 1
            records.append({
                "claim_id": "HISTORICAL-%s-%04d" % (source_path.replace(".", "-").upper(), number),
                "source_path": source_path,
                "start_line": number,
                "end_line": number,
                "source_sha256": hashlib.sha256(line).hexdigest(),
                "acceptance_ids": _acceptance_links(text, source_path),
                "disposition": "inventory-only-w2-fresh-evidence-required",
            })
    return {
        "inventory_complete": all(record["acceptance_ids"] for record in records),
        "readme_claim_blocks": len(blocks),
        "historical_fix_markers": historical,
        "fresh_evidence_map_required_in": "W2",
        "records": records,
    }


def external_code_inventory(repository_root, project):
    patterns = [
        ("remote-shell", re.compile(r"\bssh\b"), ["WVA-19", "WVA-21", "WVA-26"]),
        ("remote-copy", re.compile(r"\bscp\b"), ["WVA-19", "WVA-26"]),
        ("package-install", re.compile(r"\b(?:apt-get|dnf|pacman|brew)\b"), ["WVA-23", "WVA-26"]),
        ("network-fetch", re.compile(r"\b(?:curl|wget)\b"), ["WVA-01", "WVA-26"]),
        ("archive-extract", re.compile(r"\btar\b"), ["WVA-09", "WVA-10", "WVA-26"]),
        ("embedded-python", re.compile(r"\bpython3?\b"), ["WVA-21", "WVA-26"]),
    ]
    records = []
    for identity in project["sources"]:
        if identity["role"] != "product-script":
            continue
        source_path = identity["path"]
        for number, line in enumerate((Path(repository_root) / source_path).read_bytes().splitlines(keepends=True), 1):
            text = line.decode("utf-8", "strict")
            stripped = text.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for kind, pattern, acceptance_ids in patterns:
                if not pattern.search(text):
                    continue
                records.append({
                    "boundary_id": "EXTERNAL-%s-%04d-%s" % (source_path.replace(".", "-").upper(), number, kind.upper()),
                    "source_path": source_path,
                    "line": number,
                    "kind": kind,
                    "source_identity_sha256": hashlib.sha256(line).hexdigest(),
                    "acceptance_ids": acceptance_ids,
                    "disposition": "inventory-only-w2-identity-and-execution-disposition-required",
                })
    kinds = {}
    for record in records:
        kinds[record["kind"]] = kinds.get(record["kind"], 0) + 1
    return {
        "inventory_complete": all(record["source_identity_sha256"] and record["disposition"] for record in records),
        "boundary_count": len(records),
        "kinds": kinds,
        "records": records,
    }


def secret_boundary_inventory(repository_root, project):
    paths = [identity["path"] for identity in project["sources"]]
    paths.extend([
        "harness/project.json",
        "harness/project.schema.json",
        "harness/checks.json",
        "harness/checks.schema.json",
        "tests/toolchain.json",
        "Makefile",
        ".github/workflows/deterministic.yml",
    ])
    root = Path(repository_root)
    paths.extend(str(path.relative_to(root)) for path in sorted((root / "tests/harness").glob("*.py")))
    for tree, pattern in (("tests/vectors", "**/*.json"), ("tests/fixtures", "**/*.fixture")):
        paths.extend(str(path.relative_to(root)) for path in sorted((root / tree).glob(pattern)))
    scan_public_files(repository_root, sorted(set(paths)))
    return {
        "scanned_public_artifacts": len(set(paths)),
        "negative_controls": "WVH-07 synthetic canaries",
        "real_private_inputs_used": False,
        "scope": "W1 canaries; full file-mode/log/SSH/SCP/QR audit remains W2",
    }
