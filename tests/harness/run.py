#!/usr/bin/env python3
"""WireVPN deterministic host-side harness runner."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import stat
import sys
import tempfile
import uuid

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parent.parent
sys.path.insert(0, str(HERE))

import containment
import fakebin
import instrument
import model
import schema
import static_gates


RUNNER_VERSION = "wirevpn.python-runner/1.0"
RESULT_SCHEMA = "wirevpn.characterization-result/1.0"
MAX_EVIDENCE_FILES = 10000
FAKE_COMMANDS = [
    "apt-get", "brew", "clear", "curl", "date", "dig", "dnf", "dscacheutil",
    "ip", "killall", "launchctl", "networksetup", "openssl", "pacman", "ping",
    "qrencode", "scp", "sleep", "ss", "ssh", "sysctl", "systemctl", "tar",
    "ufw", "uname", "wg", "wg-quick", "sudo",
]


class RunnerError(RuntimeError):
    execution_health = "NOT_RUN"


class HarnessFailure(RuntimeError):
    execution_health = "PARTIAL"


def _now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def _iso(value):
    return value.isoformat().replace("+00:00", "Z")


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _file_digest(path):
    return _digest(Path(path).read_bytes())


def _load_json(path):
    return model.load_json(path)


def _write_json(path, value, mode=0o600):
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    descriptor = os.open(str(path), flags, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
    return _digest(data)


def _safe_relative(value):
    path = PurePosixPath(value)
    if not value or path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise RunnerError("unsafe relative path")
    return path


def _no_symlink_components(path, allow_missing=False):
    path = Path(path)
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            mode = os.lstat(str(current)).st_mode
        except FileNotFoundError:
            if allow_missing:
                continue
            raise RunnerError("missing path component: %s" % current)
        if stat.S_ISLNK(mode):
            raise RunnerError("symlink path component is denied: %s" % current)


def _inside(path, root):
    try:
        return os.path.commonpath([str(path), str(root)]) == str(root)
    except ValueError:
        return False


def prepare_evidence_root(path, repository_root):
    path = Path(path).expanduser()
    if not path.is_absolute():
        raise RunnerError("evidence root must be absolute")
    _no_symlink_components(path, allow_missing=True)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    resolved = path.resolve(strict=True)
    repository_root = Path(repository_root).resolve(strict=True)
    home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
    if str(resolved) == "/" or resolved == home:
        raise RunnerError("filesystem root or real HOME cannot be an evidence root")
    if resolved == repository_root or _inside(resolved, repository_root) or _inside(repository_root, resolved):
        raise RunnerError("evidence and repository roots overlap")
    mode = stat.S_IMODE(os.stat(str(resolved)).st_mode)
    if mode & 0o077:
        raise RunnerError("evidence root must be owner-only")
    return resolved


def dependency_digests(repository_root, runtime_toolchain=None):
    root = Path(repository_root)
    result = {}
    project = _load_json(root / "harness/project.json")
    paths = [project["accepted_specification"]["path"]]
    paths.extend(identity["path"] for identity in project["sources"])
    paths.extend([
        "harness/project.json",
        "harness/checks.json",
        "harness/project.schema.json",
        "harness/checks.schema.json",
        "tests/toolchain.json",
        "tests/vectors/vectors.json",
        "tests/vectors/schema.json",
        "Makefile",
        ".github/workflows/deterministic.yml",
    ])
    paths.extend(str(path.relative_to(root)) for path in sorted((root / "tests/harness").glob("*.py")))
    paths.extend(str(path.relative_to(root)) for path in sorted((root / "tests/vectors").glob("**/*.json")) if "schema.json" not in str(path) and "vectors.json" not in str(path))
    paths.extend(str(path.relative_to(root)) for path in sorted((root / "tests/fixtures").glob("**/*.fixture")))
    for relative in sorted(set(paths)):
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise RunnerError("missing or unsafe evidence dependency: %s" % relative)
        result[relative] = _file_digest(path)
    if runtime_toolchain is not None:
        path = Path(runtime_toolchain)
        if not path.is_file() or path.is_symlink():
            raise RunnerError("missing or unsafe runtime toolchain")
        result["@runtime-toolchain"] = _file_digest(path)
    return result


def verify_bootstrap(repository_root, project, checks):
    root = Path(repository_root)
    for artifact in project["bootstrap"]["artifacts"]:
        digest = artifact["digest"]
        if digest["state"] != "content-bound" or _file_digest(root / artifact["path"]) != digest["sha256"]:
            raise RunnerError("bootstrap binding mismatch: %s" % artifact["artifact_id"])
    for check in checks["checks"]:
        for binding in (check["runner"], check["vectors"], check["toolchain"]):
            digest = binding["digest"]
            if digest["state"] != "content-bound" or _file_digest(root / binding["path"]) != digest["sha256"]:
                raise RunnerError("check artifact binding mismatch: %s" % check["check_id"])
    if checks["vector_bundle"]["digest"]["state"] != "content-bound" or _file_digest(root / checks["vector_bundle"]["path"]) != checks["vector_bundle"]["digest"]["sha256"]:
        raise RunnerError("vector bundle is not correctly content-bound")


def _content_digest(document):
    copy = dict(document)
    copy.pop("content_sha256", None)
    return _digest((json.dumps(copy, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))


def _verify_content_digest(document, label):
    if document.get("content_sha256") != _content_digest(document):
        raise RunnerError("content digest mismatch: %s" % label)


def rebind_vectors(repository_root):
    root = Path(repository_root)
    index_path = root / "tests/vectors/vectors.json"
    index = _load_json(index_path)
    for reference in index["vectors"]:
        semantic_path = root / reference["semantic_path"]
        binding_path = root / reference["bash_binding_path"]
        semantic = _load_json(semantic_path)
        binding = _load_json(binding_path)
        semantic["content_sha256"] = _content_digest(semantic)
        _write_json(semantic_path, semantic, 0o644)
        binding["vector_sha256"] = semantic["content_sha256"]
        binding["content_sha256"] = _content_digest(binding)
        _write_json(binding_path, binding, 0o644)
        reference["semantic_sha256"] = _file_digest(semantic_path)
        reference["bash_binding_sha256"] = _file_digest(binding_path)
    index["content_sha256"] = _content_digest(index)
    _write_json(index_path, index, 0o644)


def rebind(repository_root):
    root = Path(repository_root)
    rebind_vectors(root)
    project_path = root / "harness/project.json"
    checks_path = root / "harness/checks.json"
    project = _load_json(project_path)
    checks = _load_json(checks_path)
    artifacts = {artifact["artifact_id"]: artifact for artifact in project["bootstrap"]["artifacts"]}
    for check in checks["checks"]:
        for binding in (check["runner"], check["vectors"], check["toolchain"]):
            binding["digest"] = {
                "algorithm": "sha-256",
                "state": "content-bound",
                "sha256": _file_digest(root / binding["path"]),
            }
    bundle = checks["vector_bundle"]
    bundle["digest"] = {
        "algorithm": "sha-256",
        "state": "content-bound",
        "sha256": _file_digest(root / bundle["path"]),
    }
    _write_json(checks_path, checks, 0o644)
    for artifact in project["bootstrap"]["artifacts"]:
        artifact["digest"] = {
            "algorithm": "sha-256",
            "state": "content-bound",
            "sha256": _file_digest(root / artifact["path"]),
        }
    _write_json(project_path, project, 0o644)


def load_configuration(repository_root, require_bindings=True):
    root = Path(repository_root)
    project = _load_json(root / "harness/project.json")
    checks = _load_json(root / "harness/checks.json")
    schema.require_valid(project, _load_json(root / "harness/project.schema.json"))
    schema.require_valid(checks, _load_json(root / "harness/checks.schema.json"))
    project_ids = [entry["check_id"] for entry in project["required_checks"]]
    check_ids = [entry["check_id"] for entry in checks["checks"]]
    if len(project_ids) != len(set(project_ids)) or len(check_ids) != len(set(check_ids)):
        raise RunnerError("duplicate check identifiers")
    if set(project_ids) != set(check_ids):
        raise RunnerError("project and check inventories differ")
    if require_bindings:
        verify_bootstrap(root, project, checks)
    return project, checks


def _evidence_artifacts(evidence_root):
    records = []
    for current, directories, files in os.walk(str(evidence_root), followlinks=False):
        directories.sort()
        files.sort()
        current_path = Path(current)
        for name in directories:
            if (current_path / name).is_symlink():
                raise RunnerError("symlinked raw-evidence directory")
        for name in files:
            path = current_path / name
            relative = path.relative_to(evidence_root).as_posix()
            if relative in ("raw-evidence.json", "report.json"):
                continue
            mode = os.lstat(str(path)).st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                raise RunnerError("raw-evidence artifact is not a regular non-symlink file")
            data = path.read_bytes()
            records.append({"path": relative, "bytes": len(data), "sha256": _digest(data)})
            if len(records) > MAX_EVIDENCE_FILES:
                raise RunnerError("raw-evidence artifact bound exceeded")
    return records


def _verify_raw_evidence_artifacts(raw_path, record):
    raw = _load_json(raw_path)
    if not isinstance(raw, dict) or raw.get("suite") != record.get("suite") or raw.get("results") != record.get("results"):
        raise RunnerError("raw-evidence suite or results differ from the report")
    recorded = raw.get("artifacts")
    if not isinstance(recorded, list) or len(recorded) > MAX_EVIDENCE_FILES:
        raise RunnerError("raw-evidence artifact manifest is missing or unbounded")
    identities = {}
    for entry in recorded:
        if not isinstance(entry, dict) or set(entry) != {"path", "bytes", "sha256"}:
            raise RunnerError("malformed raw-evidence artifact identity")
        relative = entry["path"]
        _safe_relative(relative)
        if relative in identities or relative in ("raw-evidence.json", "report.json"):
            raise RunnerError("duplicate or forbidden raw-evidence artifact identity")
        identities[relative] = entry
    current = {entry["path"]: entry for entry in _evidence_artifacts(raw_path.parent)}
    if current != identities:
        raise RunnerError("raw-evidence artifacts were changed, deleted, or added")


def evidence_is_current(record, repository_root):
    if not isinstance(record, dict):
        return False
    try:
        expires_at = record["retention"]["expires_at"]
        if not isinstance(expires_at, str) or expires_at <= _iso(_now()):
            return False
        raw_identity = record["raw_evidence"]["identity"]
        raw_digest = record["raw_evidence"]["sha256"]
        if not isinstance(raw_identity, str) or not raw_identity or not isinstance(raw_digest, str):
            return False
        raw_path = Path(raw_identity)
        if not raw_path.is_file() or raw_path.is_symlink() or _file_digest(raw_path) != raw_digest:
            return False
        _verify_raw_evidence_artifacts(raw_path, record)
        runtime_toolchain = record.get("runtime_toolchain", {})
        if not isinstance(runtime_toolchain, dict):
            return False
        current = dependency_digests(repository_root, runtime_toolchain.get("path"))
        if current != record.get("dependencies"):
            return False
        if runtime_toolchain.get("path") is not None:
            select_toolchain(_load_json(runtime_toolchain["path"]))
    except (KeyError, TypeError, ValueError, OSError, RunnerError):
        return False
    return True


def _version_numbers(value):
    match = re.match(r"^(\d+(?:\.\d+)*)", value)
    if match is None:
        raise RunnerError("invalid tool version: %s" % value)
    return tuple(int(part) for part in match.group(1).split("."))


def select_toolchain(toolchain):
    host = toolchain["host"]
    selected = {
        "bash": host["bash"]["current"],
        "python": host["python"]["current"],
        "sandbox_exec": host["sandbox_exec"],
    }
    if _version_numbers(selected["bash"]["version"]) < _version_numbers(host["bash"]["minimum_version"]):
        raise RunnerError("selected Bash is below the required minimum")
    for name, identity in selected.items():
        path = Path(identity["path"])
        if not path.is_file() or path.is_symlink() or not os.access(str(path), os.X_OK):
            raise RunnerError("toolchain executable is unavailable: %s" % name)
        data = path.read_bytes()
        if len(data) != identity["bytes"] or _digest(data) != identity["sha256"]:
            raise RunnerError("toolchain identity mismatch: %s" % name)
    return selected


def resolve_toolchain_path(repository_root, value=None):
    if value is None:
        return Path(repository_root) / "tests/toolchain.json"
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise RunnerError("runtime toolchain path must be absolute")
    _no_symlink_components(path)
    if not path.is_file() or path.is_symlink():
        raise RunnerError("runtime toolchain must be a regular non-symlink file")
    resolved = path.resolve(strict=True)
    repository = Path(repository_root).resolve(strict=True)
    if _inside(resolved, repository):
        raise RunnerError("runtime toolchain must be outside the public repository")
    if stat.S_IMODE(resolved.stat().st_mode) & 0o077:
        raise RunnerError("runtime toolchain must be owner-only")
    return resolved


def _fixture_digest(repository_root, identity):
    path = Path(repository_root) / "tests/fixtures" / identity["path"]
    _no_symlink_components(path)
    data = path.read_bytes()
    if len(data) != identity["bytes"] or _digest(data) != identity["sha256"] or path.suffix != ".fixture":
        raise RunnerError("fixture identity mismatch: %s" % identity["path"])
    return data


def _install_fixture_tree(case_root, repository_root, fixtures):
    for fixture in fixtures:
        data = _fixture_digest(repository_root, fixture)
        document = json.loads(data.decode("utf-8"))
        for entry in document.get("files", []):
            relative = _safe_relative(entry["path"])
            destination = case_root / relative
            if not _inside(destination, case_root):
                raise RunnerError("fixture path escape")
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            destination.write_bytes(entry.get("text", "").encode("utf-8"))
            destination.chmod(entry.get("mode", 384))
        for directory in document.get("directories", []):
            (case_root / _safe_relative(directory)).mkdir(mode=0o700, parents=True, exist_ok=True)


def _write_fake_wrapper(path, fakebin_path, bash_path):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text("#!%s\nexec %s \"$@\"\n" % (bash_path, fakebin_path), encoding="utf-8")
    path.chmod(0o700)


def _expand_binding(value, case_root, evidence_case, bash_path):
    if isinstance(value, dict):
        expanded = {key: _expand_binding(item, case_root, evidence_case, bash_path) for key, item in value.items()}
        stdin = expanded.get("stdin")
        if isinstance(stdin, dict) and set(stdin) == {"text"} and isinstance(stdin.get("text"), str):
            data = stdin["text"].encode("utf-8")
            expanded["stdin"] = {"size": len(data), "sha256": _digest(data)}
        return expanded
    if isinstance(value, list):
        return [_expand_binding(item, case_root, evidence_case, bash_path) for item in value]
    if isinstance(value, str):
        return value.replace("@CASE@", str(case_root)).replace("@EVIDENCE@", str(evidence_case)).replace("@BASH@", bash_path)
    return value


def _prepare_case(repository_root, evidence_case, semantic, binding, toolchain):
    tools = select_toolchain(toolchain)
    parent = Path("/private/tmp") / ("wirevpn-harness-%d" % os.getuid())
    parent.mkdir(mode=0o700, exist_ok=True)
    if parent.is_symlink() or stat.S_IMODE(parent.stat().st_mode) & 0o077:
        raise RunnerError("synthetic case parent must be a real owner-only directory")
    case_root = parent / semantic["vector_id"]
    if case_root.exists() or case_root.is_symlink():
        raise RunnerError("deterministic synthetic case root is already occupied")
    case_root.mkdir(mode=0o700)
    binding = _expand_binding(binding, case_root, evidence_case, tools["bash"]["path"])
    try:
        for relative in ("home", "tmp", "work", "fakebin", "instrumentation"):
            (case_root / relative).mkdir(mode=0o700)
        _install_fixture_tree(case_root, repository_root, semantic.get("fixtures", []))
        python = tools["python"]["path"]
        bash = tools["bash"]["path"]
        command_names = sorted(set(FAKE_COMMANDS) | {call["argv"][0] for call in binding["commands"]})
        model.install_fakebin(case_root / "fakebin", command_names, python)
        model.initialize_case(
            case_root / "fakebin/model",
            binding["commands"],
            {"case": case_root, "evidence": evidence_case},
            binding.get("initial_state", {}),
        )
        for relative, command in (
            ("opt/homebrew/bin/wg-quick", "wg-quick"),
            ("usr/local/bin/wg-quick", "wg-quick"),
            ("opt/homebrew/bin/brew", "brew"),
        ):
            _write_fake_wrapper(case_root / relative, case_root / "fakebin" / command, bash)
        source_identity = next(
            item for item in binding["_project_sources"] if item["path"] == binding["entrypoint"]
        )
        replacements = instrument.default_replacements(case_root, case_root / "fakebin", bash)
        transformed, transformation = instrument.instrument_source(
            repository_root,
            {"path": source_identity["path"], "size": source_identity["bytes"], "sha256": source_identity["sha256"]},
            case_root / "instrumentation",
            replacements,
        )
        environment = {
            "PATH": str(case_root / "fakebin") + ":/usr/bin:/bin",
            "HOME": str(case_root / "home"),
            "TMPDIR": str(case_root / "tmp"),
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
        }
        return case_root, transformed, environment, transformation
    except Exception:
        shutil.rmtree(case_root, ignore_errors=True)
        raise


def execute_case(repository_root, evidence_case, semantic, binding, toolchain):
    case_root, transformed, environment, transformation = _prepare_case(
        repository_root, evidence_case, semantic, binding, toolchain
    )
    adapter = containment.DarwinContainment()
    try:
        execution = adapter.execute(
            [select_toolchain(toolchain)["bash"]["path"], str(transformed)] + binding.get("arguments", []),
            case_root / "work",
            environment,
            case_root,
            evidence_case,
            binding["timeout_seconds"],
        )
        (evidence_case / "stdout.bin").write_bytes(execution.stdout)
        (evidence_case / "stderr.bin").write_bytes(execution.stderr)
        model_dir = case_root / "fakebin/model"
        fake_result = model.finalize(model_dir)
        assertion_report = model.evaluate_assertions(
            semantic["assertions"], model.load_state(model_dir), {"case": case_root, "evidence": evidence_case}
        )
        assertions = assertion_report["results"]
        shutil.copyfile(str(model_dir / "state.json"), str(evidence_case / "state.json"))
        shutil.copyfile(str(model_dir / "calls.jsonl"), str(evidence_case / "calls.jsonl"))
        shutil.copyfile(str(case_root / "instrumentation/transformation.json"), str(evidence_case / "transformation.json"))
        exit_codes = semantic.get("exit_codes", [0])
        exit_ok = execution.returncode in exit_codes
        execution_complete = (
            execution.execution_health == containment.COMPLETE
            and fake_result.get("passed") is True
            and all("error" not in item for item in assertions)
        )
        contract_pass = exit_ok and assertion_report["passed"]
        if not execution_complete:
            overall = "HARNESS_FAIL"
            health = "PARTIAL"
        else:
            overall = "PASS" if contract_pass else "FAIL"
            health = "COMPLETE"
        return {
            "vector_id": semantic["vector_id"],
            "binding_id": binding["binding_id"],
            "execution_health": health,
            "contract_verdict": "NOT_REACHED" if health != "COMPLETE" else ("PASS" if contract_pass else "FAIL"),
            "overall_result": overall,
            "exit_code": execution.returncode,
            "expected_exit_codes": exit_codes,
            "exit_assertion_passed": exit_ok,
            "assertions": assertions,
            "fake_commands": fake_result,
            "containment": {
                "adapter": execution.profile.adapter,
                "version": execution.profile.version,
                "source_sha256": execution.profile.source_sha256,
                "profile_sha256": execution.profile.profile_sha256,
                "detail": execution.detail,
                "timed_out": execution.timed_out,
                "cleanup_complete": execution.cleanup_complete,
                "resident_processes": execution.resident_processes,
                "output_limited": execution.output_limited,
            },
            "transformation": transformation,
            "stdout_sha256": _digest(execution.stdout),
            "stderr_sha256": _digest(execution.stderr),
            "finding_id": semantic.get("finding_id") if overall == "FAIL" else None,
        }
    finally:
        shutil.rmtree(case_root, ignore_errors=True)


def validate_concurrency(document):
    if document["mode"] == "single-actor":
        return
    actors = [item["actor_id"] for item in document["actors"]]
    steps = document["schedule"]["steps"]
    step_ids = [item["step_id"] for item in steps]
    barrier_ids = [item["barrier_id"] for item in document["barriers"]]
    signal_ids = [item["signal_id"] for item in document["signals"]]
    order_ids = [item["order_id"] for item in document["partial_orders"]]
    if any(len(items) != len(set(items)) for items in (actors, step_ids, barrier_ids, signal_ids, order_ids)):
        raise RunnerError("duplicate actor, step, barrier, signal, or order identifiers")
    if len(steps) > document["schedule"]["max_steps"]:
        raise RunnerError("schedule exceeds step bound")
    actor_set, step_set, barrier_set = set(actors), set(step_ids), set(barrier_ids)
    for step in steps:
        if step["actor_id"] not in actor_set or not set(step["after_barrier_ids"]) <= barrier_set:
            raise RunnerError("schedule references unknown actor or barrier")
        if step["virtual_time_offset_ms"] > document["schedule"]["max_virtual_time_ms"]:
            raise RunnerError("schedule exceeds virtual-time bound")
    orders = []
    for barrier in document["barriers"]:
        before, after = set(barrier["after_step_ids"]), set(barrier["before_step_ids"])
        if not before <= step_set or not after <= step_set or before & after:
            raise RunnerError("invalid barrier ordering")
        orders.extend((left, right) for left in before for right in after)
    for order in document["partial_orders"]:
        if order["before_step_id"] not in step_set or order["after_step_id"] not in step_set:
            raise RunnerError("partial order references unknown step")
        if order["before_step_id"] == order["after_step_id"]:
            raise RunnerError("partial order contains a cycle")
        orders.append((order["before_step_id"], order["after_step_id"]))
    for signal in document["signals"]:
        if signal["at_step_id"] not in step_set or signal["actor_id"] not in actor_set:
            raise RunnerError("signal references unknown actor or step")
    for linearization in document["allowed_linearizations"]:
        if len(linearization) != len(step_set) or set(linearization) != step_set:
            raise RunnerError("allowed linearization does not cover every step exactly once")
        position = {step_id: index for index, step_id in enumerate(linearization)}
        if any(position[before] >= position[after] for before, after in orders):
            raise RunnerError("allowed linearization violates required ordering")


def load_vector_bundle(repository_root, requested_ids=None):
    project, checks = load_configuration(repository_root)
    index = _load_json(Path(repository_root) / "tests/vectors/vectors.json")
    vector_schema = _load_json(Path(repository_root) / "tests/vectors/schema.json")
    schema.require_valid(index, vector_schema)
    _verify_content_digest(index, "vector index")
    identifiers = [entry["vector_id"] for entry in index["vectors"]]
    if len(identifiers) != len(set(identifiers)):
        raise RunnerError("duplicate semantic vector identifiers")
    if requested_ids:
        known = set(identifiers) | {entry["acceptance_id"] for entry in index["vectors"]}
        unknown = sorted(set(requested_ids) - known)
        if unknown:
            raise RunnerError("unknown vector or acceptance identifiers: %s" % ", ".join(unknown))
    cases = []
    for reference in index["vectors"]:
        if requested_ids and reference["acceptance_id"] not in requested_ids and reference["vector_id"] not in requested_ids:
            continue
        semantic_path = Path(repository_root) / reference["semantic_path"]
        binding_path = Path(repository_root) / reference["bash_binding_path"]
        semantic = _load_json(semantic_path)
        binding = _load_json(binding_path)
        schema.require_valid(semantic, vector_schema)
        schema.require_valid(binding, vector_schema)
        _verify_content_digest(semantic, semantic["vector_id"])
        _verify_content_digest(binding, binding["binding_id"])
        if len(semantic["contracts"]) != len(semantic["assertions"]):
            raise RunnerError("contract/assertion mapping length mismatch: %s" % semantic["vector_id"])
        if len({item["assertion_id"] for item in semantic["contracts"]}) != len(semantic["contracts"]):
            raise RunnerError("duplicate contract assertion identifiers")
        if reference["acceptance_id"] not in semantic["acceptance_ids"] or reference["vector_id"] != semantic["vector_id"]:
            raise RunnerError("vector index acceptance mapping mismatch")
        if binding["arguments"] != semantic["arguments"]:
            raise RunnerError("semantic and Bash argument bindings differ")
        validate_concurrency(semantic["concurrency"])
        if _file_digest(semantic_path) != reference["semantic_sha256"] or _file_digest(binding_path) != reference["bash_binding_sha256"]:
            raise RunnerError("vector file binding mismatch: %s" % reference["vector_id"])
        if binding["vector_id"] != semantic["vector_id"] or binding["vector_sha256"] != semantic["content_sha256"]:
            raise RunnerError("Bash binding references wrong semantic vector")
        cases.append((semantic, binding))
    return project, cases


def characterize(repository_root, evidence_root, requested_ids=None, toolchain_path=None):
    project, cases = load_vector_bundle(repository_root, requested_ids)
    toolchain_path = toolchain_path or Path(repository_root) / "tests/toolchain.json"
    toolchain = _load_json(toolchain_path)
    results = []
    for semantic, binding in cases:
        binding = dict(binding)
        binding["_project_sources"] = project["sources"]
        evidence_case = evidence_root / "cases" / semantic["vector_id"]
        evidence_case.mkdir(mode=0o700, parents=True, exist_ok=False)
        try:
            result = execute_case(repository_root, evidence_case, semantic, binding, toolchain)
        except containment.ContainmentError as error:
            result = {
                "vector_id": semantic["vector_id"],
                "binding_id": binding["binding_id"],
                "execution_health": error.execution_health,
                "contract_verdict": "NOT_REACHED",
                "overall_result": "NOT_RUN" if error.execution_health == "NOT_RUN" else "HARNESS_FAIL",
                "error": type(error).__name__,
            }
        except (instrument.InstrumentationError, model.ModelError, OSError, ValueError) as error:
            result = {
                "vector_id": semantic["vector_id"],
                "binding_id": binding["binding_id"],
                "execution_health": "PARTIAL",
                "contract_verdict": "NOT_REACHED",
                "overall_result": "HARNESS_FAIL",
                "error": type(error).__name__,
            }
        if result.get("overall_result") == "FAIL" and not result.get("finding_id"):
            result["overall_result"] = "HARNESS_FAIL"
            result["error"] = "UnlinkedContractFailure"
        _write_json(evidence_case / "result.json", result)
        results.append(result)
    return results


def _base_record(repository_root, evidence_root, results, suite, runtime_toolchain=None):
    created = _now()
    raw_path = evidence_root / "raw-evidence.json"
    raw = {"suite": suite, "results": results, "artifacts": _evidence_artifacts(evidence_root)}
    raw_digest = _write_json(raw_path, raw)
    record = {
        "schema": "wirevpn.validation-result/1.0" if suite == "validation" else RESULT_SCHEMA,
        "suite": suite,
        "created_at": _iso(created),
        "retention": {"class": "owner-only-seven-days", "expires_at": _iso(created + datetime.timedelta(days=7)), "revalidation": "current"},
        "raw_evidence": {"identity": str(raw_path), "sha256": raw_digest, "artifact_count": len(raw["artifacts"])},
        "dependencies": dependency_digests(repository_root, runtime_toolchain),
        "results": results,
        "evidence_limits": ["deterministic-host-side-synthetic-evidence", "not-live-vpn-validation"],
    }
    if runtime_toolchain is not None:
        record["runtime_toolchain"] = {
            "path": str(Path(runtime_toolchain).resolve(strict=True)),
            "sha256": _file_digest(runtime_toolchain),
        }
    return record


def command_static(repository_root, evidence_root, toolchain_path=None):
    project, checks = load_configuration(repository_root)
    identities = static_gates.verify_source_manifest(repository_root, project)
    payloads = static_gates.verify_embedded_payloads(repository_root, project, identities)
    generated = static_gates.verify_generated_artifacts(repository_root, project, identities)
    toolchain_path = toolchain_path or Path(repository_root) / "tests/toolchain.json"
    toolchain = _load_json(toolchain_path)
    static_gates.verify_bash_syntax(repository_root, project, select_toolchain(toolchain)["bash"]["path"])
    ignore = static_gates.verify_ignore_rules(repository_root)
    documentation = static_gates.documentation_history_inventory(repository_root, project)
    external = static_gates.external_code_inventory(repository_root, project)
    if not documentation["inventory_complete"] or not external["inventory_complete"]:
        raise static_gates.StaticGateError("static inventory is incomplete")
    secret_boundaries = static_gates.secret_boundary_inventory(repository_root, project)
    results = [
        {"check_id": "WVH-01", "execution_health": "COMPLETE", "contract_verdict": "PASS", "overall_result": "PASS", "source_count": len(identities)},
        {"check_id": "WVH-04", "execution_health": "COMPLETE", "contract_verdict": "PASS", "overall_result": "PASS", "payloads": payloads, "generated_artifacts": generated},
        {"check_id": "WVA-19", "execution_health": "COMPLETE", "contract_verdict": "PASS", "overall_result": "PASS", "inventory": secret_boundaries},
        {"check_id": "WVA-20", "execution_health": "COMPLETE", "contract_verdict": "PASS", "overall_result": "PASS", "inventory": documentation},
        {"check_id": "WVA-21", "execution_health": "COMPLETE", "contract_verdict": "PASS", "overall_result": "PASS", "inventory": payloads, "generated_artifacts": generated},
        {"check_id": "WVA-26", "execution_health": "COMPLETE", "contract_verdict": "PASS", "overall_result": "PASS", "inventory": external},
        {"check_id": "WVA-27", "execution_health": "COMPLETE", "contract_verdict": "PASS" if ignore["complete"] else "FAIL", "overall_result": "PASS" if ignore["complete"] else "FAIL", "finding_id": None if ignore["complete"] else "RED-BASH-W1-IGNORE-COVERAGE", "inventory": ignore},
    ]
    record = _base_record(repository_root, evidence_root, results, "static", toolchain_path)
    _write_json(evidence_root / "report.json", record)
    return record


def command_characterize(repository_root, evidence_root, ids=None, toolchain_path=None):
    toolchain_path = toolchain_path or Path(repository_root) / "tests/toolchain.json"
    results = characterize(repository_root, evidence_root, ids, toolchain_path)
    record = _base_record(repository_root, evidence_root, results, "characterization", toolchain_path)
    _write_json(evidence_root / "report.json", record)
    return record


def command_validate(repository_root, evidence_root, ids=None, toolchain_path=None):
    _project, cases = load_vector_bundle(repository_root, ids)
    results = [
        {
            "vector_id": semantic["vector_id"],
            "binding_id": binding["binding_id"],
            "validation_verdict": "PASS",
            "validation_only": True,
        }
        for semantic, binding in cases
    ]
    record = _base_record(repository_root, evidence_root, results, "validation", toolchain_path)
    _write_json(evidence_root / "report.json", record)
    return record


def command_self_test(repository_root, evidence_root, toolchain_path=None):
    import self_test

    load_configuration(repository_root)
    toolchain_path = toolchain_path or Path(repository_root) / "tests/toolchain.json"
    results = self_test.run_checks(toolchain_path)
    record = _base_record(repository_root, evidence_root, results, "self-test", toolchain_path)
    _write_json(evidence_root / "report.json", record)
    return record


def _summary(record):
    counts = {}
    for result in record["results"]:
        verdict = result.get("overall_result", result.get("validation_verdict"))
        counts[verdict] = counts.get(verdict, 0) + 1
    return {"suite": record["suite"], "results": counts, "cases": len(record["results"])}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["static", "validate", "characterize", "self-test", "rebind", "revalidate"])
    parser.add_argument("--repository", default=str(REPOSITORY))
    parser.add_argument("--evidence-root", default=os.environ.get("WIREVPN_EVIDENCE_ROOT"))
    parser.add_argument("--toolchain", default=os.environ.get("WIREVPN_RUNTIME_TOOLCHAIN"))
    parser.add_argument("--id", action="append", dest="ids")
    arguments = parser.parse_args(argv)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise RunnerError("root execution is refused")
    repository = Path(arguments.repository).resolve(strict=True)
    if arguments.command == "rebind":
        rebind(repository)
        print(json.dumps({"rebound": True}, sort_keys=True))
        return 0
    if not arguments.evidence_root:
        raise RunnerError("--evidence-root or WIREVPN_EVIDENCE_ROOT is required")
    evidence = prepare_evidence_root(arguments.evidence_root, repository)
    if arguments.command == "revalidate":
        record = _load_json(evidence / "report.json")
        valid = evidence_is_current(record, repository)
        print(json.dumps({"revalid": valid}, sort_keys=True))
        return 0 if valid else 1
    run_root = evidence / ("run-" + _now().strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12])
    run_root.mkdir(mode=0o700)
    toolchain_path = resolve_toolchain_path(repository, arguments.toolchain)
    if arguments.command == "static":
        record = command_static(repository, run_root, toolchain_path)
    elif arguments.command == "self-test":
        record = command_self_test(repository, run_root, toolchain_path)
    elif arguments.command == "validate":
        record = command_validate(repository, run_root, arguments.ids, toolchain_path)
    else:
        record = command_characterize(repository, run_root, arguments.ids, toolchain_path)
    summary = _summary(record)
    print(json.dumps(summary, sort_keys=True))
    if any(result.get("overall_result") in ("HARNESS_FAIL", "NOT_RUN") for result in record["results"]):
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RunnerError, schema.SchemaValidationError, static_gates.StaticGateError) as error:
        print("HARNESS_FAIL: %s" % error, file=sys.stderr)
        sys.exit(2)
