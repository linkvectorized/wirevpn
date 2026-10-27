#!/usr/bin/env python3
"""Deterministic, synthetic-only state and file model for WireVPN fake commands.

A case directory contains expectations.json, state.json, calls.jsonl, and lock.
Expectations are ordered and use exact argv lists, including argv[0].  Output
and input fields accept text directly; stdout/stderr and file content also
accept {"base64": ...} or {"hex": ...} for scripted arbitrary bytes.
"""

import base64
import binascii
import contextlib
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile


EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_CALLS_BYTES = 8 * 1024 * 1024
MAX_STDIN_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_CALLS = 10000
HARNESS_ERROR_EXIT = 97


class ModelError(ValueError):
    """A malformed case, unsafe effect, or inconsistent synthetic log."""


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ModelError("duplicate JSON key: %r" % key)
        result[key] = value
    return result


def _invalid_constant(value):
    raise ModelError("non-finite JSON number: %s" % value)


def json_bytes(value):
    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return (text + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ModelError("value is not strict JSON: %s" % exc)


def _utf8_bytes(value, label):
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ModelError("%s is not valid Unicode text: %s" % (label, exc))


def parse_json(data):
    if not isinstance(data, bytes):
        raise ModelError("JSON input must be bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ModelError("JSON is not valid UTF-8: %s" % exc)
    try:
        return json.loads(
            text,
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_invalid_constant,
        )
    except ModelError:
        raise
    except (TypeError, ValueError) as exc:
        raise ModelError("malformed JSON: %s" % exc)


def _open_regular(path, flags, mode=0o600):
    path = os.fspath(path)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as exc:
        raise ModelError("cannot open %s: %s" % (path, exc))
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        os.close(descriptor)
        raise ModelError("not a regular file: %s" % path)
    return descriptor


def read_bounded(path, maximum=MAX_FILE_BYTES):
    if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 0:
        raise ModelError("invalid byte bound")
    try:
        descriptor = _open_regular(path, os.O_RDONLY)
    except ModelError:
        raise
    with os.fdopen(descriptor, "rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ModelError("file exceeds %d bytes: %s" % (maximum, path))
    return data


def load_json(path, maximum=MAX_JSON_BYTES):
    return parse_json(read_bounded(path, maximum))


def sha256_bytes(data):
    if not isinstance(data, bytes):
        raise ModelError("SHA-256 input must be bytes")
    return hashlib.sha256(data).hexdigest()


def sha256_file(path, maximum=MAX_FILE_BYTES):
    return sha256_bytes(read_bounded(path, maximum))


def _fsync_directory(path):
    descriptor = os.open(os.fspath(path), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_bytes(path, data, mode=0o600):
    if not isinstance(data, bytes):
        raise ModelError("atomic write input must be bytes")
    if len(data) > MAX_JSON_BYTES:
        raise ModelError("atomic write exceeds byte bound")
    destination = Path(path)
    parent = destination.parent
    if not parent.is_dir() or parent.is_symlink():
        raise ModelError("atomic write parent is not a real directory")
    if destination.is_symlink():
        raise ModelError("atomic write destination is a symlink")
    descriptor = None
    temporary = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix="." + destination.name + ".", dir=str(parent)
        )
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, str(destination))
        temporary = None
        _fsync_directory(parent)
    except (OSError, ModelError) as exc:
        if isinstance(exc, ModelError):
            raise
        raise ModelError("atomic write failed for %s: %s" % (destination, exc))
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def atomic_write_json(path, value, mode=0o600):
    atomic_write_bytes(path, json_bytes(value), mode)


@contextlib.contextmanager
def file_lock(path):
    descriptor = _open_regular(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        with os.fdopen(descriptor, "r+b", closefd=True) as stream:
            descriptor = None
            yield stream
    finally:
        if descriptor is not None:
            os.close(descriptor)


def default_state():
    return {
        "tunnel": {},
        "dns": {},
        "ipv6": {},
        "services": {},
        "peers": {},
        "packages": {},
        "virtual_time": {"seconds": 0},
    }


def _merge_state(base, overlay):
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge_state(base[key], value)
        else:
            base[key] = copy.deepcopy(value)


def _path_parts(path):
    if not isinstance(path, str) or not path:
        raise ModelError("dotted state path must be a nonempty string")
    parts = path.split(".")
    for part in parts:
        if not part or any(
            not (character.isascii() and (character.isalnum() or character in "_-"))
            for character in part
        ):
            raise ModelError("unsafe dotted state path: %r" % path)
    return parts


def get_dotted(state, path):
    current = state
    for part in _path_parts(path):
        if not isinstance(current, dict) or part not in current:
            raise ModelError("missing state path: %s" % path)
        current = current[part]
    return current


def set_dotted(state, path, value):
    if not isinstance(state, dict):
        raise ModelError("state must be a JSON object")
    parts = _path_parts(path)
    current = state
    for part in parts[:-1]:
        if part not in current:
            current[part] = {}
        elif not isinstance(current[part], dict):
            raise ModelError("state path crosses a scalar: %s" % path)
        current = current[part]
    current[parts[-1]] = copy.deepcopy(value)
    json_bytes(state)


def delete_dotted(state, path):
    parts = _path_parts(path)
    current = state
    for part in parts[:-1]:
        if not isinstance(current, dict) or part not in current:
            raise ModelError("missing state path: %s" % path)
        current = current[part]
    if not isinstance(current, dict) or parts[-1] not in current:
        raise ModelError("missing state path: %s" % path)
    del current[parts[-1]]


def increment_dotted(state, path, amount=1):
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        raise ModelError("state increment must be a finite JSON number")
    current = get_dotted(state, path)
    if isinstance(current, bool) or not isinstance(current, (int, float)):
        raise ModelError("state increment target is not numeric: %s" % path)
    result = current + amount
    json_bytes(result)
    set_dotted(state, path, result)


def apply_state_operations(state, operations):
    if not isinstance(operations, list):
        raise ModelError("state operations must be a list")
    updated = copy.deepcopy(state)
    for operation in operations:
        if not isinstance(operation, dict):
            raise ModelError("state operation must be an object")
        kind = operation.get("op")
        if kind == "set":
            if set(operation) != {"op", "path", "value"}:
                raise ModelError("set operation requires op, path, and value")
            set_dotted(updated, operation["path"], operation["value"])
        elif kind == "delete":
            if set(operation) != {"op", "path"}:
                raise ModelError("delete operation requires op and path")
            delete_dotted(updated, operation["path"])
        elif kind == "increment":
            if set(operation) not in ({"op", "path", "by"}, {"op", "path"}):
                raise ModelError("increment operation requires op, path, and optional by")
            increment_dotted(updated, operation["path"], operation.get("by", 1))
        else:
            raise ModelError("unknown state operation: %r" % kind)
    return updated


def _integer(value, label, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ModelError("%s must be an integer" % label)
    if value < minimum or value > maximum:
        raise ModelError("%s is outside its allowed range" % label)
    return value


def _scripted_bytes(value, label, maximum=MAX_OUTPUT_BYTES):
    if isinstance(value, str):
        data = _utf8_bytes(value, label)
    elif isinstance(value, dict) and set(value) == {"text"} and isinstance(value["text"], str):
        data = _utf8_bytes(value["text"], label)
    elif isinstance(value, dict) and set(value) == {"base64"} and isinstance(value["base64"], str):
        try:
            data = base64.b64decode(value["base64"].encode("ascii"), validate=True)
        except (UnicodeEncodeError, binascii.Error) as exc:
            raise ModelError("invalid base64 in %s: %s" % (label, exc))
    elif isinstance(value, dict) and set(value) == {"hex"} and isinstance(value["hex"], str):
        text = value["hex"]
        if len(text) % 2 or any(character not in "0123456789abcdefABCDEF" for character in text):
            raise ModelError("invalid hexadecimal bytes in %s" % label)
        try:
            data = binascii.unhexlify(text.encode("ascii"))
        except (UnicodeEncodeError, binascii.Error) as exc:
            raise ModelError("invalid hexadecimal bytes in %s: %s" % (label, exc))
    else:
        raise ModelError("%s must be text, base64, or hex" % label)
    if len(data) > maximum:
        raise ModelError("%s exceeds %d bytes" % (label, maximum))
    return data


def _validate_argv(value):
    if not isinstance(value, list) or not value:
        raise ModelError("argv must be a nonempty list")
    for argument in value:
        if not isinstance(argument, str) or "\x00" in argument:
            raise ModelError("argv entries must be strings without NUL")
        _utf8_bytes(argument, "argv entry")
    if not value[0] or "/" in value[0] or value[0] in (".", ".."):
        raise ModelError("argv[0] must be a command basename")


def normalize_roots(roots):
    if not isinstance(roots, dict):
        raise ModelError("synthetic roots must be an object")
    normalized = {}
    for name, value in roots.items():
        if (
            not isinstance(name, str)
            or not name
            or any(not (c.isascii() and (c.isalnum() or c in "_-")) for c in name)
        ):
            raise ModelError("invalid synthetic root name: %r" % name)
        try:
            value = os.fspath(value)
        except TypeError:
            raise ModelError("invalid synthetic root path for %s" % name)
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ModelError("invalid synthetic root path for %s" % name)
        _utf8_bytes(value, "synthetic root path")
        candidate = Path(value)
        if not candidate.is_absolute():
            raise ModelError("synthetic root must be absolute: %s" % name)
        try:
            if candidate.is_symlink() or not candidate.is_dir():
                raise ModelError("synthetic root is not a real directory: %s" % name)
            resolved = candidate.resolve(strict=True)
            if resolved == Path("/"):
                raise ModelError("the filesystem root cannot be a synthetic root")
        except OSError as exc:
            raise ModelError("cannot resolve synthetic root %s: %s" % (name, exc))
        normalized[name] = resolved
    return normalized


def _relative_effect_path(root, value):
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ModelError("invalid effect path")
    _utf8_bytes(value, "effect path")
    raw_parts = value.split("/")
    candidate = PurePosixPath(value)
    if candidate.is_absolute():
        # Only the leading slash produces an empty component; all other empty,
        # current-directory, and parent-directory components are rejected.
        if raw_parts[0] != "" or any(part in ("", ".", "..") for part in raw_parts[1:]):
            raise ModelError("absolute effect path contains traversal or empty components")
        try:
            relative = Path(value).relative_to(str(root))
        except ValueError:
            raise ModelError("absolute effect path escapes its synthetic root")
        if not str(relative) or str(relative) == ".":
            raise ModelError("effect path must identify an entry below its root")
        parts = relative.parts
    else:
        if any(part in ("", ".", "..") for part in raw_parts):
            raise ModelError("effect path contains traversal or empty components")
        parts = candidate.parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ModelError("unsafe effect path")
    return parts


def safe_effect_path(roots, root_name, value, must_exist=False, allow_missing=False):
    if root_name not in roots:
        raise ModelError("undeclared synthetic root: %r" % root_name)
    root = roots[root_name]
    parts = _relative_effect_path(root, value)
    current = root
    for index, part in enumerate(parts):
        current = current / part
        try:
            info = os.lstat(str(current))
        except FileNotFoundError:
            if must_exist or (not allow_missing and index != len(parts) - 1):
                raise ModelError("effect path does not exist: %s" % value)
            break
        except OSError as exc:
            raise ModelError("cannot inspect effect path %s: %s" % (value, exc))
        if stat.S_ISLNK(info.st_mode):
            raise ModelError("symlink in effect path: %s" % value)
        if index != len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise ModelError("non-directory parent in effect path: %s" % value)
    return root.joinpath(*parts)


def _validate_effect(effect, roots):
    if not isinstance(effect, dict):
        raise ModelError("file effect must be an object")
    kind = effect.get("op")
    common = {"op", "root", "path"}
    if kind == "write":
        allowed = common | {"content", "from_stdin", "mode", "append"}
        if not set(effect) <= allowed or not common <= set(effect):
            raise ModelError("malformed write effect")
        if ("content" in effect) == bool(effect.get("from_stdin", False)):
            raise ModelError("write effect needs exactly one content source")
        if "from_stdin" in effect and not isinstance(effect["from_stdin"], bool):
            raise ModelError("from_stdin must be Boolean")
        if "content" in effect:
            _scripted_bytes(effect["content"], "write content", MAX_FILE_BYTES)
        if "mode" in effect:
            _integer(effect["mode"], "file mode", 0, 0o777)
        if "append" in effect and not isinstance(effect["append"], bool):
            raise ModelError("append must be Boolean")
    elif kind == "mkdir":
        allowed = common | {"mode", "parents"}
        if not set(effect) <= allowed or not common <= set(effect):
            raise ModelError("malformed mkdir effect")
        if "mode" in effect:
            _integer(effect["mode"], "directory mode", 0, 0o777)
        if "parents" in effect and not isinstance(effect["parents"], bool):
            raise ModelError("parents must be Boolean")
    elif kind == "remove":
        allowed = common | {"recursive", "must_exist"}
        if not set(effect) <= allowed or not common <= set(effect):
            raise ModelError("malformed remove effect")
        for name in ("recursive", "must_exist"):
            if name in effect and not isinstance(effect[name], bool):
                raise ModelError("%s must be Boolean" % name)
    elif kind == "copy":
        required = {"op", "source_root", "source_path", "destination_root", "destination_path"}
        if not set(effect) <= required | {"mode"} or not required <= set(effect):
            raise ModelError("malformed copy effect")
        if "mode" in effect:
            _integer(effect["mode"], "file mode", 0, 0o777)
    else:
        raise ModelError("unknown file effect: %r" % kind)


def validate_case(document):
    if not isinstance(document, dict):
        raise ModelError("case must be a JSON object")
    allowed = {"version", "roots", "expectations"}
    if not set(document) <= allowed or "expectations" not in document:
        raise ModelError("case requires expectations and permits only version, roots, expectations")
    if "version" in document and document["version"] != "wirevpn-fake-case/1.0":
        raise ModelError("unsupported fake case version")
    roots = normalize_roots(document.get("roots", {}))
    raw_expectations = document["expectations"]
    if not isinstance(raw_expectations, list) or len(raw_expectations) > MAX_CALLS:
        raise ModelError("expectations must be a bounded list")
    expectations = []
    for index, raw in enumerate(raw_expectations):
        if not isinstance(raw, dict):
            raise ModelError("expectation %d is not an object" % index)
        required = {"argv", "exit", "stdout", "stderr"}
        allowed_expectation = required | {"stdin", "state", "effects"}
        if not set(raw) <= allowed_expectation or not required <= set(raw):
            raise ModelError("expectation %d has missing or unknown fields" % index)
        _validate_argv(raw["argv"])
        exit_status = _integer(raw["exit"], "exit", 0, 255)
        stdout = _scripted_bytes(raw["stdout"], "stdout")
        stderr = _scripted_bytes(raw["stderr"], "stderr")
        stdin = raw.get("stdin", {"size": 0, "sha256": EMPTY_SHA256})
        if not isinstance(stdin, dict) or set(stdin) != {"size", "sha256"}:
            raise ModelError("stdin expectation requires size and sha256")
        _integer(stdin["size"], "stdin size", 0, MAX_STDIN_BYTES)
        if (
            not isinstance(stdin["sha256"], str)
            or len(stdin["sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in stdin["sha256"])
        ):
            raise ModelError("stdin sha256 must be lowercase SHA-256")
        operations = raw.get("state", [])
        if not isinstance(operations, list):
            raise ModelError("state must be a list of operations")
        # Validate operation shapes here; path existence and value types are
        # checked against the actual current state when the call executes.
        for operation in operations:
            if not isinstance(operation, dict) or operation.get("op") not in ("set", "delete", "increment"):
                raise ModelError("invalid state operation in expectation %d" % index)
            if operation["op"] == "set" and set(operation) != {"op", "path", "value"}:
                raise ModelError("malformed state set")
            if operation["op"] == "delete" and set(operation) != {"op", "path"}:
                raise ModelError("malformed state delete")
            if operation["op"] == "increment" and set(operation) not in (
                {"op", "path"}, {"op", "path", "by"}
            ):
                raise ModelError("malformed state increment")
            _path_parts(operation["path"])
            if operation["op"] == "increment":
                amount = operation.get("by", 1)
                if isinstance(amount, bool) or not isinstance(amount, (int, float)):
                    raise ModelError("invalid state increment")
                json_bytes(amount)
            if operation["op"] == "set":
                json_bytes(operation["value"])
        effects = raw.get("effects", [])
        if not isinstance(effects, list):
            raise ModelError("effects must be a list")
        for effect in effects:
            _validate_effect(effect, roots)
            # At load time check only lexical containment. Existence is checked
            # when the ordered call executes, after earlier effects have run.
            if effect["op"] == "copy":
                for root_name, path_name in (
                    (effect["source_root"], effect["source_path"]),
                    (effect["destination_root"], effect["destination_path"]),
                ):
                    if root_name not in roots:
                        raise ModelError("undeclared synthetic root: %r" % root_name)
                    _relative_effect_path(roots[root_name], path_name)
            else:
                if effect["root"] not in roots:
                    raise ModelError("undeclared synthetic root: %r" % effect["root"])
                _relative_effect_path(roots[effect["root"]], effect["path"])
        expectations.append({
            "argv": list(raw["argv"]),
            "exit": exit_status,
            "stdout": stdout,
            "stderr": stderr,
            "stdin": dict(stdin),
            "state": copy.deepcopy(operations),
            "effects": copy.deepcopy(effects),
        })
    return {"roots": roots, "expectations": expectations}


def initialize_case(model_dir, expectations, roots, initial_state=None):
    model_dir = Path(model_dir)
    if not model_dir.is_dir() or model_dir.is_symlink():
        raise ModelError("case model directory must be a real directory")
    if not isinstance(roots, dict):
        raise ModelError("synthetic roots must be an object")
    document = {
        "version": "wirevpn-fake-case/1.0",
        "roots": {name: os.fspath(path) for name, path in roots.items()},
        "expectations": expectations,
    }
    validate_case(document)
    state = default_state()
    if initial_state is not None:
        if not isinstance(initial_state, dict):
            raise ModelError("initial state must be an object")
        _merge_state(state, initial_state)
        json_bytes(state)
    calls = model_dir / "calls.jsonl"
    if calls.is_symlink():
        raise ModelError("call log is a symlink")
    if calls.exists() and calls.stat().st_size:
        raise ModelError("refusing to reset a nonempty call log")
    atomic_write_json(model_dir / "expectations.json", document)
    atomic_write_json(model_dir / "state.json", state)
    atomic_write_bytes(calls, b"")
    lock = model_dir / "lock"
    if lock.is_symlink():
        raise ModelError("case lock is a symlink")
    descriptor = _open_regular(lock, os.O_WRONLY | os.O_CREAT, 0o600)
    os.close(descriptor)


def load_case(model_dir):
    return validate_case(load_json(Path(model_dir) / "expectations.json"))


def load_state(model_dir):
    state = load_json(Path(model_dir) / "state.json")
    if not isinstance(state, dict):
        raise ModelError("state.json must contain an object")
    return state


def _validate_log_record(record, sequence):
    if not isinstance(record, dict):
        raise ModelError("call record is not an object")
    required = {"sequence", "expectation", "status", "argv", "stdin"}
    if not set(record) <= required | {"error"} or not required <= set(record):
        raise ModelError("call record has missing or unknown fields")
    if record["sequence"] != sequence or isinstance(record["sequence"], bool):
        raise ModelError("call record sequence mismatch")
    if record["status"] not in ("matched", "unexpected", "extra", "stdin_mismatch", "error"):
        raise ModelError("unknown call record status")
    if record["status"] == "matched":
        if isinstance(record["expectation"], bool) or not isinstance(record["expectation"], int):
            raise ModelError("matched call lacks expectation index")
        if "error" in record:
            raise ModelError("matched call contains an error")
    else:
        if record["expectation"] is not None or not isinstance(record.get("error"), str):
            raise ModelError("failed call record is malformed")
        if len(record["error"]) > 4096:
            raise ModelError("call record error is too long")
    _validate_argv(record["argv"])
    stdin = record["stdin"]
    if not isinstance(stdin, dict) or set(stdin) != {"size", "sha256", "base64"}:
        raise ModelError("call stdin record is malformed")
    _integer(stdin["size"], "logged stdin size", 0, MAX_STDIN_BYTES)
    data = _scripted_bytes({"base64": stdin["base64"]}, "logged stdin", MAX_STDIN_BYTES)
    if len(data) != stdin["size"] or sha256_bytes(data) != stdin["sha256"]:
        raise ModelError("call stdin identity mismatch")


def load_calls(model_dir):
    path = Path(model_dir) / "calls.jsonl"
    data = read_bounded(path, MAX_CALLS_BYTES)
    if not data:
        return []
    if not data.endswith(b"\n"):
        raise ModelError("call log has a truncated final line")
    lines = data.splitlines()
    if len(lines) > MAX_CALLS:
        raise ModelError("call log contains too many records")
    records = []
    matched = 0
    failed_seen = False
    for sequence, line in enumerate(lines):
        if not line.strip():
            raise ModelError("call log contains an empty line")
        record = parse_json(line)
        _validate_log_record(record, sequence)
        if failed_seen:
            raise ModelError("call log continues after a failed call")
        if record["status"] == "matched":
            if record["expectation"] != matched:
                raise ModelError("matched call order is inconsistent")
            matched += 1
        else:
            failed_seen = True
        records.append(record)
    return records


def append_call(model_dir, record):
    data = json_bytes(record)
    path = Path(model_dir) / "calls.jsonl"
    if path.is_symlink():
        raise ModelError("call log is a symlink")
    descriptor = _open_regular(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        if os.fstat(descriptor).st_size + len(data) > MAX_CALLS_BYTES:
            raise ModelError("call log byte bound exceeded")
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ModelError("short call log write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _mkdir_effect(path, effect):
    parents = effect.get("parents", False)
    mode = effect.get("mode", 0o700)
    if path.exists():
        if not path.is_dir() or path.is_symlink():
            raise ModelError("mkdir destination is not a real directory")
        return
    if parents:
        path.mkdir(mode=mode, parents=True, exist_ok=False)
    else:
        path.mkdir(mode=mode)


def _remove_tree(path):
    info = os.lstat(str(path))
    if stat.S_ISLNK(info.st_mode):
        raise ModelError("refusing to remove a symlink")
    if stat.S_ISDIR(info.st_mode):
        with os.scandir(str(path)) as entries:
            children = list(entries)
        for child in children:
            _remove_tree(Path(child.path))
        os.rmdir(str(path))
    else:
        os.unlink(str(path))


def apply_file_effects(effects, roots, stdin_data):
    roots = normalize_roots(roots)
    for effect in effects:
        kind = effect["op"]
        if kind == "copy":
            source = safe_effect_path(roots, effect["source_root"], effect["source_path"], True)
            destination = safe_effect_path(
                roots, effect["destination_root"], effect["destination_path"]
            )
            info = os.lstat(str(source))
            if not stat.S_ISREG(info.st_mode):
                raise ModelError("copy source is not a regular file")
            data = read_bounded(source, MAX_FILE_BYTES)
            mode = effect.get("mode", stat.S_IMODE(info.st_mode) & 0o777)
            _write_file(destination, data, mode, False)
            continue
        path = safe_effect_path(
            roots,
            effect["root"],
            effect["path"],
            kind == "remove" and effect.get("must_exist", True),
            allow_missing=(
                kind == "mkdir" and effect.get("parents", False)
            ) or (
                kind == "remove" and not effect.get("must_exist", True)
            ),
        )
        if kind == "write":
            if effect.get("from_stdin", False):
                data = stdin_data
            else:
                data = _scripted_bytes(effect["content"], "write content", MAX_FILE_BYTES)
            _write_file(path, data, effect.get("mode", 0o600), effect.get("append", False))
        elif kind == "mkdir":
            _mkdir_effect(path, effect)
        elif kind == "remove":
            if not path.exists() and not path.is_symlink():
                if effect.get("must_exist", True):
                    raise ModelError("remove target is missing")
                continue
            if path.is_dir() and not effect.get("recursive", False):
                raise ModelError("recursive remove was not declared")
            _remove_tree(path)
        else:
            raise ModelError("unknown file effect")


def _write_file(path, data, mode, append):
    if path.is_symlink():
        raise ModelError("write destination is a symlink")
    if path.exists() and not path.is_file():
        raise ModelError("write destination is not a regular file")
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    flags |= os.O_APPEND if append else os.O_TRUNC
    descriptor = os.open(str(path), flags, mode)
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ModelError("short synthetic file write")
            view = view[written:]
        os.fsync(descriptor)
    except OSError as exc:
        raise ModelError("synthetic file write failed: %s" % exc)
    finally:
        os.close(descriptor)


def _json_equal(left, right):
    return json_bytes(left) == json_bytes(right)


def _assertion_result(index, assertion, passed, actual=None, error=None):
    result = {
        "index": index,
        "kind": assertion.get("kind") if isinstance(assertion, dict) else None,
        "passed": bool(passed),
    }
    if actual is not None:
        result["actual"] = actual
    if error is not None:
        result["error"] = error
    return result


def evaluate_assertions(assertions, state, roots):
    if not isinstance(assertions, list):
        raise ModelError("assertions must be a list")
    roots = normalize_roots(roots)
    results = []
    for index, assertion in enumerate(assertions):
        try:
            if not isinstance(assertion, dict) or "kind" not in assertion:
                raise ModelError("assertion must be an object with kind")
            kind = assertion["kind"]
            if kind in ("state_equals", "state_not_equals"):
                if set(assertion) != {"kind", "path", "expected"}:
                    raise ModelError("state assertion requires kind, path, expected")
                actual = get_dotted(state, assertion["path"])
                equal = _json_equal(actual, assertion["expected"])
                passed = equal if kind == "state_equals" else not equal
                results.append(_assertion_result(index, assertion, passed, actual=actual))
                continue
            file_kinds = {
                "file_exists", "file_absent", "file_hash", "file_sha256", "file_text", "file_mode"
            }
            if kind not in file_kinds:
                raise ModelError("unknown assertion kind: %r" % kind)
            required = {"kind", "root", "path"}
            if kind not in ("file_exists", "file_absent"):
                required.add("expected")
            if set(assertion) != required:
                raise ModelError("file assertion has missing or unknown fields")
            path = safe_effect_path(
                roots, assertion["root"], assertion["path"], False, allow_missing=True
            )
            exists = path.exists()
            if exists and path.is_symlink():
                raise ModelError("assertion path is a symlink")
            if kind == "file_absent":
                results.append(_assertion_result(index, assertion, not exists, actual=exists))
            elif kind == "file_exists":
                passed = exists and path.is_file()
                results.append(_assertion_result(index, assertion, passed, actual=passed))
            elif not exists or not path.is_file():
                results.append(_assertion_result(index, assertion, False, error="file is absent"))
            elif kind in ("file_hash", "file_sha256"):
                expected = assertion["expected"]
                if not isinstance(expected, str) or len(expected) != 64:
                    raise ModelError("file hash assertion requires SHA-256")
                actual = sha256_file(path)
                results.append(_assertion_result(index, assertion, actual == expected, actual=actual))
            elif kind == "file_text":
                expected = assertion["expected"]
                if not isinstance(expected, str):
                    raise ModelError("file text expectation must be a string")
                try:
                    actual = read_bounded(path).decode("utf-8")
                except UnicodeDecodeError:
                    results.append(_assertion_result(index, assertion, False, error="file is not UTF-8"))
                else:
                    results.append(_assertion_result(index, assertion, actual == expected, actual=actual))
            elif kind == "file_mode":
                expected = _integer(assertion["expected"], "expected file mode", 0, 0o7777)
                actual = stat.S_IMODE(os.lstat(str(path)).st_mode)
                results.append(_assertion_result(index, assertion, actual == expected, actual=actual))
        except (ModelError, OSError) as exc:
            results.append(_assertion_result(index, assertion, False, error=str(exc)))
    passed = all(result["passed"] for result in results)
    return {"passed": passed, "status": "PASS" if passed else "FAIL", "results": results}


def install_fakebin(fakebin_dir, command_names, python_path):
    """Install fresh executable copies and the runtime model in fakebin/model."""
    if isinstance(command_names, str):
        raise ModelError("command_names must be an iterable of basenames")
    names = list(command_names)
    if not names or len(names) > 256:
        raise ModelError("command names must be nonempty and bounded")
    for name in names:
        if (
            not isinstance(name, str)
            or not name
            or name in (".", "..", "model")
            or "/" in name
            or "\\" in name
            or "\x00" in name
            or any(not (c.isascii() and (c.isalnum() or c in "._+-")) for c in name)
        ):
            raise ModelError("invalid fake command basename: %r" % name)
    if len(set(names)) != len(names):
        raise ModelError("command names must be unique")
    if not isinstance(python_path, str) or not python_path.startswith("/"):
        raise ModelError("python_path must be an absolute fixed path")
    if any(c.isspace() for c in python_path) or "\x00" in python_path:
        raise ModelError("python_path cannot contain whitespace or NUL")
    interpreter = Path(python_path)
    try:
        interpreter = interpreter.resolve(strict=True)
    except OSError as exc:
        raise ModelError("cannot resolve fixed Python interpreter: %s" % exc)
    if not interpreter.is_file() or not os.access(str(interpreter), os.X_OK):
        raise ModelError("fixed Python interpreter is not an executable file")
    shebang = "#!" + str(interpreter)
    if len(shebang.encode("utf-8")) > 127:
        raise ModelError("Python shebang exceeds the portable kernel limit")

    source = Path(__file__).with_name("fakebin.py")
    source_data = read_bounded(source, MAX_FILE_BYTES)
    first_line, separator, body = source_data.partition(b"\n")
    if not separator or not first_line.startswith(b"#!"):
        raise ModelError("fakebin.py lacks its install-time shebang")
    installed_source = shebang.encode("utf-8") + b"\n" + body

    destination = Path(fakebin_dir)
    if destination.is_symlink():
        raise ModelError("fakebin directory must not be a symlink")
    if destination.exists():
        if not destination.is_dir():
            raise ModelError("fakebin destination is not a directory")
        if any(destination.iterdir()):
            raise ModelError("fakebin destination must be fresh and empty")
    else:
        try:
            destination.mkdir(mode=0o700, parents=False)
        except OSError as exc:
            raise ModelError("cannot create fakebin directory: %s" % exc)
    model_dir = destination / "model"
    model_dir.mkdir(mode=0o700)
    model_source = read_bounded(Path(__file__), MAX_FILE_BYTES)
    _write_file(model_dir / "model.py", model_source, 0o600, False)
    installed = {}
    for name in names:
        path = destination / name
        _write_file(path, installed_source, 0o700, False)
        installed[name] = path
    return installed


def finalize_case(model_dir, assertions=None):
    failures = []
    missing = []
    extra = []
    matched = 0
    expected = None
    case = None
    state = None
    try:
        case = load_case(model_dir)
        expected = len(case["expectations"])
    except (ModelError, OSError) as exc:
        failures.append({"component": "expectations", "error": str(exc)})
    try:
        state = load_state(model_dir)
    except (ModelError, OSError) as exc:
        failures.append({"component": "state", "error": str(exc)})
    try:
        records = load_calls(model_dir)
        matched = sum(1 for record in records if record["status"] == "matched")
        for record in records:
            if record["status"] != "matched":
                failures.append({
                    "component": "call",
                    "sequence": record["sequence"],
                    "status": record["status"],
                    "error": record["error"],
                })
            if record["status"] == "extra":
                extra.append(record["sequence"])
    except (ModelError, OSError) as exc:
        records = []
        failures.append({"component": "calls", "error": str(exc)})
    if expected is not None:
        missing = list(range(matched, expected))
        if missing:
            failures.append({"component": "missing", "expectations": missing})
    assertion_result = None
    if assertions is not None:
        if case is None or state is None:
            assertion_result = {
                "passed": False,
                "status": "FAIL",
                "results": [],
                "error": "case or state unavailable",
            }
        else:
            try:
                assertion_result = evaluate_assertions(assertions, state, case["roots"])
            except (ModelError, OSError) as exc:
                assertion_result = {
                    "passed": False,
                    "status": "FAIL",
                    "results": [],
                    "error": str(exc),
                }
        if not assertion_result["passed"]:
            failures.append({"component": "assertions", "error": "semantic assertion failure"})
    passed = not failures
    result = {
        "passed": passed,
        "status": "PASS" if passed else "FAIL",
        "expected": expected,
        "matched": matched,
        "missing": missing,
        "extra": extra,
        "failures": failures,
    }
    if assertion_result is not None:
        result["assertions"] = assertion_result
    return result


def finalize(model_dir, assertions=None):
    return finalize_case(model_dir, assertions)
