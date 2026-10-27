#!/usr/bin/env python3
"""One exact-argv fake command; copied under each synthetic command name."""

import base64
import os
from pathlib import Path
import sys


# The host installer replaces the shebang and copies model.py beside the case
# data in fakebin/model.  No command dispatch, sockets, or elevation live here.
_EXECUTABLE = Path(os.path.abspath(__file__))
_MODEL_DIR = _EXECUTABLE.parent / "model"
sys.dont_write_bytecode = True
sys.path.insert(0, str(_MODEL_DIR))

import model  # noqa: E402


def _stdin_record(data):
    return {
        "size": len(data),
        "sha256": model.sha256_bytes(data),
        "base64": base64.b64encode(data).decode("ascii"),
    }


def _record(sequence, expectation, status, argv, stdin_data, error=None):
    result = {
        "sequence": sequence,
        "expectation": expectation,
        "status": status,
        "argv": argv,
        "stdin": _stdin_record(stdin_data),
    }
    if error is not None:
        result["error"] = error[:4096]
    return result


def _harness_error(message):
    try:
        sys.stderr.write("fake harness: %s\n" % message[:4096])
        sys.stderr.flush()
    except OSError:
        pass
    return model.HARNESS_ERROR_EXIT


def run():
    command = _EXECUTABLE.name
    argv = [command] + sys.argv[1:]
    try:
        if _EXECUTABLE.is_symlink():
            raise model.ModelError("fake executable must not be a symlink")
        if command == "networksetup":
            # The real command leaves inherited service-list stdin unread.
            stdin_data = b""
        else:
            stdin_data = sys.stdin.buffer.read(model.MAX_STDIN_BYTES + 1)
        if len(stdin_data) > model.MAX_STDIN_BYTES:
            raise model.ModelError("stdin exceeds synthetic byte bound")
        if not _MODEL_DIR.is_dir() or _MODEL_DIR.is_symlink():
            raise model.ModelError("case model directory is missing or unsafe")
    except (model.ModelError, OSError) as exc:
        return _harness_error(str(exc))

    stdout = b""
    stderr = b""
    exit_status = model.HARNESS_ERROR_EXIT
    try:
        with model.file_lock(_MODEL_DIR / "lock"):
            case = model.load_case(_MODEL_DIR)
            records = model.load_calls(_MODEL_DIR)
            matched = sum(1 for item in records if item["status"] == "matched")
            sequence = len(records)
            if matched != len(records):
                return _harness_error("an earlier fake call already failed")
            expectations = case["expectations"]
            if matched >= len(expectations):
                error = "extra call; all %d expectations were already matched" % matched
                model.append_call(
                    _MODEL_DIR, _record(sequence, None, "extra", argv, stdin_data, error)
                )
                return _harness_error(error)
            index = matched
            expectation = expectations[index]
            if argv != expectation["argv"]:
                error = "unexpected argv at expectation %d: expected %r, got %r" % (
                    index, expectation["argv"], argv
                )
                model.append_call(
                    _MODEL_DIR, _record(sequence, None, "unexpected", argv, stdin_data, error)
                )
                return _harness_error(error)
            expected_stdin = expectation["stdin"]
            actual_hash = model.sha256_bytes(stdin_data)
            if len(stdin_data) != expected_stdin["size"] or actual_hash != expected_stdin["sha256"]:
                error = "stdin mismatch at expectation %d: expected size/hash %d/%s, got %d/%s" % (
                    index,
                    expected_stdin["size"],
                    expected_stdin["sha256"],
                    len(stdin_data),
                    actual_hash,
                )
                model.append_call(
                    _MODEL_DIR,
                    _record(sequence, None, "stdin_mismatch", argv, stdin_data, error),
                )
                return _harness_error(error)
            try:
                model.apply_file_effects(expectation["effects"], case["roots"], stdin_data)
                state = model.load_state(_MODEL_DIR)
                updated = model.apply_state_operations(state, expectation["state"])
                model.atomic_write_json(_MODEL_DIR / "state.json", updated)
                model.append_call(
                    _MODEL_DIR, _record(sequence, index, "matched", argv, stdin_data)
                )
            except (model.ModelError, OSError) as exc:
                error = "synthetic effect failed at expectation %d: %s" % (index, exc)
                try:
                    model.append_call(
                        _MODEL_DIR, _record(sequence, None, "error", argv, stdin_data, error)
                    )
                except model.ModelError:
                    pass
                return _harness_error(error)
            stdout = expectation["stdout"]
            stderr = expectation["stderr"]
            exit_status = expectation["exit"]
    except (model.ModelError, OSError) as exc:
        return _harness_error(str(exc))

    try:
        sys.stdout.buffer.write(stdout)
        sys.stdout.buffer.flush()
        sys.stderr.buffer.write(stderr)
        sys.stderr.buffer.flush()
    except BrokenPipeError:
        return model.HARNESS_ERROR_EXIT
    return exit_status


if __name__ == "__main__":
    sys.exit(run())
