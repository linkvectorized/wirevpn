"""Nonprivileged, per-case Darwin containment for the WireVPN test harness.

This module intentionally provides only a Darwin/Seatbelt adapter.  It does not
claim same-user isolation or protection from a malicious operator/kernel.  PATH
shims and transformed commands are instrumentation, never the containment
boundary.

Seatbelt profiles are inherited and nested profiles cannot relax earlier denials.
The managed cleanup contract covers descendants remaining in the created session;
nonprivileged Darwin cannot reliably adopt and reap a hostile descendant that
deliberately detaches into a new session, so harness actors must not do that.
"""

from __future__ import unicode_literals

import dataclasses
import hashlib
import math
import os
import stat

try:
    import pwd
except ImportError:  # Unsupported platforms still import and report NOT_RUN.
    pwd = None
try:
    import resource
except ImportError:
    resource = None
import subprocess
import sys
import tempfile
import time
from typing import Dict, Iterable, Mapping, Optional, Sequence, Tuple


ADAPTER_NAME = "wirevpn-darwin-seatbelt"
ADAPTER_VERSION = "1"
SANDBOX_EXEC = "/usr/bin/sandbox-exec"
PREFLIGHT_EXECUTABLE = "/usr/bin/true"
MAX_TIMEOUT_SECONDS = 300.0
PREFLIGHT_TIMEOUT_SECONDS = 5.0
CLEANUP_TIMEOUT_SECONDS = 3.0
MAX_CAPTURE_BYTES = 4 * 1024 * 1024

COMPLETE = "COMPLETE"
PARTIAL = "PARTIAL"
NOT_RUN = "NOT_RUN"


class ContainmentError(Exception):
    """Base class for errors raised before behavior-case dispatch."""

    execution_health = NOT_RUN


class ContainmentUnavailable(ContainmentError):
    """The required enforced profile is unsupported or cannot be verified."""


class InvalidExecutionRequest(ContainmentError, ValueError):
    """A path, argv, environment, or timeout fails the closed-world contract."""


class RootExecutionRefused(ContainmentError):
    """Real root privileges are never accepted by this adapter."""


class EvidenceSetupError(ContainmentError):
    """Private evidence capture could not be initialized before dispatch."""


@dataclasses.dataclass(frozen=True)
class ProfileIdentity:
    adapter: str
    version: str
    source_sha256: str
    profile_sha256: str


@dataclasses.dataclass(frozen=True)
class ContainmentProfile:
    text: str
    identity: ProfileIdentity


@dataclasses.dataclass(frozen=True)
class ContainmentStatus:
    available: bool
    execution_health: Optional[str]
    reason: Optional[str]
    adapter: str
    version: str
    source_sha256: Optional[str]


@dataclasses.dataclass(frozen=True)
class ExecutionResult:
    execution_health: str
    returncode: Optional[int]
    stdout: bytes
    stderr: bytes
    timed_out: bool
    cleanup_complete: bool
    resident_processes: bool
    output_limited: bool
    profile: ProfileIdentity
    detail: Optional[str] = None


def _path_text(path: object, label: str) -> str:
    try:
        value = os.fspath(path)
    except TypeError:
        raise InvalidExecutionRequest("%s must be a text filesystem path" % label)
    if not isinstance(value, str) or not value:
        raise InvalidExecutionRequest("%s must be a nonempty text path" % label)
    if "\x00" in value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise InvalidExecutionRequest("%s contains unsupported control characters" % label)
    if not os.path.isabs(value):
        raise InvalidExecutionRequest("%s must be absolute" % label)
    normalized = os.path.normpath(value)
    if normalized == os.path.sep:
        raise InvalidExecutionRequest("%s must not be /" % label)
    return normalized


def _has_symlink_component(path: str) -> bool:
    current = os.path.sep
    for component in path.strip(os.path.sep).split(os.path.sep):
        current = os.path.join(current, component)
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(mode):
            return True
    return False


def _canonical_existing_directory(path: object, label: str) -> str:
    normalized = _path_text(path, label)
    if not os.path.isdir(normalized):
        raise InvalidExecutionRequest("%s must be an existing directory" % label)
    if _has_symlink_component(normalized) or os.path.realpath(normalized) != normalized:
        raise InvalidExecutionRequest("%s must not traverse symlinks or aliases" % label)
    return normalized


def _is_within(path: str, ancestor: str) -> bool:
    try:
        return os.path.commonpath([path, ancestor]) == ancestor
    except ValueError:
        return False


def _sbpl_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class DarwinContainment(object):
    """Generate exact Seatbelt profiles and synchronously execute bounded cases."""

    def __init__(self, additional_denied_paths: Iterable[object] = ()) -> None:
        if pwd is None:
            home = os.path.expanduser("~")
        else:
            home = pwd.getpwuid(os.getuid()).pw_dir
        self.real_home = _path_text(home, "real HOME")
        protected = [
            "/etc/wireguard",
            "/opt/AdGuardHome",
            "/Library/LaunchDaemons",
            "/Library/LaunchAgents",
            "/etc/systemd",
            "/lib/systemd/system",
            "/usr/lib/systemd/system",
        ]
        for relative in (
            ".wirevpn",
            ".config/wirevpn",
            ".config/AdGuardHome",
            "Library/Application Support/AdGuardHome",
        ):
            protected.append(os.path.join(self.real_home, relative))
        self._host_denied_paths = tuple(protected)
        extra = []
        for path in additional_denied_paths:
            normalized = _path_text(path, "additional denied path")
            if normalized not in extra:
                extra.append(normalized)
        self._additional_denied_paths = tuple(extra)
        self._repository_root = os.path.realpath(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
        )

    @staticmethod
    def _source_sha256(source_path: Optional[str] = None) -> str:
        path = source_path or os.path.abspath(__file__)
        digest = hashlib.sha256()
        with open(path, "rb") as source_file:
            while True:
                block = source_file.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
        return digest.hexdigest()

    def status(self) -> ContainmentStatus:
        if sys.platform != "darwin":
            return ContainmentStatus(
                False, NOT_RUN, "Darwin Seatbelt is required on this behavior lane",
                ADAPTER_NAME, ADAPTER_VERSION, None,
            )
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return ContainmentStatus(
                False, NOT_RUN, "root execution is refused",
                ADAPTER_NAME, ADAPTER_VERSION, None,
            )
        if not os.path.isfile(SANDBOX_EXEC) or not os.access(SANDBOX_EXEC, os.X_OK):
            return ContainmentStatus(
                False, NOT_RUN, "sandbox-exec is unavailable",
                ADAPTER_NAME, ADAPTER_VERSION, None,
            )
        try:
            source_sha256 = self._source_sha256()
        except (OSError, ValueError):
            return ContainmentStatus(
                False, NOT_RUN, "adapter source identity is unavailable",
                ADAPTER_NAME, ADAPTER_VERSION, None,
            )
        return ContainmentStatus(
            True, None, None, ADAPTER_NAME, ADAPTER_VERSION, source_sha256,
        )

    def _prepare_roots(self, case_root: object, evidence_dir: object) -> Tuple[str, str]:
        case = _canonical_existing_directory(case_root, "case root")
        evidence = _canonical_existing_directory(evidence_dir, "evidence directory")
        if _is_within(case, evidence) or _is_within(evidence, case):
            raise InvalidExecutionRequest("case and evidence roots must be non-overlapping")
        if _is_within(case, self.real_home):
            raise InvalidExecutionRequest("case root must not be inside real HOME")
        for root, label in ((case, "case root"), (evidence, "evidence directory")):
            if root == self.real_home:
                raise InvalidExecutionRequest("%s must not be real HOME" % label)
            if (
                root == self._repository_root
                or _is_within(root, self._repository_root)
                or _is_within(self._repository_root, root)
            ):
                raise InvalidExecutionRequest("%s must not contain or enter the canonical repository" % label)
            for denied in self._additional_denied_paths:
                if _is_within(root, denied):
                    raise InvalidExecutionRequest("%s enters an explicitly denied path" % label)
            for protected in self._host_denied_paths:
                if _is_within(root, protected):
                    raise InvalidExecutionRequest("%s enters a denied host path" % label)
                if _is_within(protected, root):
                    raise InvalidExecutionRequest("%s is broader than a denied host path" % label)
        # Only the explicitly named evidence directory may carve a hole in HOME.
        return case, evidence

    @staticmethod
    def _make_identity(profile_text: str, source_sha256: str) -> ProfileIdentity:
        return ProfileIdentity(
            ADAPTER_NAME,
            ADAPTER_VERSION,
            source_sha256,
            _sha256_bytes(profile_text.encode("utf-8")),
        )

    def profile_for(self, case_root: object, evidence_dir: object) -> ContainmentProfile:
        case, evidence = self._prepare_roots(case_root, evidence_dir)
        lines = [
            "(version 1)",
            "(deny default)",
            "(allow process-fork)",
            "(allow process-exec)",
            "(allow signal (target same-sandbox))",
            "(allow file-read*)",
            "(allow file-map-executable)",
            "(allow sysctl-read)",
            "(deny network*)",
            # Hard links could import a host inode through an approved directory.
            "(deny file-link)",
            "(allow file-write*",
            "  (literal \"/dev/null\")",
            "  (literal \"/dev/stdout\")",
            "  (literal \"/dev/stderr\")",
            "  (subpath %s)" % _sbpl_string(case),
            "  (subpath %s))" % _sbpl_string(evidence),
            "(deny file-read* (subpath %s))" % _sbpl_string(self.real_home),
            "(deny file-write* (subpath %s))" % _sbpl_string(self.real_home),
            # This is the sole HOME exception and is still subject to final denials.
            "(allow file-read* (subpath %s))" % _sbpl_string(evidence),
            "(allow file-write* (subpath %s))" % _sbpl_string(evidence),
        ]
        if _is_within(evidence, self.real_home):
            # Python 3.14 resolves each ancestor even when the leaf is approved.
            current = self.real_home
            lines.append("(allow file-read-metadata (literal %s))" % _sbpl_string(current))
            relative = os.path.relpath(evidence, self.real_home)
            for component in relative.split(os.sep)[:-1]:
                current = os.path.join(current, component)
                lines.append("(allow file-read-metadata (literal %s))" % _sbpl_string(current))
        for denied in self._host_denied_paths + self._additional_denied_paths:
            lines.append("(deny file-read* (subpath %s))" % _sbpl_string(denied))
            lines.append("(deny file-write* (subpath %s))" % _sbpl_string(denied))
        # An exact trailing newline is part of the profile identity.
        text = "\n".join(lines) + "\n"
        try:
            source_sha256 = self._source_sha256()
        except OSError as error:
            raise ContainmentUnavailable(
                "adapter source identity failed before dispatch: %s" % type(error).__name__
            )
        return ContainmentProfile(text, self._make_identity(text, source_sha256))

    @staticmethod
    def _validate_timeout(timeout: object) -> float:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise InvalidExecutionRequest("timeout must be a finite number")
        value = float(timeout)
        if not math.isfinite(value) or value <= 0 or value > MAX_TIMEOUT_SECONDS:
            raise InvalidExecutionRequest(
                "timeout must be greater than zero and at most %s seconds" % MAX_TIMEOUT_SECONDS
            )
        return value

    @staticmethod
    def _validate_argv(argv: Sequence[object]) -> Tuple[str, ...]:
        if isinstance(argv, (str, bytes)) or argv is None:
            raise InvalidExecutionRequest("argv must be a nonempty sequence")
        try:
            arguments = list(argv)
        except TypeError:
            raise InvalidExecutionRequest("argv must be a nonempty sequence")
        if not arguments:
            raise InvalidExecutionRequest("argv must be a nonempty sequence")
        result = []
        for argument in arguments:
            if not isinstance(argument, str) or not argument or "\x00" in argument:
                raise InvalidExecutionRequest("argv entries must be nonempty text without NUL")
            result.append(argument)
        if not os.path.isabs(result[0]):
            raise InvalidExecutionRequest("argv[0] must be an explicit absolute executable")
        if not os.path.isfile(result[0]) or not os.access(result[0], os.X_OK):
            raise InvalidExecutionRequest("argv[0] is not an executable regular file")
        return tuple(result)

    def _validate_cwd(self, cwd: object, case: str, evidence: str) -> str:
        if cwd is None:
            return case
        directory = _canonical_existing_directory(cwd, "working directory")
        if not (_is_within(directory, case) or _is_within(directory, evidence)):
            raise InvalidExecutionRequest("working directory escapes approved synthetic roots")
        return directory

    def _validate_env(
        self, env: Optional[Mapping[object, object]], case: str, evidence: str
    ) -> Dict[str, str]:
        supplied = {} if env is None else env
        if not hasattr(supplied, "items"):
            raise InvalidExecutionRequest("env must be a mapping")
        clean = {
            "PATH": "/usr/bin:/bin",
            "HOME": case,
            "TMPDIR": case,
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
        }
        for key, value in supplied.items():
            if not isinstance(key, str) or not key or "=" in key or "\x00" in key:
                raise InvalidExecutionRequest("environment keys are invalid")
            if not isinstance(value, str) or "\x00" in value:
                raise InvalidExecutionRequest("environment values must be text without NUL")
            upper = key.upper()
            if (
                upper.startswith("DYLD_")
                or upper.startswith("LD_")
                or upper.startswith("PYTHON")
                or upper in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "GLOBIGNORE")
            ):
                raise InvalidExecutionRequest("unsafe interpreter/loader environment: %s" % key)
            clean[key] = value
        for key in ("HOME", "TMPDIR"):
            directory = _canonical_existing_directory(clean[key], key)
            if not (_is_within(directory, case) or _is_within(directory, evidence)):
                raise InvalidExecutionRequest("%s escapes approved synthetic roots" % key)
            clean[key] = directory
        clean["LANG"] = "C"
        clean["LC_ALL"] = "C"
        clean["TZ"] = "UTC"
        return clean

    @staticmethod
    def _group_exists(pgid: int) -> bool:
        try:
            os.killpg(pgid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    @staticmethod
    def _kill_group(pgid: int) -> bool:
        try:
            os.killpg(pgid, 9)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    @classmethod
    def _drain_group(cls, pgid: int) -> bool:
        deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
        while True:
            alive = cls._kill_group(pgid)
            if not alive:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)

    @classmethod
    def _cleanup(cls, process: subprocess.Popen, leader_was_reaped: bool) -> Tuple[bool, bool]:
        pgid = process.pid
        resident = leader_was_reaped and cls._group_exists(pgid)
        cls._kill_group(pgid)
        clean = True
        try:
            process.wait(timeout=CLEANUP_TIMEOUT_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            clean = False
        if not cls._drain_group(pgid):
            clean = False
        return clean, resident

    @staticmethod
    def _set_resource_limits() -> None:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(
            resource.RLIMIT_FSIZE, (MAX_CAPTURE_BYTES, MAX_CAPTURE_BYTES)
        )

    def _preflight(self, profile: str, cwd: str, env: Dict[str, str]) -> None:
        try:
            process = subprocess.Popen(
                [SANDBOX_EXEC, "-p", profile, PREFLIGHT_EXECUTABLE],
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
            )
        except OSError as error:
            raise ContainmentUnavailable("Seatbelt preflight could not start: %s" % type(error).__name__)
        timed_out = False
        try:
            process.wait(timeout=PREFLIGHT_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
        except BaseException:
            self._cleanup(process, False)
            raise
        clean, resident = self._cleanup(process, not timed_out)
        if timed_out or process.returncode != 0 or not clean or resident:
            raise ContainmentUnavailable(
                "Seatbelt profile verification failed; behavior execution is NOT_RUN"
            )

    def execute(
        self,
        argv: Sequence[object],
        cwd: object,
        env: Optional[Mapping[object, object]],
        case_root: object,
        evidence_dir: object,
        timeout: object,
    ) -> ExecutionResult:
        """Execute one case, or raise a typed error before case dispatch.

        A nonzero target exit is COMPLETE execution health.  Timeout, residual
        processes, output limiting, incomplete cleanup, and dispatch failures
        are PARTIAL and can never be mistaken for a passing behavior case.
        """
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            raise RootExecutionRefused("real root execution is refused")
        availability = self.status()
        if not availability.available:
            raise ContainmentUnavailable(availability.reason or "containment unavailable")
        profile = self.profile_for(case_root, evidence_dir)
        case, evidence = self._prepare_roots(case_root, evidence_dir)
        arguments = self._validate_argv(argv)
        directory = self._validate_cwd(cwd, case, evidence)
        environment = self._validate_env(env, case, evidence)
        bounded_timeout = self._validate_timeout(timeout)
        self._preflight(profile.text, directory, environment)

        try:
            stdout_file = tempfile.TemporaryFile(
                prefix="wirevpn-stdout-", dir=evidence
            )
            try:
                stderr_file = tempfile.TemporaryFile(
                    prefix="wirevpn-stderr-", dir=evidence
                )
            except BaseException:
                stdout_file.close()
                raise
        except OSError as error:
            raise EvidenceSetupError(
                "evidence capture setup failed before dispatch: %s" % type(error).__name__
            )
        try:
            try:
                process = subprocess.Popen(
                    [SANDBOX_EXEC, "-p", profile.text] + list(arguments),
                    cwd=directory,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    close_fds=True,
                    start_new_session=True,
                    preexec_fn=self._set_resource_limits,
                )
            except OSError as error:
                return ExecutionResult(
                    PARTIAL, None, b"", b"", False, True, False, False,
                    profile.identity, "DISPATCH_ERROR:%s" % type(error).__name__,
                )

            timed_out = False
            leader_reaped = False
            try:
                process.wait(timeout=bounded_timeout)
                leader_reaped = True
            except subprocess.TimeoutExpired:
                timed_out = True
            except BaseException:
                self._cleanup(process, False)
                raise
            clean, resident = self._cleanup(process, leader_reaped)
            stdout_file.flush()
            stderr_file.flush()
            stdout_size = stdout_file.seek(0, os.SEEK_END)
            stderr_size = stderr_file.seek(0, os.SEEK_END)
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read(MAX_CAPTURE_BYTES)
            stderr = stderr_file.read(MAX_CAPTURE_BYTES)
            limited = (
                stdout_size >= MAX_CAPTURE_BYTES or stderr_size >= MAX_CAPTURE_BYTES
            )
            details = []
            if timed_out:
                details.append("TIMEOUT")
            if resident:
                details.append("RESIDENT_PROCESS")
            if not clean:
                details.append("CLEANUP_INCOMPLETE")
            if limited:
                details.append("OUTPUT_LIMIT")
            healthy = not details and process.returncode is not None
            return ExecutionResult(
                COMPLETE if healthy else PARTIAL,
                process.returncode,
                stdout,
                stderr,
                timed_out,
                clean,
                resident,
                limited,
                profile.identity,
                ",".join(details) if details else None,
            )
        finally:
            stdout_file.close()
            stderr_file.close()
