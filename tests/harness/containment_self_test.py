"""Synthetic conformance and negative controls for Darwin containment."""

from __future__ import unicode_literals

import hashlib
import io
import os
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

import containment


PYTHON = "/usr/bin/python3"
SHELL = "/bin/sh"


class ContainmentTestBase(unittest.TestCase):
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory(prefix="wirevpn-containment-")
        self.base = os.path.realpath(self._temporary.name)
        self.case = self._directory("case")
        self.evidence = self._directory("evidence")
        self.outside = self._directory("outside")
        self.restricted = self._directory("outside/restricted")
        self.adapter = containment.DarwinContainment([self.restricted])

    def tearDown(self):
        self._temporary.cleanup()

    def _directory(self, relative):
        path = os.path.join(self.base, relative)
        os.makedirs(path, exist_ok=True)
        return path

    def _execute(self, argv, timeout=8.0, env=None, case=None, evidence=None, cwd=None):
        return self.adapter.execute(
            argv,
            self.case if cwd is None else cwd,
            {} if env is None else env,
            self.case if case is None else case,
            self.evidence if evidence is None else evidence,
            timeout,
        )

    def _python(self, source, timeout=8.0, env=None):
        return self._execute([PYTHON, "-c", source], timeout=timeout, env=env)

    def assertProcessGone(self, pid):
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)


class AvailabilityAndIdentityTests(ContainmentTestBase):
    def test_status_and_exact_profile_identity(self):
        status = self.adapter.status()
        if sys.platform == "darwin":
            self.assertTrue(status.available, status.reason)
            self.assertIsNone(status.execution_health)
        profile = self.adapter.profile_for(self.case, self.evidence)
        again = self.adapter.profile_for(self.case, self.evidence)
        self.assertEqual(profile, again)
        self.assertEqual(
            profile.identity.profile_sha256,
            hashlib.sha256(profile.text.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(profile.identity.source_sha256, status.source_sha256)
        self.assertTrue(profile.text.endswith("\n"))

    def test_profile_and_source_changes_alter_identity(self):
        profile = self.adapter.profile_for(self.case, self.evidence)
        other_evidence = self._directory("other-evidence")
        changed_path = self.adapter.profile_for(self.case, other_evidence)
        self.assertNotEqual(profile.identity.profile_sha256, changed_path.identity.profile_sha256)
        changed_profile = profile.text + "# synthetic mutation\n"
        changed_identity = self.adapter._make_identity(
            changed_profile, profile.identity.source_sha256
        )
        self.assertNotEqual(profile.identity.profile_sha256, changed_identity.profile_sha256)
        synthetic_source = os.path.join(self.base, "adapter-source.py")
        with open(synthetic_source, "wb") as source_file:
            source_file.write(b"first synthetic source\n")
        first_source = self.adapter._source_sha256(synthetic_source)
        with open(synthetic_source, "ab") as source_file:
            source_file.write(b"second synthetic source\n")
        second_source = self.adapter._source_sha256(synthetic_source)
        self.assertNotEqual(first_source, second_source)
        changed_source_identity = self.adapter._make_identity(profile.text, second_source)
        self.assertNotEqual(profile.identity.source_sha256, changed_source_identity.source_sha256)

    def test_unsupported_platform_is_not_run_before_dispatch(self):
        with mock.patch.object(containment.sys, "platform", "linux"):
            status = self.adapter.status()
            self.assertFalse(status.available)
            self.assertEqual(status.execution_health, containment.NOT_RUN)
            with self.assertRaises(containment.ContainmentUnavailable) as caught:
                self._python("raise SystemExit(0)")
        self.assertEqual(caught.exception.execution_health, containment.NOT_RUN)

    def test_root_execution_is_refused_before_dispatch(self):
        with mock.patch.object(containment.os, "geteuid", return_value=0):
            with self.assertRaises(containment.RootExecutionRefused) as caught:
                self._python("raise SystemExit(0)")
        self.assertEqual(caught.exception.execution_health, containment.NOT_RUN)

    def test_invalid_roots_and_unbounded_time_fail_closed(self):
        for bad_root in ("/", self.adapter.real_home, self.adapter._repository_root):
            with self.subTest(root=bad_root):
                with self.assertRaises(containment.InvalidExecutionRequest):
                    self.adapter.profile_for(bad_root, self.evidence)
        with self.assertRaises(containment.InvalidExecutionRequest):
            self.adapter.profile_for(self.case, self.case)
        nested_evidence = self._directory("case/nested-evidence")
        with self.assertRaises(containment.InvalidExecutionRequest):
            self.adapter.profile_for(self.case, nested_evidence)
        alias = os.path.join(self.base, "case-alias")
        os.symlink(self.case, alias)
        with self.assertRaises(containment.InvalidExecutionRequest):
            self.adapter.profile_for(alias, self.evidence)
        for timeout in (0, -1, float("inf"), float("nan"), 301, True, "1"):
            with self.subTest(timeout=timeout):
                with self.assertRaises(containment.InvalidExecutionRequest):
                    self._python("pass", timeout=timeout)

    def test_ambient_environment_and_unsafe_loader_settings_do_not_leak(self):
        variable = "WIREVPN_SYNTHETIC_AMBIENT_CANARY"
        old_value = os.environ.get(variable)
        os.environ[variable] = "synthetic-must-not-leak"
        try:
            result = self._python(
                "import os; raise SystemExit(0 if os.getenv(%r) is None else 1)" % variable
            )
        finally:
            if old_value is None:
                os.environ.pop(variable, None)
            else:
                os.environ[variable] = old_value
        self.assertEqual(result.returncode, 0, result.stderr)
        with self.assertRaises(containment.InvalidExecutionRequest):
            self._python("pass", env={"PYTHONPATH": self.case})
        with self.assertRaises(containment.InvalidExecutionRequest):
            self._python("pass", env={"DYLD_INSERT_LIBRARIES": "synthetic"})


@unittest.skipUnless(sys.platform == "darwin", "Darwin behavior lane")
class DarwinExecutionTests(ContainmentTestBase):
    def setUp(self):
        super().setUp()
        status = self.adapter.status()
        if not status.available:
            self.fail("required Darwin containment unavailable: %s" % status.reason)

    def test_allowed_shell_and_python_writes_and_output_capture(self):
        shell_target = os.path.join(self.case, "shell-allowed.fixture")
        result = self._execute(
            [SHELL, "-c", "printf shell-ok > \"$1\"; printf stdout; printf stderr >&2; exit 7", "sh", shell_target]
        )
        self.assertEqual(result.execution_health, containment.COMPLETE, result.detail)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, b"stdout")
        self.assertIn(b"stderr", result.stderr)
        with open(shell_target, "rb") as allowed_file:
            self.assertEqual(allowed_file.read(), b"shell-ok")
        python_target = os.path.join(self.evidence, "python-allowed.fixture")
        result = self._python(
            "import pathlib; pathlib.Path(%r).write_text('python-ok', encoding='utf-8')" % python_target
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(python_target, "rb") as allowed_file:
            self.assertEqual(allowed_file.read(), b"python-ok")

    def test_direct_shell_and_python_outside_writes_fail(self):
        shell_target = os.path.join(self.outside, "shell-denied.fixture")
        result = self._execute(
            [SHELL, "-c", "printf denied > \"$1\"", "sh", shell_target]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.execution_health, containment.COMPLETE)
        self.assertFalse(os.path.exists(shell_target))
        python_target = os.path.join(self.outside, "python-denied.fixture")
        result = self._python("open(%r, 'wb').write(b'denied')" % python_target)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(os.path.exists(python_target))

    def test_socket_creation_and_connection_fail_without_a_service(self):
        source = (
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "s.settimeout(0.2)\n"
            "s.connect(('192.0.2.1', 9))\n"
        )
        result = self._python(source)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"synthetic", result.stdout)

    def test_restricted_read_and_symlink_read_escape_fail(self):
        canary = "synthetic-private-canary-7f3a"
        secret = os.path.join(self.restricted, "secret.fixture")
        with open(secret, "w", encoding="utf-8") as secret_file:
            secret_file.write(canary)
        result = self._python("print(open(%r).read())" % secret)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(canary.encode("ascii"), result.stdout)
        link = os.path.join(self.case, "restricted-link")
        os.symlink(self.restricted, link)
        result = self._python("print(open(%r).read())" % os.path.join(link, "secret.fixture"))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(canary.encode("ascii"), result.stdout)

    def test_symlink_and_dotdot_write_escapes_fail(self):
        link = os.path.join(self.case, "outside-link")
        os.symlink(self.outside, link)
        target = os.path.join(link, "symlink-escape.fixture")
        result = self._python("open(%r, 'wb').write(b'denied')" % target)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(self.outside, "symlink-escape.fixture")))
        dotdot = os.path.join(self.case, "..", "outside", "dotdot-escape.fixture")
        result = self._execute([SHELL, "-c", "printf denied > \"$1\"", "sh", dotdot])
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(self.outside, "dotdot-escape.fixture")))

    def test_hardlink_escape_fails(self):
        host_file = os.path.join(self.outside, "host.fixture")
        with open(host_file, "wb") as host:
            host.write(b"synthetic-host")
        imported = os.path.join(self.case, "imported.fixture")
        result = self._python("import os; os.link(%r, %r)" % (host_file, imported))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(os.path.exists(imported))

    def test_crafted_archive_path_escape_fails(self):
        archive = os.path.join(self.evidence, "crafted.tar")
        with tarfile.open(archive, "w") as crafted:
            entry = tarfile.TarInfo("../outside/archive-escape.fixture")
            payload = b"archive-denied"
            entry.size = len(payload)
            crafted.addfile(entry, io.BytesIO(payload))
        result = self._python(
            "import tarfile; tarfile.open(%r).extractall(%r)" % (archive, self.case)
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(self.outside, "archive-escape.fixture")))

    def test_unintended_inherited_descriptor_is_closed(self):
        canary = b"synthetic-descriptor-canary-91bc"
        secret = os.path.join(self.restricted, "descriptor.fixture")
        with open(secret, "wb") as secret_file:
            secret_file.write(canary)
        descriptor = os.open(secret, os.O_RDONLY)
        try:
            result = self._python(
                "import os; data = os.read(%d, 4096); print(data.decode())" % descriptor,
                env={"SYNTHETIC_FD": str(descriptor)},
            )
        finally:
            os.close(descriptor)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(canary, result.stdout)

    def test_child_inherits_write_and_read_denials(self):
        target = os.path.join(self.outside, "child-denied.fixture")
        secret = os.path.join(self.restricted, "child-secret.fixture")
        with open(secret, "wb") as secret_file:
            secret_file.write(b"synthetic-child-canary")
        source = (
            "import subprocess, sys\n"
            "child = 'open(%r, %r).read()'\n"
            "raise SystemExit(subprocess.call([sys.executable, '-c', child]))\n"
        ) % (secret, "rb")
        result = self._python(source)
        self.assertNotEqual(result.returncode, 0)
        source = (
            "import subprocess, sys\n"
            "child = 'open(%r, %r).write(b%r)'\n"
            "raise SystemExit(subprocess.call([sys.executable, '-c', child]))\n"
        ) % (target, "wb", b"denied")
        result = self._python(source)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(os.path.exists(target))

    def test_nested_sandbox_cannot_relax_parent_profile(self):
        target = os.path.join(self.outside, "nested-profile-denied.fixture")
        source = (
            "import subprocess\n"
            "raise SystemExit(subprocess.call([%r, '-p', '(allow default)', "
            "%r, '-c', 'printf denied > %r']))\n"
        ) % (containment.SANDBOX_EXEC, SHELL, target)
        result = self._python(source)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(os.path.exists(target))

    def test_timeout_kills_and_reaps_complete_managed_group(self):
        pid_file = os.path.join(self.evidence, "child.pid")
        child = "import time; time.sleep(60)"
        parent = (
            "import os, subprocess, sys, time\n"
            "child = subprocess.Popen([sys.executable, '-c', %r])\n"
            "open(%r, 'w').write(str(child.pid))\n"
            "time.sleep(60)\n"
        ) % (child, pid_file)
        result = self._python(parent, timeout=0.4)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.execution_health, containment.PARTIAL)
        self.assertTrue(result.cleanup_complete, result.detail)
        with open(pid_file, "r", encoding="ascii") as recorded:
            child_pid = int(recorded.read())
        self.assertProcessGone(child_pid)
        self.assertIsNotNone(result.returncode)

    def test_resident_child_after_leader_exit_is_destroyed(self):
        pid_file = os.path.join(self.evidence, "resident.pid")
        child = "import time; time.sleep(60)"
        parent = (
            "import subprocess, sys\n"
            "child = subprocess.Popen([sys.executable, '-c', %r])\n"
            "open(%r, 'w').write(str(child.pid))\n"
        ) % (child, pid_file)
        result = self._python(parent)
        self.assertFalse(result.timed_out)
        self.assertTrue(result.resident_processes)
        self.assertEqual(result.execution_health, containment.PARTIAL)
        self.assertTrue(result.cleanup_complete, result.detail)
        with open(pid_file, "r", encoding="ascii") as recorded:
            child_pid = int(recorded.read())
        self.assertProcessGone(child_pid)


if __name__ == "__main__":
    unittest.main()
