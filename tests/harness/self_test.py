#!/usr/bin/env python3
"""Required negative controls for the WireVPN deterministic harness."""

import copy
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import containment
import containment_self_test
import instrument
import model
import run
import schema
import shell_lint
import static_gates
import toolchain


ZERO_SHA256 = "0" * 64
TOOLCHAIN_PATH = run.REPOSITORY / "tests/toolchain.json"


def _write(path, data):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode("utf-8")
    path.write_bytes(data)
    return path


def _json(path, value):
    return _write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def semantic_document():
    return {
        "schema": "wirevpn.semantic-vector/1.0",
        "vector_id": "negative-control-vector",
        "acceptance_ids": ["WVA-28"],
        "platform": "platform-independent",
        "arguments": [],
        "applicability": {
            "baseline_commit": "01143e05ce105ab42fec5fd7b0bacaac49ad2405",
            "condition": "Synthetic negative-control document.",
        },
        "fixtures": [],
        "contracts": [{
            "assertion_id": "clock-remains-zero",
            "basis": "safety",
            "statement": "The synthetic virtual clock remains zero.",
            "requirement_links": ["WVA-28"],
            "finding_links": [],
        }],
        "assertions": [{
            "kind": "state_equals",
            "path": "virtual_time.seconds",
            "expected": 0,
        }],
        "exit_codes": [0],
        "finding_id": None,
        "concurrency": {"mode": "single-actor"},
        "content_sha256": ZERO_SHA256,
    }


def binding_document():
    return {
        "schema": "wirevpn.bash-execution-binding/1.0",
        "binding_id": "negative-control-binding",
        "vector_id": "negative-control-vector",
        "vector_sha256": ZERO_SHA256,
        "entrypoint": "wirevpn.sh",
        "arguments": [],
        "instrumentation_profile": "wirevpn-bash-instrumentation/1.0",
        "containment_profile": "wirevpn-darwin-seatbelt/1",
        "timeout_seconds": 5,
        "initial_state": {},
        "commands": [{"argv": ["date"], "exit": 0, "stdout": "", "stderr": ""}],
        "baseline_observation": {
            "authority": "non-authoritative",
            "statement": "This document exercises validation only.",
        },
        "content_sha256": ZERO_SHA256,
    }


def vector_reference():
    return {
        "vector_id": "negative-control-vector",
        "acceptance_id": "WVA-28",
        "semantic_path": "tests/vectors/harness/negative-control-vector.json",
        "bash_binding_path": "tests/vectors/bash/negative-control-vector.json",
        "semantic_sha256": ZERO_SHA256,
        "bash_binding_sha256": ZERO_SHA256,
    }


def concurrency_document():
    return {
        "mode": "multi-actor",
        "actors": [
            {"actor_id": "primary", "role": "primary"},
            {"actor_id": "daemon", "role": "daemon"},
        ],
        "schedule": {
            "max_steps": 2,
            "max_virtual_time_ms": 100,
            "max_spawned_processes": 2,
            "steps": [
                {
                    "step_id": "first",
                    "actor_id": "primary",
                    "operation_id": "start",
                    "virtual_time_offset_ms": 0,
                    "after_barrier_ids": [],
                },
                {
                    "step_id": "second",
                    "actor_id": "daemon",
                    "operation_id": "stop",
                    "virtual_time_offset_ms": 100,
                    "after_barrier_ids": ["started"],
                },
            ],
        },
        "barriers": [{
            "barrier_id": "started",
            "after_step_ids": ["first"],
            "before_step_ids": ["second"],
        }],
        "signals": [{
            "signal_id": "termination",
            "at_step_id": "second",
            "actor_id": "daemon",
            "name": "SIGTERM",
            "expected_handler_observation": "The synthetic daemon observes termination.",
        }],
        "partial_orders": [{
            "order_id": "start-before-stop",
            "before_step_id": "first",
            "after_step_id": "second",
        }],
        "allowed_linearizations": [["first", "second"]],
        "final_state_invariants": ["The synthetic service is stopped."],
    }


def make_dependency_repository(base):
    root = Path(base) / "repository"
    _json(root / "harness/project.json", {
        "accepted_specification": {"path": "docs/specs/accepted.md"},
        "sources": [{"path": "product.sh"}],
    })
    for relative in (
        "harness/checks.json",
        "harness/project.schema.json",
        "harness/checks.schema.json",
        "tests/toolchain.json",
        "tests/vectors/vectors.json",
        "tests/vectors/schema.json",
        "tests/vectors/harness/vector.json",
        "tests/vectors/bash/vector.json",
        "Makefile",
        ".github/workflows/deterministic.yml",
    ):
        _json(root / relative, {})
    _write(root / "docs/specs/accepted.md", "accepted specification\n")
    _write(root / "product.sh", "#!/bin/bash\nexit 0\n")
    _write(root / "tests/harness/run.py", "# synthetic runner\n")
    _write(root / "tests/fixtures/synthetic.fixture", "{}\n")
    return root


def make_evidence_record(repository, evidence):
    Path(evidence).mkdir(mode=0o700, parents=True, exist_ok=True)
    return run._base_record(repository, evidence, [], "negative-control")


def make_characterization_repository(base, index, with_documents=False):
    root = Path(base) / "characterization-repository"
    _json(root / "tests/vectors/vectors.json", index)
    shutil.copyfile(run.REPOSITORY / "tests/vectors/schema.json", root / "tests/vectors/schema.json")
    _json(root / "tests/toolchain.json", {})
    if with_documents:
        semantic = semantic_document()
        semantic["content_sha256"] = run._content_digest(semantic)
        binding = binding_document()
        binding["vector_sha256"] = semantic["content_sha256"]
        binding["content_sha256"] = run._content_digest(binding)
        semantic_path = _json(root / index["vectors"][0]["semantic_path"], semantic)
        binding_path = _json(root / index["vectors"][0]["bash_binding_path"], binding)
        index["vectors"][0]["semantic_sha256"] = run._file_digest(semantic_path)
        index["vectors"][0]["bash_binding_sha256"] = run._file_digest(binding_path)
        index["content_sha256"] = run._content_digest(index)
        _json(root / "tests/vectors/vectors.json", index)
    return root


class HarnessTestCase(unittest.TestCase):
    check_id = None

    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory(prefix="wirevpn-self-test-")
        self.base = Path(os.path.realpath(self._temporary.name))

    def tearDown(self):
        self._temporary.cleanup()


class SourceInvalidationTests(HarnessTestCase):
    check_id = "WVH-01"

    def test_tracked_dirty_untracked_generated_and_runner_changes_invalidate(self):
        repository = make_dependency_repository(self.base / "baseline")
        evidence = self.base / "evidence"
        record = make_evidence_record(repository, evidence)
        self.assertTrue(run.evidence_is_current(record, repository))
        mutations = [
            ("tracked-source", "product.sh", False),
            ("accepted-specification", "docs/specs/accepted.md", False),
            ("dirty-vector", "tests/vectors/harness/vector.json", False),
            ("fixture", "tests/fixtures/synthetic.fixture", False),
            ("toolchain", "tests/toolchain.json", False),
            ("runner", "tests/harness/run.py", False),
            ("untracked-harness", "tests/harness/untracked.py", True),
            ("generated-vector", "tests/vectors/harness/generated.json", True),
            ("untracked-fixture", "tests/fixtures/generated.fixture", True),
        ]
        for index, (label, relative, created) in enumerate(mutations):
            with self.subTest(mutation=label):
                copy_base = self.base / ("mutation-%d" % index)
                changed = Path(shutil.copytree(repository, copy_base / "repository"))
                target = changed / relative
                if created:
                    _write(target, "{}\n")
                else:
                    with target.open("ab") as stream:
                        stream.write(b"\n# synthetic mutation\n")
                self.assertFalse(run.evidence_is_current(record, changed), label)

    def test_deleted_dependency_invalidates(self):
        repository = make_dependency_repository(self.base / "deleted")
        record = make_evidence_record(repository, self.base / "deleted-evidence")
        (repository / "tests/vectors/bash/vector.json").unlink()
        self.assertFalse(run.evidence_is_current(record, repository))


class PathPolicyTests(HarnessTestCase):
    check_id = "WVH-02"

    def test_root_execution_is_refused_before_any_suite(self):
        with mock.patch.object(run.os, "geteuid", return_value=0):
            with self.assertRaises(run.RunnerError):
                run.main(["static", "--repository", str(self.base)])

    def test_fixture_path_escape_is_refused(self):
        case = self.base / "case"
        case.mkdir()
        document = {"files": [{"path": "../escaped.fixture", "text": "denied"}]}
        data = json.dumps(document).encode("utf-8")
        fixture = _write(self.base / "escape.fixture", data)
        identity = {
            "path": fixture.name,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        with self.assertRaises(run.RunnerError):
            run._install_fixture_tree(case, fixture.parent, [identity])
        self.assertFalse((self.base / "escaped.fixture").exists())

    def test_model_rejects_traversal_absolute_escape_and_symlinks(self):
        case = self.base / "case"
        evidence = self.base / "evidence"
        case.mkdir()
        evidence.mkdir()
        roots = model.normalize_roots({"case": case, "evidence": evidence})
        for path in ("../escape", "nested/../../escape", str(self.base / "escape")):
            with self.subTest(path=path):
                with self.assertRaises(model.ModelError):
                    model.safe_effect_path(roots, "case", path, allow_missing=True)
        os.symlink(str(evidence), str(case / "link"))
        with self.assertRaises(model.ModelError):
            model.safe_effect_path(roots, "case", "link/escape", allow_missing=True)


class FakeCommandNegativeTests(HarnessTestCase):
    check_id = "WVH-03"

    def setUp(self):
        super().setUp()
        self.case = self.base / "case"
        self.evidence = self.base / "evidence"
        self.fakebin = self.base / "fakebin"
        self.case.mkdir()
        self.evidence.mkdir()
        self.fakebin.mkdir()
        model.install_fakebin(self.fakebin, ["date", "uname", "sudo", "networksetup"], sys.executable)
        self.roots = {"case": self.case, "evidence": self.evidence}

    def _expectation(self, argv, stdin=None):
        expectation = {"argv": argv, "exit": 0, "stdout": "", "stderr": ""}
        if stdin is not None:
            data = stdin.encode("utf-8")
            expectation["stdin"] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        return expectation

    def _initialize(self, expectations):
        model.initialize_case(self.fakebin / "model", expectations, self.roots)

    def _invoke(self, command, *arguments, **kwargs):
        return subprocess.run(
            [str(self.fakebin / command)] + list(arguments),
            input=kwargs.get("stdin", b""),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "HOME": str(self.case), "TMPDIR": str(self.case)},
            timeout=5,
            check=False,
        )

    def _failed_status(self, expected):
        records = model.load_calls(self.fakebin / "model")
        self.assertEqual(records[-1]["status"], expected)
        self.assertFalse(model.finalize(self.fakebin / "model")["passed"])

    def test_unexpected_call_fails(self):
        self._initialize([self._expectation(["date"])])
        self.assertEqual(self._invoke("uname").returncode, model.HARNESS_ERROR_EXIT)
        self._failed_status("unexpected")

    def test_missing_call_fails(self):
        self._initialize([self._expectation(["date"])])
        result = model.finalize(self.fakebin / "model")
        self.assertFalse(result["passed"])
        self.assertEqual(result["missing"], [0])

    def test_extra_call_fails(self):
        self._initialize([self._expectation(["date"])])
        self.assertEqual(self._invoke("date").returncode, 0)
        self.assertEqual(self._invoke("date").returncode, model.HARNESS_ERROR_EXIT)
        self._failed_status("extra")

    def test_duplicated_call_cannot_satisfy_two_expectations(self):
        self._initialize([self._expectation(["date"]), self._expectation(["date"])])
        self.assertEqual(self._invoke("date").returncode, 0)
        result = model.finalize(self.fakebin / "model")
        self.assertFalse(result["passed"])
        self.assertEqual(result["missing"], [1])

    def test_stdin_mismatch_fails(self):
        self._initialize([self._expectation(["date"], stdin="expected")])
        self.assertEqual(self._invoke("date", stdin=b"different").returncode, model.HARNESS_ERROR_EXIT)
        self._failed_status("stdin_mismatch")

    def test_path_escaping_effect_fails_before_dispatch(self):
        expectation = self._expectation(["date"])
        expectation["effects"] = [{
            "op": "write",
            "root": "case",
            "path": "../escaped.fixture",
            "content": "denied",
        }]
        with self.assertRaises(model.ModelError):
            self._initialize([expectation])

    def test_fake_sudo_never_dispatches_or_elevates(self):
        self._initialize([self._expectation(["sudo", "date"], stdin="")])
        result = self._invoke("sudo", "date")
        self.assertEqual(result.returncode, 0)
        records = model.load_calls(self.fakebin / "model")
        self.assertEqual([record["argv"] for record in records], [["sudo", "date"]])
        self.assertTrue(model.finalize(self.fakebin / "model")["passed"])

    def test_networksetup_does_not_consume_process_substitution_input(self):
        self._initialize([
            self._expectation(["networksetup", "-getinfo", "Wi-Fi"]),
            self._expectation(["networksetup", "-getinfo", "Ethernet"]),
        ])
        script = (
            'while IFS= read -r service; do '
            '"$1" -getinfo "$service" || exit; '
            'done < <(printf "Wi-Fi\\nEthernet\\n")'
        )
        result = subprocess.run(
            ["/bin/bash", "-c", script, "bash", str(self.fakebin / "networksetup")],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "HOME": str(self.case), "TMPDIR": str(self.case)},
            timeout=5,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(model.finalize(self.fakebin / "model")["passed"])


class EmbeddedPayloadTests(HarnessTestCase):
    check_id = "WVH-04"

    def test_payload_equivalence_and_drift_detection(self):
        project = run._load_json(run.REPOSITORY / "harness/project.json")
        identities = static_gates.verify_source_manifest(run.REPOSITORY, project)
        observations = static_gates.verify_embedded_payloads(run.REPOSITORY, project, identities)
        self.assertEqual(len(observations), len(project["embedded_payloads"]))
        copied = self.base / "repository"
        copied.mkdir()
        for identity in project["sources"] + [project["accepted_specification"]]:
            destination = copied / identity["path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(run.REPOSITORY / identity["path"], destination)
        with (copied / "wirevpn-connect.sh").open("ab") as stream:
            stream.write(b"# synthetic payload drift\n")
        with self.assertRaises(static_gates.StaticGateError):
            static_gates.verify_embedded_payloads(copied, project)


class GeneratedArtifactTests(HarnessTestCase):
    check_id = "WVH-04"

    def test_exact_source_and_emitted_template_inventory(self):
        project = run._load_json(run.REPOSITORY / "harness/project.json")
        identities = static_gates.verify_source_manifest(run.REPOSITORY, project)
        observations = static_gates.verify_generated_artifacts(run.REPOSITORY, project, identities)
        self.assertEqual(len(observations), 29)
        self.assertEqual({item["artifact_id"] for item in observations}, {
            "server-live-config-backup",
            "server-config-backup",
            "server-public-key-sync",
            "server-private-key-generate",
            "server-public-key-generate",
            "server-client-private-key-generate",
            "server-client-public-key-generate",
            "server-wg0-conf",
            "server-sysctl-ip-forward-fragment",
            "server-client-conf",
            "adguard-resolv-conf",
            "adguard-install-configure-json",
            "adguard-dns-config-json",
            "adguard-filter-add-url-json",
            "client-register-server-public-key-sync",
            "client-register-peer-private-key",
            "client-register-peer-public-key",
            "client-register-wg0-peer-fragment",
            "client-register-peer-conf",
            "client-register-downloaded-peer-conf",
            "client-conf-backup",
            "client-installed-conf",
            "client-launchd-startup-plist",
            "mobile-add-server-public-key-sync",
            "mobile-add-peer-private-key",
            "mobile-add-peer-public-key",
            "mobile-add-wg0-peer-fragment",
            "mobile-add-peer-conf",
            "mobile-add-downloaded-peer-conf",
        })
        for artifact in project["generated_artifacts"]:
            for identity_name in ("source", "content"):
                with self.subTest(artifact=artifact["artifact_id"], identity=identity_name):
                    mutated = copy.deepcopy(project)
                    target = next(item for item in mutated["generated_artifacts"] if item["artifact_id"] == artifact["artifact_id"])
                    target[identity_name]["sha256"] = ZERO_SHA256
                    with self.assertRaises(static_gates.StaticGateError):
                        static_gates.verify_generated_artifacts(run.REPOSITORY, mutated, identities)
        for artifact in project["generated_artifacts"]:
            if artifact["framing"] == "request-body":
                continue
            with self.subTest(removed_write_site=artifact["artifact_id"]):
                mutated = copy.deepcopy(project)
                mutated["generated_artifacts"] = [
                    item for item in mutated["generated_artifacts"]
                    if item["artifact_id"] != artifact["artifact_id"]
                ]
                with self.assertRaisesRegex(static_gates.StaticGateError, "write-site inventory mismatch"):
                    static_gates.verify_generated_artifacts(run.REPOSITORY, mutated, identities)

    def test_generated_body_mutation_fails_after_source_rebinding(self):
        project = run._load_json(run.REPOSITORY / "harness/project.json")
        copied = self.base / "repository"
        copied.mkdir()
        for identity in project["sources"] + [project["accepted_specification"]]:
            destination = copied / identity["path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(run.REPOSITORY / identity["path"], destination)
        target = copied / "client_setup.sh"
        data = target.read_bytes()
        original = b"printf '\\n[Peer]\\n# %s\\nPublicKey = %s\\nAllowedIPs = %s/32\\n'"
        self.assertEqual(data.count(original), 1)
        data = data.replace(original, original.replace(b"# %s", b"# %d"))
        target.write_bytes(data)
        rebound = copy.deepcopy(project)
        identity = next(item for item in rebound["sources"] if item["path"] == "client_setup.sh")
        identity["bytes"] = len(data)
        identity["sha256"] = hashlib.sha256(data).hexdigest()
        entrypoint = next(item for item in rebound["entrypoints"] if item["source_path"] == "client_setup.sh")
        entrypoint["source_sha256"] = identity["sha256"]
        identities = static_gates.verify_source_manifest(copied, rebound)
        with self.assertRaisesRegex(static_gates.StaticGateError, "client-register-wg0-peer-fragment source"):
            static_gates.verify_generated_artifacts(copied, rebound, identities)


class VectorSchemaTests(HarnessTestCase):
    check_id = "WVH-05"

    def setUp(self):
        super().setUp()
        self.vector_schema = run._load_json(run.REPOSITORY / "tests/vectors/schema.json")

    def assertRejected(self, document):
        with self.assertRaises(schema.SchemaValidationError):
            schema.require_valid(document, self.vector_schema)

    def test_unknown_fields_are_rejected_in_every_document_type(self):
        documents = [semantic_document(), binding_document(), {
            "schema": "wirevpn.vector-index/1.0",
            "vectors": [vector_reference()],
            "content_sha256": ZERO_SHA256,
        }]
        for document in documents:
            with self.subTest(schema=document["schema"]):
                document["unreviewed_field"] = True
                self.assertRejected(document)

    def test_missing_expectations_and_unbounded_retries_are_rejected(self):
        binding = binding_document()
        binding["commands"] = []
        self.assertRejected(binding)
        binding = binding_document()
        binding["retries"] = {"limit": "unbounded"}
        self.assertRejected(binding)
        binding = binding_document()
        binding["timeout_seconds"] = 31
        self.assertRejected(binding)

    def test_duplicate_vector_ids_are_rejected_by_runner(self):
        index = {
            "schema": "wirevpn.vector-index/1.0",
            "vectors": [vector_reference(), vector_reference()],
            "content_sha256": ZERO_SHA256,
        }
        index["content_sha256"] = run._content_digest(index)
        repository = make_characterization_repository(self.base, index)
        with mock.patch.object(run, "load_configuration", return_value=({}, {})):
            with self.assertRaises(run.RunnerError):
                run.characterize(repository, self.base / "evidence")

    def test_unknown_requested_vector_is_rejected(self):
        index = {
            "schema": "wirevpn.vector-index/1.0",
            "vectors": [vector_reference()],
            "content_sha256": ZERO_SHA256,
        }
        index["content_sha256"] = run._content_digest(index)
        repository = make_characterization_repository(self.base, index)
        with mock.patch.object(run, "load_configuration", return_value=({}, {})):
            with self.assertRaises(run.RunnerError):
                run.characterize(repository, self.base / "evidence", ["unknown-vector"])

    def test_validation_results_do_not_claim_behavior_execution(self):
        evidence = self.base / "validation-evidence"
        evidence.mkdir()
        with mock.patch.object(
            run,
            "load_vector_bundle",
            return_value=({}, [(semantic_document(), binding_document())]),
        ):
            record = run.command_validate(run.REPOSITORY, evidence)
        self.assertEqual(record["schema"], "wirevpn.validation-result/1.0")
        result = record["results"][0]
        self.assertEqual(result["validation_verdict"], "PASS")
        self.assertTrue(result["validation_only"])
        for field in ("execution_health", "contract_verdict", "overall_result"):
            self.assertNotIn(field, result)


class InstrumentationTests(HarnessTestCase):
    check_id = "WVH-06"

    def setUp(self):
        super().setUp()
        self.project = run._load_json(run.REPOSITORY / "harness/project.json")
        self.case = self.base / "case"
        self.fakebin = self.case / "fakebin"
        self.fakebin.mkdir(parents=True)
        toolchain = run._load_json(TOOLCHAIN_PATH)
        self.bash = run.select_toolchain(toolchain)["bash"]["path"]

    def _replacements(self):
        return instrument.default_replacements(self.case, self.fakebin, self.bash)

    def test_all_profiles_bind_source_output_and_exact_rules(self):
        for entrypoint in self.project["entrypoints"]:
            with self.subTest(source=entrypoint["source_path"]):
                identity = next(item for item in self.project["sources"] if item["path"] == entrypoint["source_path"])
                original_path = run.REPOSITORY / identity["path"]
                original_digest = run._file_digest(original_path)
                binding = {
                    "path": identity["path"],
                    "size": identity["bytes"],
                    "sha256": identity["sha256"],
                }
                transformed, record = instrument.instrument_source(
                    run.REPOSITORY,
                    binding,
                    self.base / ("instrumentation-" + entrypoint["entrypoint_id"]),
                    self._replacements(),
                )
                self.assertEqual(run._file_digest(original_path), original_digest)
                self.assertEqual(record["source"]["sha256"], original_digest)
                self.assertEqual(record["transformed"]["sha256"], run._file_digest(transformed))
                self.assertEqual(record["transformed"]["size"], transformed.stat().st_size)
                self.assertTrue(record["rules"])
                self.assertTrue(all(rule["replacements"] > 0 for rule in record["rules"]))

    def test_source_digest_and_size_mismatch_fail(self):
        identity = self.project["sources"][0]
        for field in ("size", "sha256"):
            with self.subTest(field=field):
                binding = {"path": identity["path"], "size": identity["bytes"], "sha256": identity["sha256"]}
                binding[field] = 0 if field == "size" else ZERO_SHA256
                with self.assertRaises(instrument.InstrumentationError):
                    instrument.verify_source(run.REPOSITORY, binding)

    def test_replacement_count_mismatch_fails(self):
        original = (run.REPOSITORY / "server_setup.sh").read_bytes()
        changed = original.replace(b"/etc/wireguard", b"", 1)
        with self.assertRaises(instrument.InstrumentationError):
            instrument.transform("server_setup.sh", changed, self._replacements())

    def test_unmapped_privileged_path_fails(self):
        original = (run.REPOSITORY / "server_setup.sh").read_bytes() + b"\n/etc/shadow\n"
        with self.assertRaises(instrument.InstrumentationError):
            instrument.transform("server_setup.sh", original, self._replacements())


class BuildAndCITests(HarnessTestCase):
    check_id = "WVH-01"

    def test_workflow_is_pinned_read_only_and_offline(self):
        workflow = (run.REPOSITORY / ".github/workflows/deterministic.yml").read_text(encoding="utf-8")
        uses = re.findall(r"uses:\s*([^\s]+)", workflow)
        self.assertTrue(uses)
        for reference in uses:
            with self.subTest(reference=reference):
                self.assertRegex(reference, r"@[0-9a-f]{40}$")
        self.assertIn("contents: read", workflow)
        self.assertIn("runs-on: macos-14", workflow)
        self.assertIn('python-version: "3.14.3"', workflow)
        for denied in ("pull_request_target", "secrets.", "upload-artifact", "|| true", "sudo ", "curl ", "wget "):
            self.assertNotIn(denied, workflow)

    def test_makefile_exposes_deterministic_entry_points(self):
        makefile = (run.REPOSITORY / "Makefile").read_text(encoding="utf-8")
        for target in ("verify-harness", "verify-vectors", "verify-bash-static", "verify-shell-lint", "characterize-bash", "verify-public"):
            self.assertIn(target + ":", makefile)

    def test_shell_lint_lane_is_exactly_pinned(self):
        workflow = (run.REPOSITORY / ".github/workflows/deterministic.yml").read_text(encoding="utf-8")
        self.assertIn("shell-lint:", workflow)
        self.assertIn("shell_lint.py provision", workflow)
        self.assertIn("shell_lint.py check", workflow)
        pins = shell_lint.load_pins(run.REPOSITORY / "tests/toolchain.json")
        self.assertEqual(pins["shellcheck"]["version"], "0.11.0")
        self.assertEqual(pins["shfmt"]["version"], "3.12.0")
        self.assertEqual(pins["shellcheck"]["asset"]["sha256"], "56affdd8de5527894dca6dc3d7e0a99a873b0f004d7aabc30ae407d3f48b0a79")
        self.assertEqual(pins["shfmt"]["asset"]["sha256"], "d903802e0ce3ecbc82b98512f55ba370b0d37a93f3f78de394f5b657052b33dd")
        mutated = copy.deepcopy(run._load_json(run.REPOSITORY / "tests/toolchain.json"))
        mutated["shell_lint"]["shellcheck"]["asset"]["sha256"] = "0" * 63
        path = _json(self.base / "invalid-lint-toolchain.json", mutated)
        with self.assertRaises(shell_lint.LintError):
            shell_lint.load_pins(path)

    def test_lint_version_and_archive_controls_fail_closed(self):
        pins = shell_lint.load_pins(run.REPOSITORY / "tests/toolchain.json")
        fake = _write(self.base / "shellcheck", "#!/bin/sh\nprintf 'version: 0.0.0\\n'\n")
        fake.chmod(0o700)
        with self.assertRaises(shell_lint.LintError):
            shell_lint.assert_version("shellcheck", fake, pins["shellcheck"]["version"])
        asset = copy.deepcopy(pins["shellcheck"]["asset"])
        asset["allowed_members"] = [asset["member"], "../escape"]
        archive_path = self.base / "malicious.tar.xz"
        with tarfile.open(str(archive_path), "w:xz") as archive:
            for name in asset["allowed_members"]:
                member = tarfile.TarInfo(name)
                data = b"synthetic"
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        with self.assertRaises(shell_lint.LintError):
            shell_lint.extract_shellcheck(archive_path, asset, self.base / "extracted-shellcheck")


class ToolchainDiscoveryTests(HarnessTestCase):
    check_id = "WVH-01"

    def test_discovered_toolchain_is_exact_and_outside_public_repository(self):
        output = self.base / "runtime-toolchain.json"
        digest = toolchain.write_discovery(run.REPOSITORY, output)
        self.assertEqual(run._file_digest(output), digest)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        selected = run.select_toolchain(run._load_json(output))
        self.assertGreaterEqual(run._version_numbers(selected["bash"]["version"]), (4, 0, 0))
        self.assertEqual(Path(selected["python"]["path"]).resolve(), Path(sys.executable).resolve())
        below_minimum = run._load_json(output)
        below_minimum["host"]["bash"]["current"]["version"] = "3.2.57"
        with self.assertRaises(run.RunnerError):
            run.select_toolchain(below_minimum)
        self.assertEqual(run.resolve_toolchain_path(run.REPOSITORY, output), output.resolve())
        with self.assertRaises(toolchain.ToolchainError):
            toolchain.write_discovery(run.REPOSITORY, run.REPOSITORY / "runtime-toolchain.json")

    def test_ci_discovery_enforces_exact_bash_version(self):
        with mock.patch.object(toolchain.platform, "python_version", return_value="3.14.3"):
            discovered = toolchain.discover(run.REPOSITORY, require_ci=True)
            self.assertEqual(discovered["host"]["bash"]["current"]["version"], "5.3.9")
            document = run._load_json(run.REPOSITORY / "tests/toolchain.json")
            document["ci"]["bash"]["version"] = "0.0.0"
            repository = self.base / "ci-repository"
            _json(repository / "tests/toolchain.json", document)
            with self.assertRaisesRegex(toolchain.ToolchainError, "exact CI requirement"):
                toolchain.discover(repository, require_ci=True)


class EvidenceIntegrityTests(HarnessTestCase):
    check_id = "WVH-07"

    def test_raw_case_artifact_mutation_deletion_and_addition_block_revalidation(self):
        repository = make_dependency_repository(self.base / "repository")
        evidence = self.base / "case-artifact-evidence"
        case = evidence / "cases/synthetic"
        names = ("stdout.bin", "stderr.bin", "state.json", "calls.jsonl", "result.json", "transformation.json")
        for name in names:
            _write(case / name, "synthetic-%s\n" % name)
        record = run._base_record(repository, evidence, [], "negative-control")
        self.assertEqual(record["raw_evidence"]["artifact_count"], len(names))
        self.assertTrue(run.evidence_is_current(record, repository))
        for name in names:
            with self.subTest(artifact=name):
                path = case / name
                original = path.read_bytes()
                path.write_bytes(original + b"mutation")
                self.assertFalse(run.evidence_is_current(record, repository))
                path.write_bytes(original)
                self.assertTrue(run.evidence_is_current(record, repository))
                path.unlink()
                self.assertFalse(run.evidence_is_current(record, repository))
                path.write_bytes(original)
                self.assertTrue(run.evidence_is_current(record, repository))
        extra = _write(case / "extra.bin", "unbound")
        self.assertFalse(run.evidence_is_current(record, repository))
        extra.unlink()
        self.assertTrue(run.evidence_is_current(record, repository))
        changed_report = copy.deepcopy(record)
        changed_report["results"] = [{"overall_result": "PASS"}]
        self.assertFalse(run.evidence_is_current(changed_report, repository))

    def test_raw_evidence_tamper_and_deletion_block_revalidation(self):
        repository = make_dependency_repository(self.base / "repository")
        record = make_evidence_record(repository, self.base / "tampered")
        self.assertTrue(run.evidence_is_current(record, repository))
        with Path(record["raw_evidence"]["identity"]).open("ab") as stream:
            stream.write(b"tampered")
        self.assertFalse(run.evidence_is_current(record, repository))
        record = make_evidence_record(repository, self.base / "deleted")
        Path(record["raw_evidence"]["identity"]).unlink()
        self.assertFalse(run.evidence_is_current(record, repository))

    def test_expiry_and_stale_dependencies_block_revalidation(self):
        repository = make_dependency_repository(self.base / "repository")
        record = make_evidence_record(repository, self.base / "expired")
        record["retention"]["expires_at"] = "2000-01-01T00:00:00Z"
        self.assertFalse(run.evidence_is_current(record, repository))
        record = make_evidence_record(repository, self.base / "stale")
        with (repository / "product.sh").open("ab") as stream:
            stream.write(b"# stale\n")
        self.assertFalse(run.evidence_is_current(record, repository))

    def test_runtime_toolchain_mutation_blocks_revalidation(self):
        repository = make_dependency_repository(self.base / "repository")
        runtime = self.base / "runtime-toolchain.json"
        toolchain.write_discovery(run.REPOSITORY, runtime)
        evidence = self.base / "runtime-evidence"
        evidence.mkdir()
        record = run._base_record(
            repository,
            evidence,
            [],
            "negative-control",
            runtime,
        )
        self.assertTrue(run.evidence_is_current(record, repository))
        _json(runtime, {"synthetic": "changed"})
        self.assertFalse(run.evidence_is_current(record, repository))

    def test_runtime_executable_mutation_blocks_revalidation(self):
        repository = make_dependency_repository(self.base / "repository")
        runtime = self.base / "runtime-toolchain.json"
        toolchain.write_discovery(run.REPOSITORY, runtime)
        document = run._load_json(runtime)
        selected = {
            "bash": document["host"]["bash"]["current"],
            "python": document["host"]["python"]["current"],
            "sandbox_exec": document["host"]["sandbox_exec"],
        }
        copies = {}
        for name, identity in selected.items():
            target = self.base / ("executable-" + name)
            shutil.copyfile(identity["path"], target)
            target.chmod(0o700)
            data = target.read_bytes()
            identity.update({
                "path": str(target),
                "resolved_path": str(target),
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            })
            copies[name] = target
        _json(runtime, document)
        runtime.chmod(0o600)
        evidence = self.base / "executable-evidence"
        evidence.mkdir()
        record = run._base_record(repository, evidence, [], "negative-control", runtime)
        self.assertTrue(run.evidence_is_current(record, repository))
        for name, target in copies.items():
            with self.subTest(executable=name):
                original = target.read_bytes()
                target.write_bytes(original + b"synthetic mutation")
                self.assertFalse(run.evidence_is_current(record, repository))
                target.write_bytes(original)
                self.assertTrue(run.evidence_is_current(record, repository))

    def test_malformed_reports_fail_closed(self):
        repository = make_dependency_repository(self.base / "repository")
        valid = make_evidence_record(repository, self.base / "valid")
        malformed = [None, [], {}, {"retention": None}, {"retention": {}, "raw_evidence": []}]
        for record in malformed:
            with self.subTest(record=record):
                self.assertFalse(run.evidence_is_current(record, repository))
        record = copy.deepcopy(valid)
        record["raw_evidence"]["sha256"] = ZERO_SHA256
        self.assertFalse(run.evidence_is_current(record, repository))

    def test_secret_canaries_and_private_material_are_not_public(self):
        denied = [
            b"WIREVPN" b"_SECRET_CANARY=synthetic",
            b"/U\x73ers/synthetic/private/client.conf",
            b"-----BEGIN " b"PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----",
            b"custom-canary-value",
        ]
        for data in denied:
            with self.subTest(data=data[:24]):
                with self.assertRaises(static_gates.StaticGateError):
                    static_gates.scan_public_bytes(data, "negative-control", "custom-canary-value")
        static_gates.scan_public_bytes(b"synthetic public documentation\n", "safe")
        project = run._load_json(run.REPOSITORY / "harness/project.json")
        with mock.patch.object(static_gates, "scan_public_files") as scanned:
            static_gates.secret_boundary_inventory(run.REPOSITORY, project)
        scanned_paths = set(scanned.call_args[0][1])
        harness_modules = {
            str(path.relative_to(run.REPOSITORY))
            for path in (run.REPOSITORY / "tests/harness").glob("*.py")
        }
        self.assertTrue(harness_modules)
        self.assertLessEqual(harness_modules, scanned_paths)


class InterruptionRecoveryTests(HarnessTestCase):
    check_id = "WVH-08"

    def _repository(self, base):
        index = {
            "schema": "wirevpn.vector-index/1.0",
            "vectors": [vector_reference()],
            "content_sha256": ZERO_SHA256,
        }
        return make_characterization_repository(base, index, with_documents=True)

    def test_interruption_leaves_no_success_and_requires_fresh_evidence_case(self):
        repository = self._repository(self.base / "interrupted")
        evidence = self.base / "evidence"
        evidence.mkdir()
        project = {"sources": []}
        with mock.patch.object(run, "load_configuration", return_value=(project, {})):
            with mock.patch.object(run, "execute_case", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    run.characterize(repository, evidence)
            case = evidence / "cases/negative-control-vector"
            self.assertFalse((case / "result.json").exists())
            self.assertFalse((evidence / "report.json").exists())
            with mock.patch.object(run, "execute_case", return_value={"overall_result": "PASS"}):
                with self.assertRaises(OSError):
                    run.characterize(repository, evidence)
            fresh = self.base / "fresh-evidence"
            fresh.mkdir()
            result = {
                "vector_id": "negative-control-vector",
                "overall_result": "PASS",
                "execution_health": "COMPLETE",
                "contract_verdict": "PASS",
            }
            with mock.patch.object(run, "execute_case", return_value=result):
                results = run.characterize(repository, fresh)
            self.assertEqual(results[0]["overall_result"], "PASS")
            self.assertTrue((fresh / "cases/negative-control-vector/result.json").is_file())

    def test_execution_interrupt_cleans_synthetic_case_root(self):
        case = self.base / "case"
        evidence = self.base / "evidence"
        case.mkdir()
        evidence.mkdir()
        transformed = _write(case / "transformed.sh", "#!/bin/bash\n")
        adapter = mock.Mock()
        adapter.execute.side_effect = KeyboardInterrupt
        with mock.patch.object(run, "_prepare_case", return_value=(case, transformed, {}, {})):
            with mock.patch.object(run, "select_toolchain", return_value={"bash": {"path": "/bin/bash"}}):
                with mock.patch.object(run.containment, "DarwinContainment", return_value=adapter):
                    with self.assertRaises(KeyboardInterrupt):
                        run.execute_case(
                            self.base,
                            evidence,
                            {"vector_id": "negative-control-vector"},
                            {"arguments": [], "timeout_seconds": 1},
                            {},
                        )
        self.assertFalse(case.exists())

    def test_occupied_deterministic_case_root_is_not_deleted(self):
        parent = Path("/private/tmp") / ("wirevpn-harness-%d" % os.getuid())
        parent.mkdir(mode=0o700, exist_ok=True)
        vector_id = "occupied-%s" % self.base.name.replace("wirevpn-self-test-", "")
        case = parent / vector_id
        case.mkdir()
        marker = _write(case / "preserve.fixture", "preserve")
        try:
            with mock.patch.object(run, "select_toolchain", return_value={}):
                with self.assertRaises(run.RunnerError):
                    run._prepare_case(self.base, self.base, {"vector_id": vector_id}, {}, {})
            self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")
        finally:
            shutil.rmtree(case)


class EvidenceRootPolicyTests(HarnessTestCase):
    check_id = "WVH-10"

    def test_evidence_root_rejects_overlap_symlinks_and_open_permissions(self):
        repository = self.base / "repository"
        repository.mkdir()
        home = Path(run.pwd.getpwuid(os.getuid()).pw_dir)
        for candidate in (Path("/"), repository, self.base, home):
            with self.subTest(candidate=str(candidate)):
                with self.assertRaises(run.RunnerError):
                    run.prepare_evidence_root(candidate, repository)
        relative = Path("relative-evidence")
        with self.assertRaises(run.RunnerError):
            run.prepare_evidence_root(relative, repository)
        open_root = self.base / "open-evidence"
        open_root.mkdir(mode=0o755)
        with self.assertRaises(run.RunnerError):
            run.prepare_evidence_root(open_root, repository)
        actual = self.base / "actual-evidence"
        actual.mkdir(mode=0o700)
        alias = self.base / "evidence-alias"
        os.symlink(str(actual), str(alias))
        with self.assertRaises(run.RunnerError):
            run.prepare_evidence_root(alias, repository)
        self.assertEqual(run.prepare_evidence_root(actual, repository), actual.resolve())

    def test_raw_private_evidence_path_is_denied_in_public_artifacts(self):
        record = {
            "raw_evidence": {"identity": "/U\x73ers/synthetic/wirevpn-harness/raw-evidence.json"},
        }
        with self.assertRaises(static_gates.StaticGateError):
            static_gates.scan_public_bytes(json.dumps(record).encode("utf-8"), "report.json")


class ConcurrencyScheduleTests(HarnessTestCase):
    check_id = "WVA-28"

    def setUp(self):
        super().setUp()
        self.vector_schema = run._load_json(run.REPOSITORY / "tests/vectors/schema.json")

    def assertInvalid(self, document):
        with self.assertRaises(run.RunnerError):
            run.validate_concurrency(document)

    def test_valid_bounded_schedule(self):
        run.validate_concurrency(concurrency_document())

    def test_duplicate_ids_unknown_references_and_bounds_fail(self):
        mutations = []
        duplicate_actor = concurrency_document()
        duplicate_actor["actors"][1]["actor_id"] = "primary"
        mutations.append(duplicate_actor)
        duplicate_step = concurrency_document()
        duplicate_step["schedule"]["steps"][1]["step_id"] = "first"
        mutations.append(duplicate_step)
        duplicate_barrier = concurrency_document()
        duplicate_barrier["barriers"].append(duplicate_barrier["barriers"][0])
        mutations.append(duplicate_barrier)
        duplicate_signal = concurrency_document()
        duplicate_signal["signals"].append(duplicate_signal["signals"][0])
        mutations.append(duplicate_signal)
        duplicate_order = concurrency_document()
        duplicate_order["partial_orders"].append(duplicate_order["partial_orders"][0])
        mutations.append(duplicate_order)
        unknown_actor = concurrency_document()
        unknown_actor["schedule"]["steps"][0]["actor_id"] = "unknown"
        mutations.append(unknown_actor)
        unknown_barrier = concurrency_document()
        unknown_barrier["schedule"]["steps"][1]["after_barrier_ids"] = ["unknown"]
        mutations.append(unknown_barrier)
        unknown_signal = concurrency_document()
        unknown_signal["signals"][0]["at_step_id"] = "unknown"
        mutations.append(unknown_signal)
        too_many_steps = concurrency_document()
        too_many_steps["schedule"]["max_steps"] = 1
        mutations.append(too_many_steps)
        excessive_time = concurrency_document()
        excessive_time["schedule"]["steps"][1]["virtual_time_offset_ms"] = 101
        mutations.append(excessive_time)
        for document in mutations:
            with self.subTest(document=document):
                self.assertInvalid(document)

    def test_invalid_barriers_cycles_and_linearizations_fail(self):
        invalid_barrier = concurrency_document()
        invalid_barrier["barriers"][0]["after_step_ids"] = ["missing"]
        self.assertInvalid(invalid_barrier)
        self_cycle = concurrency_document()
        self_cycle["partial_orders"][0]["after_step_id"] = "first"
        self.assertInvalid(self_cycle)
        incomplete = concurrency_document()
        incomplete["allowed_linearizations"] = [["first", "first"]]
        self.assertInvalid(incomplete)
        wrong_order = concurrency_document()
        wrong_order["allowed_linearizations"] = [["second", "first"]]
        self.assertInvalid(wrong_order)

    def test_multi_actor_schema_requires_explicit_ordering_and_signal_rules(self):
        semantic = semantic_document()
        semantic["concurrency"] = concurrency_document()
        schema.require_valid(semantic, self.vector_schema)
        for field in ("barriers", "signals", "partial_orders", "allowed_linearizations", "final_state_invariants"):
            with self.subTest(field=field):
                changed = semantic_document()
                changed["concurrency"] = concurrency_document()
                del changed["concurrency"][field]
                with self.assertRaises(schema.SchemaValidationError):
                    schema.require_valid(changed, self.vector_schema)


def _flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            for test in _flatten(item):
                yield test
        else:
            yield item


def run_checks(toolchain_path=None):
    global TOOLCHAIN_PATH
    TOOLCHAIN_PATH = Path(toolchain_path) if toolchain_path is not None else run.REPOSITORY / "tests/toolchain.json"
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromModule(sys.modules[__name__]))
    suite.addTests(loader.loadTestsFromModule(containment_self_test))
    tests = list(_flatten(suite))
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=1).run(suite)
    failed = {test.id(): (test, detail) for test, detail in result.failures + result.errors}
    skipped = {test.id(): reason for test, reason in result.skipped}
    grouped = {}
    for test in tests:
        check_id = getattr(test.__class__, "check_id", None)
        if check_id is None and test.__class__.__module__ == containment_self_test.__name__:
            check_id = "WVH-09"
        if check_id is None:
            continue
        group = grouped.setdefault(check_id, {"tests": 0, "failures": [], "skips": []})
        group["tests"] += 1
        if test.id() in failed:
            group["failures"].append({"test": test.id(), "detail": failed[test.id()][1][-4000:]})
        if test.id() in skipped:
            group["skips"].append({"test": test.id(), "reason": skipped[test.id()]})
    results = []
    for check_id in sorted(grouped):
        group = grouped[check_id]
        if group["failures"]:
            health, verdict, overall = "PARTIAL", "NOT_REACHED", "HARNESS_FAIL"
        elif group["skips"] or not group["tests"]:
            health, verdict, overall = "NOT_RUN", "NOT_REACHED", "NOT_RUN"
        else:
            health, verdict, overall = "COMPLETE", "PASS", "PASS"
        results.append({
            "check_id": check_id,
            "check_version": "1.0.0",
            "requirement": "required",
            "execution_health": health,
            "contract_verdict": verdict,
            "overall_result": overall,
            "test_count": group["tests"],
            "failures": group["failures"],
            "skips": group["skips"],
        })
    return results


if __name__ == "__main__":
    unittest.main()
