from __future__ import annotations

import unittest
from copy import deepcopy
from datetime import UTC, datetime, timedelta, timezone

from ctfmesh_domain import (
    ActorKind,
    ActorRef,
    ArtifactRole,
    ChallengeCategory,
    ChallengeManifest,
    EvidenceRef,
    Fact,
    FactStatus,
)
from pydantic import ValidationError

SHA256 = "a" * 64


def valid_manifest_data() -> dict[str, object]:
    return {
        "apiVersion": "ctfmesh.io/v1alpha1",
        "kind": "Challenge",
        "metadata": {
            "name": "operator-contract-case",
            "category": "web",
            "tags": ["contract-test", "source-available"],
        },
        "spec": {
            "mode": "assisted",
            "target": {
                "type": "docker_compose",
                "compose_file": "./challenge/docker-compose.yml",
                "service": "app",
                "healthcheck": {
                    "url": "http://challenge:8080/health",
                    "expected_status": 200,
                },
                "allowed_endpoints": [
                    {"host": "challenge", "ports": [8080], "protocols": ["http"]}
                ],
                "target_aliases": {"lab": "http://challenge:8080/"},
            },
            "artifacts": [{"path": "./dist/source.zip", "role": "source"}],
            "flag": {
                "patterns": [r"CTF\{[A-Za-z0-9_:-]+\}"],
                "source_policy": {
                    "allow_from_target_response": True,
                    "allow_from_target_filesystem": True,
                    "deny_from_input_artifacts": True,
                },
                "replay_count": 2,
            },
            "limits": {
                "wall_time_seconds": 3600,
                "max_worker_turns": 120,
                "max_tool_calls": 500,
                "max_http_requests": 1500,
                "max_parallel_requests": 10,
                "max_cost_usd": 20.0,
                "max_artifact_bytes": 1_073_741_824,
            },
            "providers": {
                "preferred": "codex",
                "fallbacks": ["claude-code", "openai-responses"],
            },
            "memory": {
                "namespace": "personal-techniques",
                "cutoff": datetime(2026, 7, 18, tzinfo=UTC),
                "internet_search": False,
            },
        },
    }


class ChallengeManifestTests(unittest.TestCase):
    def test_valid_manifest_normalizes_paths_hosts_and_utc(self) -> None:
        data = valid_manifest_data()
        cutoff = datetime(2026, 7, 18, 7, tzinfo=timezone(timedelta(hours=7)))
        data["spec"]["memory"]["cutoff"] = cutoff  # type: ignore[index]

        manifest = ChallengeManifest.model_validate(data)

        self.assertEqual(manifest.spec.target.compose_file, "challenge/docker-compose.yml")
        self.assertEqual(manifest.spec.target.allowed_endpoints[0].host, "challenge")
        self.assertEqual(manifest.spec.target.target_aliases, {"lab": "http://challenge:8080"})
        self.assertEqual(manifest.spec.memory.cutoff.utcoffset(), timedelta(0))
        self.assertEqual(manifest.spec.memory.cutoff.hour, 0)

    def test_manifest_accepts_utc_iso_datetime_from_json_or_yaml(self) -> None:
        data = valid_manifest_data()
        data["spec"]["memory"]["cutoff"] = "2026-07-18T00:00:00Z"  # type: ignore[index]
        manifest = ChallengeManifest.model_validate(data)
        self.assertEqual(manifest.spec.memory.cutoff, datetime(2026, 7, 18, tzinfo=UTC))

    def test_remote_target_requires_exact_health_and_reset_scope(self) -> None:
        data = valid_manifest_data()
        data["spec"]["target"] = {  # type: ignore[index]
            "type": "remote",
            "healthcheck": {"url": "https://lab.example.test/health", "expected_status": 200},
            "reset_url": "https://lab.example.test/reset",
            "allowed_endpoints": [
                {"host": "lab.example.test", "ports": [443], "protocols": ["https"]}
            ],
        }

        manifest = ChallengeManifest.model_validate(data)

        self.assertEqual(manifest.spec.target.type, "remote")
        self.assertIsNone(manifest.spec.target.compose_file)

    def test_ui_source_binding_is_limited_to_assisted_remote_cases(self) -> None:
        data = valid_manifest_data()
        data["spec"]["target"] = {  # type: ignore[index]
            "type": "remote",
            "healthcheck": {"url": "https://lab.example.test/", "expected_status": 200},
            "allowed_endpoints": [
                {"host": "lab.example.test", "ports": [443], "protocols": ["https"]}
            ],
            "target_aliases": {"target": "https://lab.example.test"},
        }
        data["spec"]["source"] = {  # type: ignore[index]
            "intake_id": "intake_0123456789abcdef0123456789abcdef",
            "slot_id": "source-slot-1",
        }

        manifest = ChallengeManifest.model_validate(data)
        self.assertEqual(manifest.spec.source.slot_id, "source-slot-1")  # type: ignore[union-attr]

        data["spec"]["mode"] = "contest"  # type: ignore[index]
        with self.assertRaisesRegex(ValidationError, "limited to assisted"):
            ChallengeManifest.model_validate(data)

    def test_category_enum_accepts_all_supported_ctf_disciplines(self) -> None:
        for category in ChallengeCategory:
            with self.subTest(category=category.value):
                data = valid_manifest_data()
                data["metadata"]["category"] = category.value  # type: ignore[index]

                manifest = ChallengeManifest.model_validate(data)

                self.assertEqual(manifest.metadata.category, category)

    def test_artifact_bundle_accepts_offline_inputs_and_default_profiles(self) -> None:
        data = valid_manifest_data()
        data["metadata"]["category"] = "forensics"  # type: ignore[index]
        data["spec"]["target"] = {"type": "artifact_bundle"}  # type: ignore[index]
        data["spec"]["artifacts"] = [  # type: ignore[index]
            {"path": "inputs/challenge.pcapng", "role": "pcap"},
            {"path": "inputs/memory.raw", "role": "memory_dump"},
            {"path": "inputs/challenge.7z", "role": "archive"},
        ]

        manifest = ChallengeManifest.model_validate(data)

        self.assertEqual(manifest.spec.target.type, "artifact_bundle")
        self.assertEqual(manifest.spec.target.allowed_endpoints, ())
        self.assertEqual(manifest.spec.tool_profile, ())
        self.assertEqual(manifest.spec.skill_profile, ())
        self.assertEqual(
            tuple(artifact.role for artifact in manifest.spec.artifacts),
            (ArtifactRole.PCAP, ArtifactRole.MEMORY_DUMP, ArtifactRole.ARCHIVE),
        )

    def test_artifact_bundle_rejects_declared_runtime_or_network_fields(self) -> None:
        forbidden_fields = {
            "compose_file": "docker-compose.yml",
            "service": "challenge",
            "healthcheck": {"url": "http://challenge:8080/health", "expected_status": 200},
            "allowed_endpoints": [],
            "target_aliases": {"lab": "http://challenge:8080"},
            "reset_url": "http://challenge:8080/reset",
        }
        for field, value in forbidden_fields.items():
            with self.subTest(field=field):
                data = valid_manifest_data()
                data["spec"]["target"] = {"type": "artifact_bundle", field: value}  # type: ignore[index]
                with self.assertRaisesRegex(
                    ValidationError, "artifact_bundle target cannot declare"
                ):
                    ChallengeManifest.model_validate(data)

    def test_target_aliases_are_origin_only_and_pinned_to_exact_scope(self) -> None:
        invalid_path = valid_manifest_data()
        invalid_path["spec"]["target"]["target_aliases"] = {  # type: ignore[index]
            "lab": "http://challenge:8080/base"
        }
        with self.assertRaisesRegex(ValidationError, "origin-only HTTP"):
            ChallengeManifest.model_validate(invalid_path)

        out_of_scope = valid_manifest_data()
        out_of_scope["spec"]["target"]["target_aliases"] = {  # type: ignore[index]
            "other": "http://other:8080"
        }
        with self.assertRaisesRegex(ValidationError, "outside allowed_endpoints"):
            ChallengeManifest.model_validate(out_of_scope)

    def test_profiles_are_defaulted_strict_and_duplicate_free(self) -> None:
        data = valid_manifest_data()
        data["spec"]["tool_profile"] = ["files.read", "sandbox.execute"]  # type: ignore[index]
        data["spec"]["skill_profile"] = ["common.artifact-triage", "reverse.triage"]  # type: ignore[index]

        manifest = ChallengeManifest.model_validate(data)

        self.assertEqual(manifest.spec.tool_profile, ("files.read", "sandbox.execute"))
        self.assertEqual(
            manifest.spec.skill_profile,
            ("common.artifact-triage", "reverse.triage"),
        )

        duplicate = valid_manifest_data()
        duplicate["spec"]["tool_profile"] = ["files.read", "files.read"]  # type: ignore[index]
        with self.assertRaisesRegex(ValidationError, "profile entries must not contain duplicates"):
            ChallengeManifest.model_validate(duplicate)

        invalid = valid_manifest_data()
        invalid["spec"]["skill_profile"] = ["invalid profile"]  # type: ignore[index]
        with self.assertRaises(ValidationError):
            ChallengeManifest.model_validate(invalid)

    def test_network_targets_still_require_an_exact_http_scope(self) -> None:
        data = valid_manifest_data()
        data["spec"]["target"] = {"type": "remote"}  # type: ignore[index]
        with self.assertRaisesRegex(ValidationError, "remote target requires healthcheck"):
            ChallengeManifest.model_validate(data)

    def test_unknown_field_is_rejected(self) -> None:
        data = valid_manifest_data()
        data["unexpected"] = True
        with self.assertRaises(ValidationError):
            ChallengeManifest.model_validate(data)

    def test_naive_cutoff_is_rejected(self) -> None:
        data = valid_manifest_data()
        data["spec"]["memory"]["cutoff"] = datetime(2026, 7, 18)  # type: ignore[index]
        with self.assertRaisesRegex(ValidationError, "timezone-aware"):
            ChallengeManifest.model_validate(data)

    def test_wildcard_scope_is_rejected(self) -> None:
        data = valid_manifest_data()
        data["spec"]["target"]["allowed_endpoints"][0]["host"] = "*.example.test"  # type: ignore[index]
        with self.assertRaisesRegex(ValidationError, "single exact hostname"):
            ChallengeManifest.model_validate(data)

    def test_healthcheck_must_be_inside_exact_allowlist(self) -> None:
        data = valid_manifest_data()
        data["spec"]["target"]["healthcheck"]["url"] = "http://challenge:8081/health"  # type: ignore[index]
        with self.assertRaisesRegex(ValidationError, "outside allowed_endpoints"):
            ChallengeManifest.model_validate(data)

    def test_all_budget_fields_are_required_and_finite(self) -> None:
        missing = valid_manifest_data()
        del missing["spec"]["limits"]["max_tool_calls"]  # type: ignore[index]
        with self.assertRaises(ValidationError):
            ChallengeManifest.model_validate(missing)

        infinite = valid_manifest_data()
        infinite["spec"]["limits"]["max_cost_usd"] = float("inf")  # type: ignore[index]
        with self.assertRaises(ValidationError):
            ChallengeManifest.model_validate(infinite)

    def test_contest_mode_denies_public_internet_and_search(self) -> None:
        search = valid_manifest_data()
        search["spec"]["mode"] = "contest"  # type: ignore[index]
        search["spec"]["memory"]["internet_search"] = True  # type: ignore[index]
        with self.assertRaisesRegex(ValidationError, "internet search"):
            ChallengeManifest.model_validate(search)

        public = valid_manifest_data()
        public["spec"]["mode"] = "contest"  # type: ignore[index]
        public["spec"]["target"]["allowed_endpoints"][0]["host"] = "example.com"  # type: ignore[index]
        public["spec"]["target"]["healthcheck"]["url"] = "http://example.com:8080/health"  # type: ignore[index]
        public["spec"]["target"]["target_aliases"] = {"lab": "http://example.com:8080"}  # type: ignore[index]
        with self.assertRaisesRegex(ValidationError, "public Internet"):
            ChallengeManifest.model_validate(public)


class EvidenceInvariantTests(unittest.TestCase):
    def _fact_data(self) -> dict[str, object]:
        return {
            "id": "fact-1",
            "run_id": "run-1",
            "statement": "The declared metadata is not constrained.",
            "confidence": 0.9,
            "status": "confirmed",
            "evidence": [],
            "created_by": {"kind": "worker", "id": "worker-1"},
            "created_at": datetime.now(UTC),
        }

    def test_worker_cannot_confirm_fact_without_evidence(self) -> None:
        with self.assertRaisesRegex(ValidationError, "confirmed facts require evidence"):
            Fact.model_validate(self._fact_data())

    def test_human_assertion_can_confirm_without_tool_evidence(self) -> None:
        data = self._fact_data()
        data["created_by"] = {"kind": "human", "id": "operator-1"}
        fact = Fact.model_validate(data)
        self.assertEqual(fact.status, FactStatus.CONFIRMED)
        self.assertEqual(fact.created_by.kind, ActorKind.HUMAN)

    def test_digest_backed_evidence_allows_worker_confirmation(self) -> None:
        data = deepcopy(self._fact_data())
        data["evidence"] = [
            {
                "artifact_id": "artifact-1",
                "locator": "app.py:42",
                "digest": SHA256,
                "observed_at": datetime.now(UTC),
            }
        ]
        fact = Fact.model_validate(data)
        self.assertIsInstance(fact.evidence[0], EvidenceRef)

    def test_evidence_rejects_non_sha256_digest(self) -> None:
        data = self._fact_data()
        data["evidence"] = [
            {
                "artifact_id": "artifact-1",
                "digest": "not-a-digest",
                "observed_at": datetime.now(UTC),
            }
        ]
        with self.assertRaises(ValidationError):
            Fact.model_validate(data)

    def test_contract_is_strict_about_scalar_types(self) -> None:
        with self.assertRaises(ValidationError):
            ActorRef.model_validate({"kind": "human", "id": 123})


if __name__ == "__main__":
    unittest.main()
