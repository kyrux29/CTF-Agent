from __future__ import annotations

import unittest

from ctfmesh_domain import ChallengeManifest
from ctfmesh_policy import (
    Decision,
    PolicyDecisionPoint,
    PolicyRequest,
    ReasonCode,
)
from test_domain import valid_manifest_data


def make_request(**overrides: object) -> PolicyRequest:
    data: dict[str, object] = {
        "run_id": "run-1",
        "mode": "assisted",
        "actor": {"kind": "worker", "id": "worker-1"},
        "tool": "http.request",
        "risk": "target_interaction",
        "allowed_tools": ["http.request"],
        "requested_url": "http://challenge:8080/admin?id=1",
        "budget_remaining": {
            "tool_calls": 5,
            "http_requests": 5,
            "cost_usd": 5.0,
        },
        "approval_state": "not_requested",
    }
    data.update(overrides)
    return PolicyRequest.model_validate(data)


class PolicyDecisionPointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = ChallengeManifest.model_validate(valid_manifest_data())
        self.pdp = PolicyDecisionPoint()

    def test_exact_manifest_scope_is_allowed(self) -> None:
        result = self.pdp.decide(make_request(), self.manifest)
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertEqual(result.reason_code, ReasonCode.MANIFEST_SCOPE_MATCH)
        self.assertEqual(
            result.constraints,
            {"protocol": "http", "host": "challenge", "port": 8080},
        )

    def test_similar_but_not_exact_url_scope_is_denied(self) -> None:
        denied_urls = (
            "http://challenge.evil:8080/",
            "http://challenge:8081/",
            "https://challenge:8080/",
            "http://challenge:8080/#fragment",
            "http://user:password@challenge:8080/",
        )
        for url in denied_urls:
            with self.subTest(url=url):
                result = self.pdp.decide(make_request(requested_url=url), self.manifest)
                self.assertEqual(result.decision, Decision.DENY)
                self.assertEqual(result.reason_code, ReasonCode.SCOPE_NOT_ALLOWED)

    def test_tool_not_on_task_allowlist_is_denied_by_default(self) -> None:
        result = self.pdp.decide(make_request(allowed_tools=["files.list"]), self.manifest)
        self.assertEqual(result.decision, Decision.DENY)
        self.assertEqual(result.reason_code, ReasonCode.TOOL_NOT_ALLOWED)

    def test_target_interaction_requires_explicit_scope(self) -> None:
        result = self.pdp.decide(make_request(requested_url=None), self.manifest)
        self.assertEqual(result.decision, Decision.DENY)
        self.assertEqual(result.reason_code, ReasonCode.SCOPE_REQUIRED)

    def test_budget_exhaustion_and_forged_remaining_budget_are_denied(self) -> None:
        exhausted = make_request(
            budget_remaining={"tool_calls": 1, "http_requests": 0, "cost_usd": 1.0}
        )
        result = self.pdp.decide(exhausted, self.manifest)
        self.assertEqual(result.reason_code, ReasonCode.BUDGET_EXHAUSTED)

        invalid = make_request(
            budget_remaining={"tool_calls": 501, "http_requests": 5, "cost_usd": 1.0}
        )
        result = self.pdp.decide(invalid, self.manifest)
        self.assertEqual(result.reason_code, ReasonCode.BUDGET_INVALID)

    def test_high_impact_requires_approval_then_allows(self) -> None:
        pending = make_request(risk="high_impact")
        result = self.pdp.decide(pending, self.manifest)
        self.assertEqual(result.decision, Decision.REQUIRE_APPROVAL)

        approved = make_request(risk="high_impact", approval_state="approved")
        result = self.pdp.decide(approved, self.manifest)
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertEqual(result.reason_code, ReasonCode.APPROVAL_GRANTED)

        denied = make_request(risk="high_impact", approval_state="denied")
        result = self.pdp.decide(denied, self.manifest)
        self.assertEqual(result.decision, Decision.DENY)
        self.assertEqual(result.reason_code, ReasonCode.APPROVAL_DENIED)

    def test_read_only_workspace_path_is_bounded(self) -> None:
        allowed = make_request(
            tool="files.read_text_range",
            risk="read_only",
            allowed_tools=["files.read_text_range"],
            requested_url=None,
            workspace_root="/tmp/ctfmesh-workspace",
            requested_path="source/app.py",
        )
        self.assertEqual(self.pdp.decide(allowed, self.manifest).decision, Decision.ALLOW)

        escaped = make_request(
            tool="files.read_text_range",
            risk="read_only",
            allowed_tools=["files.read_text_range"],
            requested_url=None,
            workspace_root="/tmp/ctfmesh-workspace",
            requested_path="../outside.txt",
        )
        result = self.pdp.decide(escaped, self.manifest)
        self.assertEqual(result.decision, Decision.DENY)
        self.assertEqual(result.reason_code, ReasonCode.WORKSPACE_SCOPE_DENIED)

    def test_url_cannot_be_smuggled_through_read_only_risk(self) -> None:
        request = make_request(risk="read_only")
        result = self.pdp.decide(request, self.manifest)
        self.assertEqual(result.decision, Decision.DENY)
        self.assertEqual(result.reason_code, ReasonCode.RISK_SCOPE_MISMATCH)

    def test_request_mode_must_match_manifest(self) -> None:
        request = make_request(mode="coach")
        result = self.pdp.decide(request, self.manifest)
        self.assertEqual(result.decision, Decision.DENY)
        self.assertEqual(result.reason_code, ReasonCode.MODE_MISMATCH)


if __name__ == "__main__":
    unittest.main()
