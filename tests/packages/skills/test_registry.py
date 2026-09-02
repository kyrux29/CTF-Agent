"""Focused tests for the declarative, deny-by-default skill registry."""

from __future__ import annotations

import pytest
from ctfmesh_skills import (
    BUILTIN_SKILLS,
    CATALOG_SOURCES,
    LJAGIELLO_CTF_SKILLS_CATALOG_SOURCE,
    MCP_SOURCE_PROFILES,
    DuplicateSkillError,
    McpSourceProfile,
    SkillCategory,
    SkillRegistry,
    SkillSelectionRequest,
    SkillSourceRef,
    SkillSpec,
    UnknownSkillError,
    builtin_skill_registry,
    mcp_source_profiles_for,
    skill_guidance,
)
from pydantic import ValidationError


def test_builtin_registry_covers_requested_ctf_categories() -> None:
    specs = builtin_skill_registry().list_specs()

    assert [spec.id for spec in specs] == sorted(spec.id for spec in specs)
    assert {spec.id for spec in specs} == {
        "common.artifact-triage",
        "ai_ml.triage",
        "blockchain.triage",
        "crypto.triage",
        "forensics.triage",
        "hardware.triage",
        "misc.triage",
        "mobile.triage",
        "osint.triage",
        "programming.triage",
        "pwn.triage",
        "reverse.triage",
        "stego.triage",
        "web.triage",
    }
    assert {spec.category for spec in specs} == set(SkillCategory)
    assert all(len(spec.prompt_digest) == 64 for spec in specs)


def test_selection_is_deny_by_default() -> None:
    registry = builtin_skill_registry()

    assert registry.select(SkillSelectionRequest()) == ()
    assert (
        registry.select(
            SkillSelectionRequest(
                requested_categories=(SkillCategory.WEB,),
                allowed_skill_ids=("web.triage",),
            )
        )
        == ()
    )


def test_selection_requires_all_explicit_gates_and_is_deterministic() -> None:
    registry = builtin_skill_registry()
    web = registry.get("web.triage")
    common = registry.get("common.artifact-triage")

    request = SkillSelectionRequest(
        requested_categories=(SkillCategory.COMMON, SkillCategory.WEB),
        allowed_skill_ids=("common.artifact-triage", "web.triage"),
        allowed_tools=("artifacts.inspect", "files.list"),
        available_capabilities=("workspace.read",),
        approved_prompt_digests=tuple(sorted((common.prompt_digest, web.prompt_digest))),
    )

    assert [spec.id for spec in registry.select(request)] == [
        "common.artifact-triage",
        "web.triage",
    ]
    assert registry.select(request) == registry.select(request)


def test_selection_rejects_missing_tool_or_capability_implicitly() -> None:
    registry = builtin_skill_registry()
    web = registry.get("web.triage")

    missing_tool = SkillSelectionRequest(
        requested_categories=(SkillCategory.WEB,),
        allowed_skill_ids=("web.triage",),
        allowed_tools=("files.list",),
        available_capabilities=("workspace.read",),
        approved_prompt_digests=(web.prompt_digest,),
    )
    missing_capability = SkillSelectionRequest(
        requested_categories=(SkillCategory.WEB,),
        allowed_skill_ids=("web.triage",),
        allowed_tools=("artifacts.inspect", "files.list"),
        available_capabilities=(),
        approved_prompt_digests=(web.prompt_digest,),
    )

    assert registry.select(missing_tool) == ()
    assert registry.select(missing_capability) == ()


def test_selection_rejects_an_unapproved_prompt_digest() -> None:
    registry = builtin_skill_registry()

    request = SkillSelectionRequest(
        requested_categories=(SkillCategory.WEB,),
        allowed_skill_ids=("web.triage",),
        allowed_tools=("artifacts.inspect", "files.list"),
        available_capabilities=("workspace.read",),
        approved_prompt_digests=("0" * 64,),
    )

    assert registry.select(request) == ()


def test_registry_rejects_duplicate_ids_and_unknown_lookup() -> None:
    first = BUILTIN_SKILLS[0]
    duplicate = first.model_copy(update={"version": "2.0.0"})
    registry = SkillRegistry((first,))

    with pytest.raises(DuplicateSkillError, match="duplicate skill registration"):
        registry.register(duplicate)
    with pytest.raises(UnknownSkillError, match="unknown skill"):
        registry.get("does-not-exist")


def test_contracts_reject_unknown_fields_and_noncanonical_allowlists() -> None:
    spec = SkillSpec.model_validate(
        {
            "id": "web.triage",
            "category": "web",
            "version": "1.0.0",
            "description": "test",
            "allowed_tools": [],
            "required_capabilities": [],
            "prompt_digest": "a" * 64,
        }
    )
    assert spec.category is SkillCategory.WEB

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SkillSpec.model_validate(
            {
                "id": "web.triage",
                "category": "web",
                "version": "1.0.0",
                "description": "test",
                "allowed_tools": [],
                "required_capabilities": [],
                "prompt_digest": "a" * 64,
                "unexpected": True,
            }
        )
    with pytest.raises(ValidationError, match="deterministic sorted order"):
        SkillSelectionRequest(
            allowed_tools=("http.request", "files.read"),
        )


def test_reviewed_guidance_is_digest_pinned_and_nonempty() -> None:
    registry = builtin_skill_registry()
    crypto = registry.get("crypto.triage")

    assert "representation" in skill_guidance(crypto)
    tampered = crypto.model_copy(update={"prompt_digest": "0" * 64})
    with pytest.raises(RuntimeError, match="digest mismatch"):
        skill_guidance(tampered)


def test_reviewed_catalog_source_is_commit_license_and_content_pinned() -> None:
    source = LJAGIELLO_CTF_SKILLS_CATALOG_SOURCE

    assert source in CATALOG_SOURCES
    assert {item.role for item in CATALOG_SOURCES} == {
        "reviewed_catalog",
        "reference_only",
    }
    assert source.repository_url == "https://github.com/ljagiello/ctf-skills"
    assert source.revision == "d6662d26b5ed3caa56f5eaf6eb887964f3747162"
    assert source.path == "README.md"
    assert (
        source.content_sha256 == "6c8740960ce9a51bf3cda6d41281016b918e820cb46236772e9090a2bf5bd377"
    )
    assert source.role == "reviewed_catalog"
    assert source.license_spdx == "MIT"
    assert source.license_path == "LICENSE"
    assert (
        source.license_sha256 == "25fb2cfc684b4f1e510e8ecf2deeeedfe9ee80ebae4c41b806baa439857a394b"
    )


def test_source_ref_rejects_mutable_or_noncanonical_supply_chain_metadata() -> None:
    source = LJAGIELLO_CTF_SKILLS_CATALOG_SOURCE.model_dump()

    with pytest.raises(ValidationError):
        SkillSourceRef.model_validate({**source, "revision": "main"})
    with pytest.raises(ValidationError, match="canonical credential-free HTTPS"):
        SkillSourceRef.model_validate(
            {**source, "repository_url": "http://github.com/ljagiello/ctf-skills"}
        )
    with pytest.raises(ValidationError, match="must not contain traversal"):
        SkillSourceRef.model_validate({**source, "path": "../ctf-web/SKILL.md"})
    with pytest.raises(ValidationError):
        SkillSourceRef.model_validate({**source, "content_sha256": "0" * 63})
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SkillSourceRef.model_validate({**source, "branch": "main"})


def test_source_references_are_immutable_and_canonical_on_skills() -> None:
    registry = builtin_skill_registry()
    web = registry.get("web.triage")
    crypto = registry.get("crypto.triage")

    assert [(source.repository_url, source.path, source.role) for source in web.source_refs] == [
        ("https://github.com/OWASP/wstg", "README.md", "reference_only"),
        ("https://github.com/ljagiello/ctf-skills", "README.md", "reviewed_catalog"),
        ("https://github.com/ljagiello/ctf-skills", "ctf-web/SKILL.md", "reviewed_catalog"),
    ]
    assert [source.path for source in crypto.source_refs] == ["README.md", "ctf-crypto/SKILL.md"]
    assert [
        source.repository_url for source in registry.get("common.artifact-triage").source_refs
    ] == ["https://github.com/google/google-ctf"]
    assert registry.get("mobile.triage").source_refs == ()
    assert web.version == "1.2.0"
    assert skill_guidance(web)

    # JSON boundaries submit arrays; model_validate proves the contract freezes
    # that mutable representation into the immutable tuple used at runtime.
    spec = SkillSpec.model_validate(
        {
            "id": "web.reference-test",
            "category": "web",
            "version": "1.0.0",
            "description": "test source provenance",
            "prompt_digest": "b" * 64,
            "source_refs": list(web.source_refs),
        }
    )
    assert spec.source_refs == web.source_refs

    with pytest.raises(ValidationError, match="duplicate source references"):
        SkillSpec(
            id="web.duplicate-source",
            category=SkillCategory.WEB,
            version="1.0.0",
            description="test source provenance",
            prompt_digest="b" * 64,
            source_refs=(LJAGIELLO_CTF_SKILLS_CATALOG_SOURCE,) * 2,
        )
    with pytest.raises(ValidationError, match="deterministic sorted order"):
        SkillSpec(
            id="web.unsorted-source",
            category=SkillCategory.WEB,
            version="1.0.0",
            description="test source provenance",
            prompt_digest="b" * 64,
            source_refs=tuple(reversed(web.source_refs)),
        )


def test_category_aware_mcp_profiles_are_static_local_only_metadata() -> None:
    web_profiles = mcp_source_profiles_for(SkillCategory.WEB)

    assert len(web_profiles) == 1
    profile = web_profiles[0]
    assert profile.id == "web.readonly-artifacts"
    assert profile.category is SkillCategory.WEB
    assert profile.transport == "local_stdio"
    assert profile.server_id == "ctfmesh.local.readonly"
    assert profile.mcp_tool_names == ("artifacts_inspect", "files_list")
    assert profile.runtime_tool_ids == ("artifacts.inspect", "files.list")
    assert profile.source_refs == builtin_skill_registry().get("web.triage").source_refs
    assert profile.allows_external_connection is False
    assert profile.allows_network is False
    assert profile.allows_code_execution is False
    assert mcp_source_profiles_for(SkillCategory.MOBILE) == ()
    assert {item.category for item in MCP_SOURCE_PROFILES} == {
        SkillCategory.COMMON,
        SkillCategory.AI_ML,
        SkillCategory.CRYPTO,
        SkillCategory.FORENSICS,
        SkillCategory.MISC,
        SkillCategory.OSINT,
        SkillCategory.PWN,
        SkillCategory.REVERSE,
        SkillCategory.WEB,
    }


def test_mcp_source_profile_rejects_external_connection_or_unknown_fields() -> None:
    profile = mcp_source_profiles_for(SkillCategory.WEB)[0].model_dump()

    with pytest.raises(ValidationError):
        McpSourceProfile.model_validate({**profile, "allows_external_connection": True})
    with pytest.raises(ValidationError):
        McpSourceProfile.model_validate({**profile, "allows_network": True})
    with pytest.raises(ValidationError):
        McpSourceProfile.model_validate({**profile, "transport": "remote_http"})
    with pytest.raises(ValidationError, match="local read-only facade"):
        McpSourceProfile.model_validate({**profile, "mcp_tool_names": ["shell_exec"]})
    with pytest.raises(ValidationError, match="local read-only facade"):
        McpSourceProfile.model_validate({**profile, "runtime_tool_ids": ["http.request"]})
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        McpSourceProfile.model_validate({**profile, "endpoint": "https://mcp.example.test"})
