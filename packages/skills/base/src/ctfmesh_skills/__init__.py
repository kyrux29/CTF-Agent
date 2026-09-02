"""Provider-neutral, declarative CTF skill contracts.

The package intentionally contains skill metadata only.  It does not load
plugins, execute prompts, invoke tools, or perform I/O.
"""

from .registry import (
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

__all__ = [
    "BUILTIN_SKILLS",
    "CATALOG_SOURCES",
    "DuplicateSkillError",
    "LJAGIELLO_CTF_SKILLS_CATALOG_SOURCE",
    "MCP_SOURCE_PROFILES",
    "McpSourceProfile",
    "SkillCategory",
    "SkillRegistry",
    "SkillSelectionRequest",
    "SkillSourceRef",
    "SkillSpec",
    "UnknownSkillError",
    "builtin_skill_registry",
    "mcp_source_profiles_for",
    "skill_guidance",
]
