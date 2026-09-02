"""P7 proofs for digest-pinned local technique retrieval and contest opt-out."""

from __future__ import annotations

from pathlib import Path

import pytest
from ctfmesh_knowledge import (
    KnowledgeCorpus,
    KnowledgeCorpusError,
    KnowledgeRetrievalMode,
    render_knowledge_context,
    retrieve_local_knowledge,
)


def _write_corpus(root: Path) -> None:
    root.mkdir()
    (root / "padding-oracle.md").write_text(
        "# CBC padding oracle\n\n"
        "For a padding oracle, vary the preceding ciphertext block and use the "
        "oracle response to recover one plaintext byte at a time.\n\n"
        "Historical flag: CTF{never_send_old_writeup_flags}\n",
        encoding="utf-8",
    )
    (root / "heap-notes.md").write_text(
        "# Heap notes\n\nInspect allocator metadata and reproduction receipts first.\n",
        encoding="utf-8",
    )
    (root / "web-ssti.md").write_text(
        "# Server templates\n\nClassify the template engine before trying a payload.\n",
        encoding="utf-8",
    )


def test_local_corpus_pins_three_documents_and_returns_padding_oracle_excerpt(
    tmp_path: Path,
) -> None:
    """P7 acceptance proof: deterministic query retrieves the right local note."""

    root = tmp_path / "writeups"
    _write_corpus(root)

    corpus = KnowledgeCorpus.load(root)
    retrieval = corpus.retrieve(query="padding oracle", top_k=2)
    rendered = render_knowledge_context(retrieval)

    assert len(corpus.pin.documents) == 3
    assert [item.document_id for item in corpus.pin.documents] == [
        "heap-notes.md",
        "padding-oracle.md",
        "web-ssti.md",
    ]
    assert len(corpus.pin.sha256) == 64
    assert retrieval.mode is KnowledgeRetrievalMode.RETRIEVED
    assert retrieval.excerpts[0].document_id == "padding-oracle.md"
    assert "preceding ciphertext block" in retrieval.excerpts[0].text
    assert "CTF{never_send_old_writeup_flags}" not in rendered
    padding_note = next(
        item for item in corpus.documents if item.document_id == "padding-oracle.md"
    )
    assert "[redacted flag]" in padding_note.sanitized_text


def test_pinned_corpus_rejects_a_changed_operator_document(tmp_path: Path) -> None:
    """A previously reviewed source set cannot silently change under a pin."""

    root = tmp_path / "writeups"
    _write_corpus(root)
    original = KnowledgeCorpus.load(root)
    (root / "padding-oracle.md").write_text("# Changed\n", encoding="utf-8")

    with pytest.raises(KnowledgeCorpusError, match="knowledge_corpus_pin_mismatch"):
        KnowledgeCorpus.load(root, expected_pin=original.pin)


def test_contest_offline_returns_zero_hits_without_loading_a_missing_root(tmp_path: Path) -> None:
    """The hard offline gate precedes root validation, corpus scan, and query use."""

    retrieval = retrieve_local_knowledge(
        tmp_path / "does-not-exist",
        query="padding oracle",
        contest_offline=True,
    )

    assert retrieval.mode is KnowledgeRetrievalMode.CONTEST_OFFLINE
    assert retrieval.corpus_pin is None
    assert retrieval.excerpts == ()


def test_corpus_rejects_symlinks_instead_of_following_operator_filesystem_paths(
    tmp_path: Path,
) -> None:
    """Corpus construction cannot escape its declared local root through a link."""

    root = tmp_path / "writeups"
    _write_corpus(root)
    external = tmp_path / "outside.md"
    external.write_text("# Outside\n", encoding="utf-8")
    (root / "escape.md").symlink_to(external)

    with pytest.raises(KnowledgeCorpusError, match="knowledge_symlink_forbidden"):
        KnowledgeCorpus.load(root)
