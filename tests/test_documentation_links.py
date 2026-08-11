from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
INLINE_LINK = re.compile(r"!?\[[^\]]*\]\((?P<target><[^>]+>|[^\s)]+)")
REFERENCE_LINK = re.compile(
    r"^\s*\[[^\]]+\]:\s*(?P<target><[^>]+>|\S+)",
    flags=re.MULTILINE,
)


def _documentation_files() -> tuple[Path, ...]:
    return (ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md")))


def _relative_targets(markdown: str) -> tuple[str, ...]:
    matches = (*INLINE_LINK.finditer(markdown), *REFERENCE_LINK.finditer(markdown))
    targets = []
    for match in matches:
        target = match.group("target").strip("<>")
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or target.startswith("#") or not parsed.path:
            continue
        targets.append(unquote(parsed.path))
    return tuple(targets)


@pytest.mark.parametrize("document", _documentation_files(), ids=lambda path: path.name)
def test_readme_and_docs_relative_links_resolve_inside_repository(document: Path) -> None:
    repository = ROOT.resolve()
    markdown = document.read_text(encoding="utf-8")
    for target in _relative_targets(markdown):
        resolved = (document.parent / target).resolve()
        assert resolved == repository or repository in resolved.parents, (
            f"{document.relative_to(ROOT)} link escapes repository: {target}"
        )
        assert resolved.exists(), f"{document.relative_to(ROOT)} has broken link: {target}"


def test_public_documentation_index_has_required_pages() -> None:
    index = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")
    for target in (
        "architecture.md",
        "dpl_and_run_manifest.md",
        "hero_session.md",
        "responsible_use.md",
    ):
        assert f"]({target})" in index
    assert "Placeholder" not in index
