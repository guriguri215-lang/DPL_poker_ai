from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from poker_ai import runtime_provenance
from poker_core.run_manifest import UNKNOWN_COMMIT


def _source_module(tmp_path: Path, version: str = "1.2.3") -> tuple[Path, Path]:
    root = tmp_path / "project"
    module = root / "src" / "poker_ai" / "runtime_provenance.py"
    module.parent.mkdir(parents=True)
    module.write_text("# fixture\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "poker-xai"\nversion = "{version}"\n',
        encoding="utf-8",
    )
    return root, module


def test_source_version_comes_from_the_exact_anchored_pyproject(tmp_path: Path) -> None:
    _, module = _source_module(tmp_path, "4.5.6")
    assert runtime_provenance.resolve_package_version(module) == "4.5.6"


def test_source_with_unavailable_version_does_not_adopt_distribution_metadata(
    tmp_path: Path, monkeypatch
) -> None:
    root, module = _source_module(tmp_path)
    (root / "pyproject.toml").write_text('[project]\nname = "poker-xai"\n', encoding="utf-8")

    class StaleDistribution:
        version = "0.0.0"

        @staticmethod
        def locate_file(_path: Path) -> Path:
            return module

    monkeypatch.setattr(
        runtime_provenance.importlib.metadata,
        "distributions",
        lambda **_kwargs: iter((StaleDistribution(),)),
    )
    assert (
        runtime_provenance.resolve_package_version(module)
        == runtime_provenance.UNKNOWN_PACKAGE_VERSION
    )


def test_unverified_source_project_does_not_adopt_distribution_metadata(
    tmp_path: Path, monkeypatch
) -> None:
    root, module = _source_module(tmp_path)

    class StaleDistribution:
        version = "0.0.0"

        @staticmethod
        def locate_file(_path: Path) -> Path:
            return module

    monkeypatch.setattr(
        runtime_provenance.importlib.metadata,
        "distributions",
        lambda **_kwargs: iter((StaleDistribution(),)),
    )
    for pyproject in (
        '[project]\nname = "different-project"\nversion = "9.9.9"\n',
        'project = "not-a-table"\n',
    ):
        (root / "pyproject.toml").write_text(pyproject, encoding="utf-8")
        assert (
            runtime_provenance.resolve_package_version(module)
            == runtime_provenance.UNKNOWN_PACKAGE_VERSION
        )


def test_artifact_version_requires_metadata_locating_the_executing_module(
    tmp_path: Path, monkeypatch
) -> None:
    module = tmp_path / "artifact" / "poker_ai" / "runtime_provenance.py"
    module.parent.mkdir(parents=True)
    module.write_text("# fixture\n", encoding="utf-8")

    class MatchingDistribution:
        version = "7.8.9"

        @staticmethod
        def locate_file(path: Path) -> Path:
            assert path == Path("poker_ai/runtime_provenance.py")
            return module

    monkeypatch.setattr(
        runtime_provenance.importlib.metadata,
        "distributions",
        lambda **_kwargs: iter((MatchingDistribution(),)),
    )
    assert runtime_provenance.resolve_package_version(module) == "7.8.9"


def test_artifact_version_falls_back_without_matching_metadata(tmp_path: Path, monkeypatch) -> None:
    module = tmp_path / "artifact" / "poker_ai" / "runtime_provenance.py"
    module.parent.mkdir(parents=True)
    module.write_text("# fixture\n", encoding="utf-8")
    monkeypatch.setattr(
        runtime_provenance.importlib.metadata,
        "distributions",
        lambda **_kwargs: iter(()),
    )
    assert (
        runtime_provenance.resolve_package_version(module)
        == runtime_provenance.UNKNOWN_PACKAGE_VERSION
    )


def test_git_provenance_is_anchored_and_reports_dirty_state(tmp_path: Path, monkeypatch) -> None:
    root, module = _source_module(tmp_path)
    (root / ".git").mkdir()
    commit = "a" * 40

    def fake_git(_root: Path, *args: str):
        if args == ("rev-parse", "--show-toplevel"):
            return SimpleNamespace(returncode=0, stdout=str(root.resolve()).encode())
        if args == ("rev-parse", "--verify", "HEAD^{commit}"):
            return SimpleNamespace(returncode=0, stdout=f"{commit}\n".encode())
        if args == ("status", "--porcelain=v1", "--untracked-files=all"):
            return SimpleNamespace(returncode=0, stdout=b" M tracked.py\n")
        raise AssertionError(args)

    monkeypatch.setattr(runtime_provenance, "_run_git", fake_git)
    assert runtime_provenance.resolve_git_provenance(module) == (commit, True)


def test_git_provenance_does_not_adopt_cwd_or_parent_repository(
    tmp_path: Path, monkeypatch
) -> None:
    module = tmp_path / "artifact" / "poker_ai" / "runtime_provenance.py"
    module.parent.mkdir(parents=True)
    module.write_text("# fixture\n", encoding="utf-8")
    called = False

    def unexpected_git(*_args, **_kwargs):
        nonlocal called
        called = True
        return None

    monkeypatch.setattr(runtime_provenance, "_run_git", unexpected_git)
    assert runtime_provenance.resolve_git_provenance(module) == (UNKNOWN_COMMIT, None)
    assert called is False


def test_git_command_failure_uses_explicit_unknowns(tmp_path: Path, monkeypatch) -> None:
    root, module = _source_module(tmp_path)
    (root / ".git").mkdir()
    monkeypatch.setattr(runtime_provenance, "_run_git", lambda *_args: None)
    assert runtime_provenance.resolve_git_provenance(module) == (UNKNOWN_COMMIT, None)


def test_current_source_checkout_reports_project_version() -> None:
    provenance = runtime_provenance.collect_runtime_provenance()
    assert provenance.package_version == "0.1.0a17"
    assert provenance.git_commit == UNKNOWN_COMMIT or len(provenance.git_commit) == 40
    assert provenance.git_dirty is None or isinstance(provenance.git_dirty, bool)
