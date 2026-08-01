"""Build a deterministic, data-minimal AWS Lambda zip artifact."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
from collections.abc import Sequence
from pathlib import Path
from zipfile import ZIP_STORED, ZipFile, ZipInfo

_RUNTIME_IMPORTS = (
    "boto3",
    "botocore",
    "dateutil",
    "jmespath",
    "s3transfer",
    "six",
    "urllib3",
    "yaml",
)
_EXCLUDED_DIRECTORY_NAMES = frozenset({"__pycache__", ".git", ".mypy_cache", ".pytest_cache"})
_EXCLUDED_SUFFIXES = frozenset({".dll", ".dylib", ".pyc", ".pyd", ".pyo", ".so"})
_FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_REGULAR_FILE_MODE = 0o100644


class BuildError(RuntimeError):
    """Raised when a safe deterministic artifact cannot be produced."""


def build_lambda(
    project_root: Path,
    *,
    output_path: Path | None = None,
    dependency_paths: Sequence[Path] | None = None,
) -> Path:
    """Build the Lambda artifact from application source and runtime imports only."""
    root = project_root.resolve()
    package = root / "src" / "pilo_incident_investigator"
    if not package.is_dir() or package.is_symlink():
        raise BuildError(f"runtime package directory is missing or unsafe: {package}")

    dependencies = (
        tuple(path if path.is_absolute() else root / path for path in dependency_paths)
        if dependency_paths is not None
        else _installed_dependency_paths()
    )
    entries: dict[str, bytes] = {}
    _add_path(entries, package, package.name)
    for dependency in dependencies:
        _add_path(entries, dependency, dependency.name)

    artifact = output_path or root / "dist" / "pilo-incident-investigator.zip"
    if not artifact.is_absolute():
        artifact = root / artifact
    artifact.parent.mkdir(parents=True, exist_ok=True)
    temporary = artifact.with_suffix(f"{artifact.suffix}.tmp")
    temporary.unlink(missing_ok=True)

    try:
        with ZipFile(temporary, mode="w", compression=ZIP_STORED) as archive:
            for name in sorted(entries):
                info = ZipInfo(name, date_time=_FIXED_TIMESTAMP)
                info.compress_type = ZIP_STORED
                info.create_system = 3
                info.external_attr = _REGULAR_FILE_MODE << 16
                archive.writestr(info, entries[name])
        temporary.replace(artifact)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return artifact


def _installed_dependency_paths() -> tuple[Path, ...]:
    paths: list[Path] = []
    for import_name in _RUNTIME_IMPORTS:
        spec = importlib.util.find_spec(import_name)
        if spec is None:
            raise BuildError(f"installed runtime dependency is missing: {import_name}")
        if spec.submodule_search_locations:
            locations = tuple(spec.submodule_search_locations)
            if len(locations) != 1:
                raise BuildError(f"runtime dependency has ambiguous locations: {import_name}")
            paths.append(Path(locations[0]))
        elif spec.origin is not None:
            paths.append(Path(spec.origin))
        else:
            raise BuildError(f"runtime dependency has no file location: {import_name}")
    return tuple(paths)


def _add_path(entries: dict[str, bytes], source: Path, archive_name: str) -> None:
    if source.is_symlink():
        raise BuildError(f"symbolic link is not allowed in Lambda artifacts: {source}")
    if source.is_file():
        if _is_included(source):
            _add_entry(entries, archive_name, source)
        return
    if not source.is_dir():
        raise BuildError(f"artifact input does not exist: {source}")

    for candidate in sorted(source.rglob("*"), key=lambda path: path.as_posix()):
        if candidate.is_symlink():
            raise BuildError(f"symbolic link is not allowed in Lambda artifacts: {candidate}")
        if not candidate.is_file() or not _is_included(candidate):
            continue
        relative = candidate.relative_to(source).as_posix()
        _add_entry(entries, f"{archive_name}/{relative}", candidate)


def _is_included(path: Path) -> bool:
    if any(part in _EXCLUDED_DIRECTORY_NAMES for part in path.parts):
        return False
    name = path.name.lower()
    if path.suffix.lower() in _EXCLUDED_SUFFIXES:
        return False
    if name.endswith(".env") or ".env." in name:
        return False
    if name.endswith(".tfstate") or ".tfstate." in name:
        return False
    return name != "pilo-topology.yaml"


def _add_entry(entries: dict[str, bytes], archive_name: str, source: Path) -> None:
    normalized = archive_name.replace("\\", "/")
    if normalized in entries:
        raise BuildError(f"duplicate Lambda artifact entry: {normalized}")
    entries[normalized] = source.read_bytes()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Artifact path (default: dist/...)")
    args = parser.parse_args(argv)
    project_root = Path(__file__).resolve().parents[1]
    artifact = build_lambda(project_root, output_path=args.output)
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    print(f"{artifact}\nsha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
