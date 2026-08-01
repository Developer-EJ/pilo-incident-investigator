from __future__ import annotations

import hashlib
from pathlib import Path
from zipfile import ZipFile

import pytest

from scripts.build_lambda import BuildError, build_lambda


def create_project(root: Path) -> tuple[Path, ...]:
    package = root / "src" / "pilo_incident_investigator"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text('"""Synthetic package."""\n', encoding="utf-8")
    (package / "handler.py").write_text("VALUE = 1\n", encoding="utf-8")

    dependency = root / "installed" / "yaml"
    dependency.mkdir(parents=True)
    (dependency / "__init__.py").write_text("SAFE = True\n", encoding="utf-8")
    (dependency / "reader.py").write_text("READER = True\n", encoding="utf-8")
    (dependency / "_yaml.cp312-win_amd64.pyd").write_bytes(b"native")
    (dependency / "local.env").write_text("TOKEN=secret\n", encoding="utf-8")
    (dependency / ".env.production").write_text("TOKEN=secret\n", encoding="utf-8")

    (root / "config").mkdir()
    (root / "config" / "pilo-topology.yaml").write_text("secret: value\n", encoding="utf-8")
    (root / "terraform.tfstate").write_text('{"secret":"value"}\n', encoding="utf-8")
    (root / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
    return (dependency,)


def test_bundle_contains_only_source_and_pure_python_dependencies(tmp_path: Path) -> None:
    dependencies = create_project(tmp_path)

    artifact = build_lambda(tmp_path, dependency_paths=dependencies)

    with ZipFile(artifact) as archive:
        names = archive.namelist()
    assert "pilo_incident_investigator/handler.py" in names
    assert "yaml/reader.py" in names
    assert "config/pilo-topology.yaml" not in names
    assert "yaml/.env.production" not in names
    assert not any(name.endswith((".env", ".tfstate", ".pyd", ".pyc")) for name in names)


def test_bundle_is_byte_reproducible_with_normalized_metadata(tmp_path: Path) -> None:
    dependencies = create_project(tmp_path)

    first = build_lambda(
        tmp_path,
        output_path=tmp_path / "dist" / "first.zip",
        dependency_paths=dependencies,
    )
    second = build_lambda(
        tmp_path,
        output_path=tmp_path / "dist" / "second.zip",
        dependency_paths=dependencies,
    )

    assert (
        hashlib.sha256(first.read_bytes()).digest() == hashlib.sha256(second.read_bytes()).digest()
    )
    with ZipFile(first) as archive:
        assert archive.namelist() == sorted(archive.namelist())
        assert {item.date_time for item in archive.infolist()} == {(1980, 1, 1, 0, 0, 0)}
        assert {item.external_attr >> 16 for item in archive.infolist()} == {0o100644}


def test_bundle_rejects_symlinked_source_files(tmp_path: Path) -> None:
    create_project(tmp_path)
    source = tmp_path / "outside.py"
    source.write_text("SECRET = 'outside'\n", encoding="utf-8")
    link = tmp_path / "src" / "pilo_incident_investigator" / "linked.py"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("This platform does not permit test symlinks")

    with pytest.raises(BuildError, match="symbolic link"):
        build_lambda(tmp_path, dependency_paths=())


def test_bundle_requires_runtime_package_source(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()

    with pytest.raises(BuildError, match="runtime package"):
        build_lambda(tmp_path, dependency_paths=())
