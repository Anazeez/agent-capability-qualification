"""Deterministic, dependency-free identities for skill packages."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable


DEPENDENCY_FILENAMES = {
    "cargo.lock",
    "cargo.toml",
    "go.mod",
    "go.sum",
    "package-lock.json",
    "package.json",
    "pipfile",
    "pipfile.lock",
    "poetry.lock",
    "pyproject.toml",
    "pnpm-lock.yaml",
    "requirements.lock",
    "uv.lock",
    "yarn.lock",
}


@dataclass(frozen=True)
class FileRecord:
    path: str
    content: bytes
    mode: int


def _raise_for_symlink(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"symlinked skill content is not allowed: {path}")


def _raise_walk_error(error: OSError) -> None:
    raise error


def _reject_parent_symlink_escape(input_path: Path) -> None:
    absolute = Path(os.path.abspath(input_path))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:-1]:
        candidate = current / component
        if candidate.is_symlink():
            target = candidate.resolve(strict=True)
            boundary = current.resolve(strict=True)
            try:
                target.relative_to(boundary)
            except ValueError as error:
                raise ValueError(
                    f"symlinked skill path escapes its parent: {candidate}"
                ) from error
        current = candidate


def list_regular_file_records(root: Path) -> list[FileRecord]:
    """Return sorted package records without following symlinks."""

    records: list[FileRecord] = []
    for current, directories, filenames in os.walk(
        root,
        topdown=True,
        followlinks=False,
        onerror=_raise_walk_error,
    ):
        current_path = Path(current)
        kept_directories: list[str] = []
        for name in sorted(directories):
            path = current_path / name
            _raise_for_symlink(path)
            if name == ".git":
                continue
            if not stat.S_ISDIR(path.lstat().st_mode):
                raise ValueError(f"unsupported skill entry: {path}")
            kept_directories.append(name)
        directories[:] = kept_directories

        for name in sorted(filenames):
            if name == ".git":
                continue
            path = current_path / name
            _raise_for_symlink(path)
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError(f"unsupported skill entry: {path}")
            records.append(FileRecord(
                path.relative_to(root).as_posix(),
                path.read_bytes(),
                stat.S_IMODE(path.lstat().st_mode),
            ))

    return sorted(records, key=lambda record: record.path)


def _digest_records(records: Iterable[FileRecord], *, include_mode: bool = False) -> str:
    digest = hashlib.sha256()
    for record in records:
        path_bytes = record.path.encode("utf-8")
        digest.update(len(path_bytes).to_bytes(8, "big"))
        digest.update(path_bytes)
        if include_mode:
            digest.update(record.mode.to_bytes(4, "big"))
        digest.update(len(record.content).to_bytes(8, "big"))
        digest.update(record.content)
    return digest.hexdigest()


def is_dependency_file(relative_path: str) -> bool:
    name = PurePosixPath(relative_path).name.lower()
    return name in DEPENDENCY_FILENAMES or (
        name.startswith("requirements") and name.endswith(".txt")
    )


def detect_git_revision(root: Path) -> str:
    try:
        run = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return "unversioned"
    revision = run.stdout.strip()
    return revision if re.fullmatch(r"[0-9a-fA-F]{7,64}", revision) else "unversioned"


def identity_for_skill(skill_dir: Path, source_revision: str | None = None) -> dict[str, str]:
    """Build the four stable identity fields for a skill package."""

    input_path = Path(skill_dir)
    _raise_for_symlink(input_path)
    try:
        _reject_parent_symlink_escape(input_path)
    except (OSError, RuntimeError) as error:
        raise ValueError(f"skill package path is unavailable: {input_path}") from error
    try:
        root = input_path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValueError(f"skill package is unavailable: {input_path}") from error
    if not root.is_dir():
        raise ValueError(f"skill package is not a directory: {root}")

    records = list_regular_file_records(root)
    instruction_records = [record for record in records if record.path == "SKILL.md"]
    if len(instruction_records) != 1:
        raise ValueError("skill package must contain exactly one SKILL.md")
    dependency_records = [record for record in records if is_dependency_file(record.path)]

    return {
        "instruction_digest": _digest_records(instruction_records),
        "package_tree_digest": _digest_records(records, include_mode=True),
        "dependency_digest": _digest_records(dependency_records),
        "source_revision": source_revision or detect_git_revision(root),
    }
