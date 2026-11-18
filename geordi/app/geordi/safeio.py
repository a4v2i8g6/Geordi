"""Limits and safe access for hostile repositories; no code is executed."""
from __future__ import annotations

import os
import re
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

MAX_ARCHIVE = 64 * 1024 * 1024
MAX_EXPANDED = 128 * 1024 * 1024
MAX_FILES = 6000
MAX_FILE = 8 * 1024 * 1024
MAX_DEPTH = 30

class UnsafeInput(ValueError):
    pass


def clean_member(name: str) -> PurePosixPath:
    if not name or "\\" in name or "\x00" in name:
        raise UnsafeInput("unsafe archive member name")
    if re.match(r"^[A-Za-z]:", name):
        raise UnsafeInput("drive-qualified archive member")
    p = PurePosixPath(name)
    if p.is_absolute() or any(part in ("..", "") for part in p.parts) or len(p.parts) > MAX_DEPTH:
        raise UnsafeInput("archive path traversal or depth limit")
    return p


def unzip_safely(archive: Path, destination: Path) -> None:
    if archive.stat().st_size > MAX_ARCHIVE:
        raise UnsafeInput("archive is too large")
    destination.mkdir(parents=True, exist_ok=False)
    files, expanded, seen = 0, 0, set()
    with zipfile.ZipFile(archive) as zf:
        for entry in zf.infolist():
            rel = clean_member(entry.filename)
            norm = str(rel).rstrip("/").casefold()
            if norm in seen:
                raise UnsafeInput("duplicate/case-colliding member")
            seen.add(norm)
            mode = entry.external_attr >> 16
            if mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise UnsafeInput("archive links and special files are forbidden")
            target = destination.joinpath(*rel.parts)
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            files += 1
            if files > MAX_FILES or entry.file_size > MAX_FILE:
                raise UnsafeInput("archive file count or per-file limit")
            if entry.compress_size == 0 and entry.file_size:
                raise UnsafeInput("suspicious archive compression")
            if entry.compress_size and entry.file_size > entry.compress_size * 1000:
                raise UnsafeInput("compression ratio too high")
            expanded += entry.file_size
            if expanded > MAX_EXPANDED:
                raise UnsafeInput("expanded archive size limit")
            target.parent.mkdir(parents=True, exist_ok=True)
            # Newly-created destination never contains symlinks: no archive link or traversal possible.
            try:
                with zf.open(entry, "r") as src, target.open("xb") as out:
                    actual = 0
                    while True:
                        chunk = src.read(65536)
                        if not chunk:
                            break
                        actual += len(chunk)
                        if actual > entry.file_size or actual > MAX_FILE:
                            raise UnsafeInput("decompressed member exceeded declared size")
                        out.write(chunk)
                    if actual != entry.file_size:
                        raise UnsafeInput("archive member size mismatch")
                target.chmod(0o600)
            except Exception:
                target.unlink(missing_ok=True)
                raise


def read_plain_file(path: Path, root: Path | None = None) -> bytes:
    """Read a regular file without following links at any path component.

    If ``root`` is supplied, open an anchored root directory descriptor and
    descend with O_DIRECTORY|O_NOFOLLOW. This prevents a concurrent rename of
    an intermediate directory to a symlink from escaping the requested tree.
    The scanner never opens hostile files for execution.
    """
    nonblock = getattr(os, "O_NONBLOCK", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if root is None:
        fd = os.open(path, os.O_RDONLY | nofollow | nonblock)
    else:
        root = root.absolute()
        try:
            relative = path.absolute().relative_to(root)
        except ValueError as e:
            raise UnsafeInput("file is outside scan root") from e
        if not relative.parts or any(part in ("..", ".") for part in relative.parts):
            raise UnsafeInput("file is not a strict root-relative file")
        anchor = os.open(root, os.O_RDONLY | directory | nofollow)
        try:
            for part in relative.parts[:-1]:
                next_dir = os.open(part, os.O_RDONLY | directory | nofollow, dir_fd=anchor)
                os.close(anchor)
                anchor = next_dir
            fd = os.open(relative.parts[-1], os.O_RDONLY | nonblock | nofollow, dir_fd=anchor)
        finally:
            os.close(anchor)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE:
            raise UnsafeInput("nonregular or oversized file")
        with os.fdopen(os.dup(fd), "rb") as src:
            data = src.read(MAX_FILE + 1)
        if len(data) > MAX_FILE:
            raise UnsafeInput("file grew during read")
        return data
    finally:
        os.close(fd)


def inventory(root: Path):
    """Yield (relative name, bytes|None, problem|None) without following directory links."""
    if root.is_symlink():
        raise UnsafeInput("source root may not be a symlink")
    root = root.absolute()
    if not root.is_dir():
        raise UnsafeInput("source must be a directory")
    count = 0
    # os.walk does not recurse into symlinks with followlinks=False.
    errors = []
    for base, dirs, files in os.walk(root, topdown=True, followlinks=False,
                                     onerror=lambda err: errors.append(str(err))):
        base_path = Path(base)
        depth = len(base_path.relative_to(root).parts)
        if depth >= MAX_DEPTH:
            for name in dirs + files:
                yield str((base_path / name).relative_to(root)), None, "directory depth limit"
            dirs[:] = []
            continue
        dirs[:] = sorted(d for d in dirs if d != ".git")
        for dirname in list(dirs):
            if (base_path / dirname).is_symlink():
                dirs.remove(dirname)
                yield str((base_path / dirname).relative_to(root)), None, "symlink directory skipped"
        for name in sorted(files):
            count += 1
            rel = str((base_path / name).relative_to(root)).replace(os.sep, "/")
            if count > MAX_FILES:
                yield rel, None, "file count limit"
                return
            try:
                if (base_path / name).is_symlink():
                    raise UnsafeInput("symlink skipped")
                yield rel, read_plain_file(base_path / name, root), None
            except (OSError, UnsafeInput) as e:
                yield rel, None, type(e).__name__ + ": " + str(e)
    for issue in errors:
        yield "[directory-walk]", None, issue
