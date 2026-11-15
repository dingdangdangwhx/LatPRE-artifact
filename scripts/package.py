#!/usr/bin/env python3
"""Create a source-only archive without local build data."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TOP = {"latpre", "params", "baseline", "hybrid-mail", "scripts", "results"}
ROOT_FILES = {"README.md", "Makefile", "run_all.sh", ".gitignore"}
SKIP_DIRS = {"build", "bin", ".deps", ".cache", ".git", "__pycache__", "runs", "dist"}
SOURCE_SUFFIXES = {".c", ".cpp", ".h", ".inc", ".py", ".sh", ".json", ".md", ".txt",
                   ".go", ".mod", ".sum", ".patch", ".csv"}
SPECIAL_NAMES = {"Makefile", "CMakeLists.txt", ".gitignore", "NOTICE", "THIRD_PARTY_NOTICES",
                 "COPYING", "COPYING.LESSER", "LICENSE", "LICENSE-MIT"}


def source_files():
    candidates = []
    for base, dirs, names in os.walk(ROOT):
        relative = Path(base).relative_to(ROOT)
        dirs[:] = sorted(name for name in dirs
                         if name not in SKIP_DIRS and not name.startswith("build-"))
        if relative == Path("."):
            dirs[:] = [name for name in dirs if name in TOP]
        if relative == Path("results"):
            dirs[:] = [name for name in dirs if name == "extended-classical128"]
        if relative == Path("params"):
            dirs[:] = [name for name in dirs if name != "results"]
        if relative == Path("baseline/cic25"):
            dirs[:] = [name for name in dirs if name != "results"]
        candidates.extend(Path(base) / name for name in names if name != ".DS_Store")
    local_name = Path.home().name.encode().lower()
    for path in sorted(candidates):
        rel = path.relative_to(ROOT)
        if any(part in SKIP_DIRS or part.startswith("build-") for part in rel.parts[:-1]):
            continue
        if not path.is_file():
            continue
        if path.is_symlink():
            raise ValueError("Release sources cannot be symlinks: " + str(rel))
        if len(rel.parts) == 1:
            if path.name not in ROOT_FILES:
                continue
        elif rel.parts[0] not in TOP:
            continue
        if (rel.parts[0] == "results" and len(rel.parts) != 2
                and rel.parts[1] != "extended-classical128"):
            continue
        if rel.parts[0] == "params" and ("results" in rel.parts or path.name == "verification.json"):
            continue
        if rel.parts[:3] == ("baseline", "cic25", "results"):
            continue
        is_notice = path.name.startswith(("LICENSE", "COPYING")) or "licenses" in rel.parts
        if not (path.suffix in SOURCE_SUFFIXES or path.name in SPECIAL_NAMES or is_notice):
            raise ValueError("Unexpected release file; review before including: " + str(rel))
        content = path.read_bytes()
        if b"\x00" in content:
            raise ValueError("Binary content in source release: " + str(rel))
        # Personal home paths must never occur in published source or records.
        if (re.search(rb"/(?:Users|home)/[^ /\n]+/", content, re.I)
                or (b"One" + b"Drive-").lower() in content.lower()
                or (len(local_name) > 4 and local_name in content.lower())):
            raise ValueError("Local identity/path in release file: " + str(rel))
        yield rel, content, bool(path.stat().st_mode & stat.S_IXUSR)


def main():
    files = list(source_files())
    dest = ROOT / "dist/source/latpre-artifact"
    dest.mkdir(parents=True, exist_ok=True)
    # Remove only the generated source snapshot, never the working artifact.
    for entry in dest.iterdir():
        if entry.is_dir():
            shutil.rmtree(entry)
        else:
            entry.unlink()
    archive = ROOT / "dist/latpre-artifact.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as stream:
        for rel, data, executable in files:
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            mode = 0o755 if executable else 0o644
            target.chmod(mode)
            item = zipfile.ZipInfo("latpre-artifact/" + rel.as_posix(), (2026, 11, 13, 0, 0, 0))
            item.create_system = 3
            item.external_attr = (stat.S_IFREG | mode) << 16
            item.compress_type = zipfile.ZIP_DEFLATED
            stream.writestr(item, data)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (archive.parent / "SHA256SUMS").write_text(digest + "  " + archive.name + "\n")
    print(f"Published source files: {len(files)}")
    print(f"Archive: {archive.name} ({archive.stat().st_size:,} bytes)")
    print(f"SHA256: {digest}")
    print("Clean upload directory: dist/source/latpre-artifact/")


if __name__ == "__main__":
    main()
