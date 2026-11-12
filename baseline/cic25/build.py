#!/usr/bin/env python3
"""Build the pinned, locally patched single-hop CiC comparison dependency."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
PINS = json.loads((HERE / "upstream.json").read_text())


def run(argv, cwd=None, capture=False):
    print("+ " + " ".join(map(str, argv)), flush=True)
    return subprocess.run(list(map(str, argv)), cwd=cwd, check=True,
                          text=True, stdout=subprocess.PIPE if capture else None)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_tree(path):
    if not (path / ".git").exists():
        if path.exists() and any(path.iterdir()):
            raise SystemExit("Refusing to overwrite nonempty dependency directory: " + str(path))
        path.mkdir(parents=True, exist_ok=True)
        run(["git", "init", path])
        run(["git", "remote", "add", "origin", PINS["openfhe"]["url"]], path)
    head = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=path,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    if head.returncode:
        run(["git", "fetch", "--depth", "1", "origin", PINS["openfhe"]["commit"]], path)
        run(["git", "checkout", "--detach", "FETCH_HEAD"], path)
    actual = run(["git", "rev-parse", "HEAD"], path, True).stdout.strip()
    if actual != PINS["openfhe"]["commit"]:
        raise SystemExit("OpenFHE source is not at the pinned commit")
    run(["git", "submodule", "update", "--init", "--depth", "1",
         PINS["cereal"]["submodule"]], path)
    cereal = path / PINS["cereal"]["submodule"]
    if run(["git", "rev-parse", "HEAD"], cereal, True).stdout.strip() != PINS["cereal"]["commit"]:
        raise SystemExit("cereal submodule does not match the pinned revision")
    patch = HERE / "patches/openfhe-v1.2.0-single-hop.patch"
    if sha(patch) != PINS["patch_sha256"]:
        raise SystemExit("Patch checksum mismatch")
    can_apply = subprocess.run(["git", "apply", "--check", str(patch)], cwd=path,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    if can_apply:
        run(["git", "apply", patch], path)
    else:
        subprocess.run(["git", "apply", "--reverse", "--check", str(patch)],
                       cwd=path, check=True)
    for name, expected in PINS["patched_files_sha256"].items():
        if sha(path / name) != expected:
            raise SystemExit("Patched source checksum mismatch: " + name)
    changed = set(run(["git", "diff", "--name-only"], path, True).stdout.splitlines())
    if changed != set(PINS["patched_files_sha256"]):
        raise SystemExit("Unexpected changes in the OpenFHE source tree")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cmake", default=os.environ.get("CMAKE", "cmake"))
    p.add_argument("--jobs", type=int, default=2)
    p.add_argument("--source-dir", type=Path, default=HERE / ".deps/openfhe")
    p.add_argument("--dependency-build-dir", type=Path, default=HERE / ".deps/openfhe-build")
    p.add_argument("--prefix", type=Path, default=HERE / ".deps/install")
    p.add_argument("--build-dir", type=Path, default=HERE / "build")
    p.add_argument("--openfhe-dir", type=Path,
                   help="Explicit existing matching patched OpenFHE package; skips dependency build")
    a = p.parse_args()
    if not shutil.which(a.cmake):
        raise SystemExit("CMake >=3.15 is required (or set CMAKE)")
    if a.jobs < 1:
        raise SystemExit("--jobs must be positive")
    package = a.openfhe_dir.resolve() if a.openfhe_dir else a.prefix.resolve() / "lib/OpenFHE"
    if not a.openfhe_dir:
        source = a.source_dir.resolve()
        source_tree(source)
        run([a.cmake, "-S", source, "-B", a.dependency_build_dir.resolve(),
             "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_UNITTESTS=OFF", "-DBUILD_EXAMPLES=OFF",
             "-DBUILD_BENCHMARKS=OFF", "-DBUILD_EXTRAS=OFF", "-DWITH_OPENMP=OFF",
             "-DGIT_SUBMOD_AUTO=OFF", "-DBUILD_SHARED=ON", "-DBUILD_STATIC=OFF",
             "-DWITH_NATIVEOPT=OFF", "-DNATIVE_SIZE=64", "-DMATHBACKEND=4",
             "-DCMAKE_EXPORT_NO_PACKAGE_REGISTRY=ON", "-DCMAKE_CXX_FLAGS:STRING=",
             "-DCMAKE_CXX_FLAGS_RELEASE:STRING=-O3 -DNDEBUG -Wno-unused-variable",
             "-DCMAKE_INSTALL_PREFIX=" + str(a.prefix.resolve())])
        run([a.cmake, "--build", a.dependency_build_dir.resolve(), "--parallel", a.jobs])
        run([a.cmake, "--install", a.dependency_build_dir.resolve()])
    if not (package / "OpenFHEConfig.cmake").is_file():
        raise SystemExit("OpenFHEConfig.cmake not found: " + str(package))
    run([a.cmake, "-S", HERE, "-B", a.build_dir.resolve(),
         "-DCMAKE_BUILD_TYPE=Release", "-DOpenFHE_DIR=" + str(package)])
    run([a.cmake, "--build", a.build_dir.resolve(), "--parallel", a.jobs])


if __name__ == "__main__":
    main()
