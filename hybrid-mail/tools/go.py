#!/usr/bin/env python3
"""Run the pinned Go module with local, ignored build/dependency caches."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

project = Path(__file__).resolve().parents[1]
go = os.environ.get("GO", "go")
if not shutil.which(go):
    raise SystemExit("Go >= 1.23 is required. Put go on PATH or set GO=/path/to/go.")
cache = project / ".cache"
env = dict(os.environ)
env.update(
    GOENV="off",
    GOTOOLCHAIN="local",
    GOWORK="off",
    GOMAXPROCS="1",
    CGO_ENABLED="1",
)
env.setdefault("GOCACHE", str(cache / "build"))
env.setdefault("GOMODCACHE", str(cache / "modules"))
env.setdefault("GOPATH", str(cache / "gopath"))
raise SystemExit(subprocess.call([go, *sys.argv[1:]], cwd=project, env=env))
