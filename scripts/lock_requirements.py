"""Pin the resolved runtime dependency graph for repeatable deployment."""

from importlib.metadata import distribution
from pathlib import Path
from packaging.requirements import Requirement

seen = {}


def visit(name):
    dist = distribution(name)
    canonical = dist.metadata["Name"]
    if canonical.lower() in seen:
        return
    seen[canonical.lower()] = (canonical, dist.version)
    for text in dist.requires or []:
        req = Requirement(text)
        if not req.marker or req.marker.evaluate({"extra": ""}):
            visit(req.name)


for name in ("fastapi", "uvicorn", "argon2-cffi", "tzdata"):
    visit(name)
lines = [
    "# Runtime dependencies resolved from pyproject.toml. Regenerate with scripts/lock_requirements.py."
]
lines.extend(
    f"{name}=={version}"
    for name, version in sorted(seen.values(), key=lambda item: item[0].lower())
)
(Path(__file__).resolve().parents[1] / "requirements.txt").write_text(
    "\n".join(lines) + "\n", encoding="utf-8"
)
