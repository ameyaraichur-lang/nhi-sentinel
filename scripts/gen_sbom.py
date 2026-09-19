"""AT22-lite: generate a minimal SBOM for NHI Sentinel (stdlib only).

Reads the direct dependencies from pyproject.toml ([project] dependencies) and
resolves each against the installed environment via importlib.metadata.
Emits docs/sbom.json with one entry per component:

    {name, version, purl, license, dependencies}

where ``license`` is taken from distribution metadata (License field,
License-Expression, or an OSI classifier) and may be null when unavailable.
The first entry is the application itself. Prints the component count.

Usage: python scripts/gen_sbom.py
"""

from __future__ import annotations

import json
import sys
import tomllib
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
OUT = ROOT / "docs" / "sbom.json"


def canonical(name: str) -> str:
    """PEP 503 canonical distribution name."""
    return "".join(c if c not in "-_." else "-" for c in name.lower())


def license_of(dist: metadata.Distribution) -> str | None:
    """Best-effort license from metadata: field, SPDX expression, or classifier."""
    m = dist.metadata
    for key in ("License-Expression", "License"):
        val = m.get(key)
        if val:
            return val.strip()
    for classifier in m.get_all("Classifier") or []:
        if classifier.startswith("License ::"):
            return classifier.split("::")[-1].strip()
    return None


def requires_of(dist: metadata.Distribution) -> list[str]:
    """Raw Requires-Dist strings (unparsed on purpose: markers are informative)."""
    return list(dist.requires or [])


def purl(name: str, version: str) -> str:
    return f"pkg:pypi/{canonical(name)}@{version}"


def main() -> int:
    with PYPROJECT.open("rb") as fh:
        project = tomllib.load(fh)["project"]

    packages: list[dict] = []

    # Component 0: the application itself (deps straight from pyproject).
    packages.append(
        {
            "name": project["name"],
            "version": project["version"],
            "purl": purl(project["name"], project["version"]),
            "license": project.get("license") or None,
            "dependencies": list(project.get("dependencies", [])),
        }
    )

    missing: list[str] = []
    for req in project.get("dependencies", []):
        # Requirement strings here are plain "name>=x" - no extras/env markers in
        # this project; strip any version/extra clauses for the metadata lookup.
        name = req.split(";")[0].split("==")[0].split(">=")[0].split(">")[0].split("[")[0].strip()
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            missing.append(name)
            packages.append(
                {
                    "name": name,
                    "version": None,
                    "purl": f"pkg:pypi/{name}",
                    "license": None,
                    "dependencies": [],
                    "note": "not installed in the environment that generated this SBOM",
                }
            )
            continue
        packages.append(
            {
                "name": dist.metadata["Name"],
                "version": dist.version,
                "purl": purl(dist.metadata["Name"], dist.version),
                "license": license_of(dist),
                "dependencies": requires_of(dist),
            }
        )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(packages, indent=2) + "\n", encoding="utf-8")

    print(f"SBOM written to {OUT.relative_to(ROOT)}: {len(packages)} components")
    if missing:
        print(f"warning: not installed (emitted with version=null): {', '.join(missing)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
