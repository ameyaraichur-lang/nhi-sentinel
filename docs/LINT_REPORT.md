# Lint report — NHI Sentinel (report-only)

_Generated 2026-09-19 by a stdlib-only AST scan over `nhi_sentinel/**/*.py` and `tests/**/*.py` (54 files). Nothing was fixed; this is an inventory for the owning engineer._

## Method (and its limits)

- An import is flagged when the identifier it binds never appears elsewhere in the module: no other `ast.Name`/`ast.Attribute` reference and no exact-match string constant (covers `__all__` entries and forward references).
- `from __future__ import annotations` is excluded (compiler directive).
- `import *` is skipped (unanalyzable) — none present at scan time.
- Spot-checks with grep confirmed flagged symbols occur only on their import line.
- Known false-positive class: re-exports in `__init__.py` and side-effect imports (e.g. `from . import pilot` registering pilot checks) are separated into their own table below.

## Likely-unused imports: 46

| File | Line | Symbol | Category |
|---|---|---|---|
| `nhi_sentinel/api/deps.py` | 6 | `from ..contracts import Role` | likely unused |
| `nhi_sentinel/api/deps.py` | 7 | `from ..core.auth import can` | likely unused |
| `nhi_sentinel/api/routes_core.py` | 15 | `from ..core.db import Session as DbSession` | likely unused |
| `nhi_sentinel/api/routes_core.py` | 34 | `from ..core.auth import me_view as _mv` | likely unused |
| `nhi_sentinel/api/routes_data.py` | 5 | `from fastapi import Response` | likely unused |
| `nhi_sentinel/api/routes_data.py` | 21 | `from ..core.security import digest_of` | likely unused |
| `nhi_sentinel/api/routes_data.py` | 23 | `from ..reports.builder import validate_grounding` | likely unused |
| `nhi_sentinel/api/routes_gov.py` | 16 | `from ..core.db import Run` | likely unused |
| `nhi_sentinel/api/routes_gov.py` | 16 | `from ..core.db import ScopeVersion` | likely unused |
| `nhi_sentinel/api/routes_gov.py` | 16 | `from ..core.db import User` | likely unused |
| `nhi_sentinel/api/routes_gov.py` | 16 | `from ..core.db import new_id` | likely unused |
| `nhi_sentinel/api/routes_gov.py` | 16 | `from ..core.db import utcnow` | likely unused |
| `nhi_sentinel/api/routes_gov.py` | 20 | `from ..core.security import sha256_hex` | likely unused |
| `nhi_sentinel/assistant.py` | 14 | `from .core.db import Report` | likely unused |
| `nhi_sentinel/checks/reference.py` | 8 | `from .base import CheckOutcome` | likely unused |
| `nhi_sentinel/config.py` | 6 | `os` | likely unused |
| `nhi_sentinel/connectors/adapters.py` | 8 | `from .base import parse_ts` | likely unused |
| `nhi_sentinel/contracts/models.py` | 9 | `from . import AgentLifecycle` | likely unused |
| `nhi_sentinel/contracts/models.py` | 9 | `from . import CheckStatus` | likely unused |
| `nhi_sentinel/contracts/models.py` | 9 | `from . import RunState` | likely unused |
| `nhi_sentinel/core/repo.py` | 10 | `from datetime import datetime` | likely unused |
| `nhi_sentinel/core/repo.py` | 15 | `from .db import Run` | likely unused |
| `nhi_sentinel/governance.py` | 7 | `from sqlalchemy import text` | likely unused |
| `nhi_sentinel/governance.py` | 11 | `from .core.db import User` | likely unused |
| `nhi_sentinel/governance.py` | 11 | `from .core.db import session_scope` | likely unused |
| `nhi_sentinel/policies/score.py` | 8 | `from .severity import inputs_from_facts` | likely unused |
| `nhi_sentinel/reports/builder.py` | 11 | `from ..core.db import EvidenceArtifact` | likely unused |
| `nhi_sentinel/reports/builder.py` | 14 | `from ..core.events import emit` | likely unused |
| `nhi_sentinel/worker/graph.py` | 8 | `from dataclasses import field` | likely unused |
| `nhi_sentinel/worker/nodes.py` | 6 | `from datetime import timedelta` | likely unused |
| `nhi_sentinel/worker/nodes.py` | 14 | `from ..core.db import Engagement` | likely unused |
| `nhi_sentinel/worker/nodes.py` | 14 | `from ..core.db import Run` | likely unused |
| `nhi_sentinel/worker/nodes.py` | 14 | `from ..core.db import Task` | likely unused |
| `nhi_sentinel/worker/nodes.py` | 14 | `from ..core.db import session_scope` | likely unused |
| `nhi_sentinel/worker/nodes.py` | 22 | `from ..policies.score import compute_score` | likely unused |
| `nhi_sentinel/worker/nodes.py` | 24 | `from . import graph` | likely unused |
| `tests/test_api_stream.py` | 12 | `pytest` | likely unused |
| `tests/test_auth_roles.py` | 4 | `from .conftest import DEMO_PASSWORD` | likely unused |
| `tests/test_ci_scheduler.py` | 6 | `from sqlalchemy import select` | likely unused |
| `tests/test_ci_scheduler.py` | 8 | `from nhi_sentinel.core.db import Engagement` | likely unused |
| `tests/test_ci_scheduler.py` | 11 | `from nhi_sentinel.scheduler import create_subscription` | likely unused |
| `tests/test_evidence_custody.py` | 6 | `time` | likely unused |
| `tests/test_evidence_custody.py` | 7 | `from sqlalchemy import func` | likely unused |
| `tests/test_exports_assistant.py` | 5 | `from nhi_sentinel.exports import sanitize_cell` | likely unused |
| `tests/test_exports_assistant.py` | 7 | `from .conftest import APPROVER1` | likely unused |
| `tests/test_redteam_injection.py` | 12 | `from .conftest import full_run_id` | likely unused |

## Re-export / side-effect imports in `__init__.py`: 18

These bind names that are never referenced inside the same file. That is the normal
pattern for package re-exports (`from .base import REGISTRY` etc.) and for
registration side effects (`from . import pilot` registers pilot checks;
`from . import reference` likewise). Listed for completeness — do not bulk-delete.

| File | Line | Symbol | Category |
|---|---|---|---|
| `nhi_sentinel/checks/__init__.py` | 2 | `from .base import REGISTRY` | re-export / side-effect import (verify intended) |
| `nhi_sentinel/checks/__init__.py` | 2 | `from .base import Check` | re-export / side-effect import (verify intended) |
| `nhi_sentinel/checks/__init__.py` | 2 | `from .base import CheckOutcome` | re-export / side-effect import (verify intended) |
| `nhi_sentinel/checks/__init__.py` | 2 | `from .base import enabled_checks` | re-export / side-effect import (verify intended) |
| `nhi_sentinel/checks/__init__.py` | 2 | `from .base import register` | re-export / side-effect import (verify intended) |
| `nhi_sentinel/checks/__init__.py` | 3 | `from . import reference` | re-export / side-effect import (verify intended) |
| `nhi_sentinel/checks/__init__.py` | 6 | `from . import pilot` | re-export / side-effect import (verify intended) |
| `nhi_sentinel/connectors/__init__.py` | 1 | `from .base import CollectionContext` | re-export / side-effect import (verify intended) |
| `nhi_sentinel/connectors/__init__.py` | 1 | `from .base import CollectResult` | re-export / side-effect import (verify intended) |
| `nhi_sentinel/connectors/__init__.py` | 1 | `from .base import FixtureError` | re-export / side-effect import (verify intended) |
| `nhi_sentinel/connectors/__init__.py` | 1 | `from .base import ImportConnector` | re-export / side-effect import (verify intended) |
| `nhi_sentinel/connectors/__init__.py` | 2 | `from .adapters import ADAPTERS` | re-export / side-effect import (verify intended) |
| `nhi_sentinel/connectors/__init__.py` | 2 | `from .adapters import AgentRegistryConnector` | re-export / side-effect import (verify intended) |
| `nhi_sentinel/connectors/__init__.py` | 2 | `from .adapters import AwsIamConnector` | re-export / side-effect import (verify intended) |
| `nhi_sentinel/connectors/__init__.py` | 2 | `from .adapters import EntraConnector` | re-export / side-effect import (verify intended) |
| `nhi_sentinel/connectors/__init__.py` | 2 | `from .adapters import GithubConnector` | re-export / side-effect import (verify intended) |
| `nhi_sentinel/connectors/__init__.py` | 2 | `from .adapters import get_adapter` | re-export / side-effect import (verify intended) |
| `nhi_sentinel/reports/__init__.py` | 1 | `from . import builder` | re-export / side-effect import (verify intended) |

## TODO / FIXME / XXX / HACK markers: 0

None found in `nhi_sentinel/**/*.py` or `tests/**/*.py`.

## Note on this pass

- Report-only: no source files under `nhi_sentinel/` or `tests/` were modified.
- Findings cluster in the API layer (`api/routes_*.py`, `api/deps.py`) and `worker/nodes.py` — mostly imports that annotations or earlier revisions stopped referencing, plus a few (`import os` in `config.py`, `import time` in `test_evidence_custody.py`) that look like leftovers from removed code.
- Each row in the first table was verified to appear exactly once in its file (the import line itself) for the spot-checked subset; treat the rest with the same
  one-grep check before removal.