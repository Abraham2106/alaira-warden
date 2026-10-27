# ALAIRA Warden

Evidence-based npm vulnerability investigations with Zetaris, Meterless Nightshift,
H-MEM, deterministic correlation, isolated remediation and supervised GitHub PRs.

## Run locally

Requirements: Python 3.12, Node.js, Git, uv and Docker Desktop running Linux containers.

```powershell
uv sync --frozen
npm ci --ignore-scripts
python scripts/bootstrap.py
docker compose -f compose.yaml -f compose.dev.yaml up -d db
uv run python -m alaira_warden.db
uv run python scripts/provision_identity.py
uv run uvicorn alaira_warden.main:app --host 127.0.0.1 --port 8000 --workers 1
```

Open http://127.0.0.1:8000 and connect using the individual credential generated in
artifacts/private/administrator.token. Bootstrap/provisioning are first-install steps;
do not recreate identities or overwrite the existing .env during an upgrade.

Configure sponsors through environment variables documented in .env.example.
Zetaris is the investigation data layer; PostgreSQL holds transactions, audit and checkpoints.
NVIDIA is configured in Nightshift Providers. No provider key belongs in source control.

## Use

Register an authorized repository, generate its inventory, create an investigation and
advance its stages. Imported deployment history remains separate from current exposure.
Model critique can revise its read plan but cannot assign exposure. Review findings,
compose a response plan, then use Run correction and scanners with exact candidate versions.

Build and provision the offline image before execution:

```powershell
docker build -f src/alaira_warden/remediation/Dockerfile.scanners -t alaira-warden-remediation-tools src/alaira_warden/remediation
docker image inspect alaira-warden-remediation-tools --format '{{.Id}}'
```

Set WARDEN_REMEDIATION_IMAGE to that immutable sha256 ID. The included npm cache covers
the controlled lodash fixture; other applications require their authorized dependencies
preloaded into an approved image. Project execution has no network, no provider credentials,
a read-only container root and finite budgets. Missing dependencies or scanners block approval.

Approve validated artifact binds the exact commit, validations, repository and destination.
Publish approved PR rechecks actors and reconciles existing PRs. GitHub requires repository
Contents and Pull requests write permissions. Dependabot intake additionally requires
Dependabot alerts read. Merge and deployment remain prohibited.

Corrections and publication run in the trusted host API, not the read-only Compose API.
Use one API worker while H-MEM uses its single-process persistence. Product jobs are persistent;
interrupted jobs require cancellation/review and never automatically replay unknown work.

## Sample and verification

Help > Create sample investigation uses labeled synthetic inputs without sponsor credentials.
It does not prove live sponsor integrations or actual remediation.

```powershell
uv run pytest -q
node --test tests/*.test.cjs
uv run ruff check .
uv run ruff format --check .
```

Database tests require WARDEN_TEST_DATABASE_URL pointing to a database ending in _test.
Real Docker safety tests use WARDEN_RUN_DOCKER_TESTS=1. Full scanner integration uses
WARDEN_RUN_REMEDIATION_SCANNER_TESTS=1. The HTTP product execution test can also run real
scanners with WARDEN_RUN_PRODUCT_DOCKER=1 and WARDEN_REMEDIATION_IMAGE configured.

Verified locally: 411 Python tests passed, 5 skipped; 12 UI checks passed. A separate
HTTP test executed Git, npm, Syft, Trivy and OSV-Scanner for a controlled repository.
GitHub PR transport was controlled in tests: an authenticated live PR was not published.
No GitHub credential was available in this installation when this version was verified.
