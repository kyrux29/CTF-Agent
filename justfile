set dotenv-load := true

setup:
    uv sync --all-packages --all-groups
    pnpm install --frozen-lockfile

check-backend:
    uv lock --check
    uv run ruff format --check .
    uv run ruff check .
    uv run pyright
    uv run pytest -q

check-web:
    pnpm --filter @ctfmesh/web check
    pnpm --filter @ctfmesh/pi-runner check

check: check-backend check-web

test-unit:
    uv run pytest tests/unit tests/contract tests/security -q

test-integration:
    uv run pytest tests/integration -q

test-e2e:
    uv run pytest tests/e2e -q

dev-up:
    docker compose up -d --build --wait

# Creates the ignored local internal-service configuration once. Provider keys
# are entered through browser Settings and are not accepted here.
m6-bootstrap:
    python3 support/scripts/dev/bootstrap_m6_runtime.py

# Adds Power's separate local service capabilities without touching M6 values.
# AI provider keys are entered only through browser Settings.
power-bootstrap:
    python3 support/scripts/dev/bootstrap_power_runtime.py

m6-up:
    docker compose --profile m6-ui up -d --build --wait

dev-down:
    docker compose down --remove-orphans

clean:
    python3 support/scripts/dev/clean.py

clean-all:
    python3 support/scripts/dev/clean.py --dependencies
