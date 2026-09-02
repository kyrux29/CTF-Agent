#!/usr/bin/env sh
# Start P3's isolated echo target, run the opt-in IAT proof, then remove every
# test resource. No test target starts with the product Power profile.
set -eu

project="ctfmesh-p3-smoke"
compose_file="tests/compose/power-tube-echo.yml"

cleanup() {
  docker compose --project-name "$project" --file "$compose_file" down --volumes --remove-orphans
}
trap cleanup EXIT INT TERM

docker compose --project-name "$project" --file "$compose_file" up --build --abort-on-container-exit --exit-code-from proof
CTFMESH_RUN_POWER_DOCKER_SMOKE=1 uv run pytest -q tests/integration/test_power_iat_sandboxd_smoke.py
