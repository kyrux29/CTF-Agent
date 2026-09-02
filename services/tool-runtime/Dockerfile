# One minimal, digest-pinned image serves the gateway and the two source-only
# slots. Runtime commands select a fixed module; no container receives a shell
# endpoint, package manager, provider credential, or Docker socket.
FROM python:3.12.4-slim-bookworm@sha256:a3e58f9399353be051735f09be0316bfdeab571a5c6a24fd78b92df85bcb2d85 AS build

WORKDIR /app
RUN pip install --no-cache-dir uv==0.5.26
COPY . .
# A slot/gateway image needs only the typed runtime closure, not every provider,
# CLI, evaluation, or MCP package in the workspace.
RUN uv sync --frozen --package ctfmesh-tool-runtime --no-dev

FROM python:3.12.4-slim-bookworm@sha256:a3e58f9399353be051735f09be0316bfdeab571a5c6a24fd78b92df85bcb2d85

# Match the API artifact-volume group without running the gateway as the same
# UID. The source slots do not mount this volume at all.
RUN groupadd --gid 10001 ctfmesh-artifacts \
    && useradd --uid 65532 --gid 10001 --create-home --shell /usr/sbin/nologin ctfmesh
WORKDIR /app
COPY --from=build /app /app
# The gateway needs group-only write access to the shared immutable artifact
# volume. Compose explicitly overrides both source slots back to 65532:65532,
# and those slots do not mount the artifact volume at all.
USER 65532:10001
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1

CMD ["python", "-m", "ctfmesh_tool_runtime.gateway_main"]
