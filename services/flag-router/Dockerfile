# The router is separate from both solver and Control API. It can re-read
# immutable observation artifacts but never gets a Docker socket or provider key.
FROM python:3.12.4-slim-bookworm@sha256:a3e58f9399353be051735f09be0316bfdeab571a5c6a24fd78b92df85bcb2d85 AS build

WORKDIR /app
RUN pip install --no-cache-dir uv==0.5.26
COPY . .
RUN uv sync --frozen --package ctfmesh-flag-router --no-dev

FROM python:3.12.4-slim-bookworm@sha256:a3e58f9399353be051735f09be0316bfdeab571a5c6a24fd78b92df85bcb2d85

# Sandboxd and the API write immutable artifacts as UID/GID 10001 with mode
# 0600. The router needs the same numeric read identity to re-read an exact
# observation, while Compose still mounts the volume read-only and the router
# retains no Docker socket, provider credentials, or target network.
RUN groupadd --gid 10001 ctfmesh-artifacts \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin ctfmesh
WORKDIR /app
COPY --from=build /app /app
USER 10001:10001
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
CMD ["ctfmesh-flag-router"]
