# The router is separate from both solver and Control API. It can re-read
# immutable observation artifacts but never gets a Docker socket or provider key.
FROM python:3.12.4-slim-bookworm@sha256:a3e58f9399353be051735f09be0316bfdeab571a5c6a24fd78b92df85bcb2d85 AS build

WORKDIR /app
RUN pip install --no-cache-dir uv==0.5.26
COPY . .
RUN uv sync --frozen --package ctfmesh-flag-router --no-dev

FROM python:3.12.4-slim-bookworm@sha256:a3e58f9399353be051735f09be0316bfdeab571a5c6a24fd78b92df85bcb2d85

RUN groupadd --gid 10001 ctfmesh-artifacts \
    && useradd --uid 65532 --gid 10001 --no-create-home --shell /usr/sbin/nologin ctfmesh
WORKDIR /app
COPY --from=build /app /app
USER 65532:10001
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
CMD ["ctfmesh-flag-router"]
