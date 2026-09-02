# The ReAct runner has no Docker socket, challenge mount, or provider API-key
# environment. A future dispatcher supplies a request-scoped key in process
# memory only; this image proves that boundary at the composition root.
FROM python:3.12.4-slim-bookworm@sha256:a3e58f9399353be051735f09be0316bfdeab571a5c6a24fd78b92df85bcb2d85 AS build

WORKDIR /app
RUN pip install --no-cache-dir uv==0.5.26
COPY . .
RUN uv sync --frozen --package ctfmesh-solver-runtime --no-dev

FROM python:3.12.4-slim-bookworm@sha256:a3e58f9399353be051735f09be0316bfdeab571a5c6a24fd78b92df85bcb2d85

RUN useradd --uid 65532 --no-create-home --shell /usr/sbin/nologin ctfmesh
WORKDIR /app
COPY --from=build /app /app
USER 65532:65532
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
CMD ["/bin/false"]
