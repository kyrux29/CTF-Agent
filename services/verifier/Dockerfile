# The verifier image is intentionally distinct from the API image.  It owns no
# database connection, provider SDK, challenge source mount, or Docker client;
# only the declarative replay package and its domain contracts are installed.
FROM python:3.12.4-slim-bookworm@sha256:a3e58f9399353be051735f09be0316bfdeab571a5c6a24fd78b92df85bcb2d85 AS build
WORKDIR /app
RUN pip install --no-cache-dir uv==0.5.26
COPY . .
RUN uv sync --frozen --package ctfmesh-verifier --no-dev

FROM python:3.12.4-slim-bookworm@sha256:a3e58f9399353be051735f09be0316bfdeab571a5c6a24fd78b92df85bcb2d85
RUN groupadd --gid 65532 ctfmesh \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin ctfmesh
WORKDIR /app
COPY --from=build /app /app
USER 65532:65532
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1
CMD ["ctfmesh-verifier-worker"]
