FROM python:3.12.4-slim-bookworm@sha256:a3e58f9399353be051735f09be0316bfdeab571a5c6a24fd78b92df85bcb2d85 AS build
WORKDIR /app
RUN pip install --no-cache-dir uv==0.5.26
COPY . .
# The API image installs its declared closure only. Pulling every workspace
# package into the control plane made builds slower and accidentally widened
# the runtime surface with components this service never imports.
RUN uv sync --frozen --package ctfmesh-api --no-dev

# This non-deployed target exists for reproducible Python checks when the host
# has no usable virtual environment. Pyright's bundled Node binary requires
# libatomic on Debian slim; the production API image stays dependency-minimal.
FROM build AS test
RUN apt-get update \
    && apt-get install --no-install-recommends --yes libatomic1 \
    && rm -rf /var/lib/apt/lists/*

FROM python:3.12.4-slim-bookworm@sha256:a3e58f9399353be051735f09be0316bfdeab571a5c6a24fd78b92df85bcb2d85
RUN useradd --create-home --uid 10001 ctfmesh
WORKDIR /app
COPY --from=build /app /app
USER 10001
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["sh", "-c", "alembic -c packages/db/alembic.ini upgrade head && exec uvicorn ctfmesh_api.main:app --host 0.0.0.0 --port 8000"]
