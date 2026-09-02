# `sandboxd` is a trusted control-plane service only in the opt-in Power
# profile. It is intentionally separate from solver-runtime: this service may
# access the local Docker socket while a solver workspace never can.
FROM python:3.12.4-slim-bookworm@sha256:a3e58f9399353be051735f09be0316bfdeab571a5c6a24fd78b92df85bcb2d85 AS build

WORKDIR /app
RUN pip install --no-cache-dir uv==0.5.26
COPY . .
RUN uv sync --frozen --package ctfmesh-sandboxd --no-dev

FROM python:3.12.4-slim-bookworm@sha256:a3e58f9399353be051735f09be0316bfdeab571a5c6a24fd78b92df85bcb2d85

WORKDIR /app
COPY --from=build /app /app
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# Root is needed only to access the host-controlled Unix socket. The Compose
# profile drops Linux capabilities and does not grant privileged/host modes.
CMD ["ctfmesh-sandboxd"]
