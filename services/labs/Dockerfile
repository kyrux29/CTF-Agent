FROM python:3.12.4-slim-bookworm@sha256:a3e58f9399353be051735f09be0316bfdeab571a5c6a24fd78b92df85bcb2d85

# The target has no package manager, shell entrypoint, source mount, or write
# layer at runtime. It only needs the Python standard library and one read-only
# per-lab flag volume provisioned by the separate controller.
RUN groupadd --gid 65532 ctfmesh \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin ctfmesh
WORKDIR /app
COPY services/labs/src /app
USER 65532:65532
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 8080
CMD ["python", "-m", "ctfmesh_labs.server"]
