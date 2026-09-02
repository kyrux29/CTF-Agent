# This service intentionally uses only the Python standard library. It is a
# narrow CONNECT tunnel, not a general HTTP proxy or a place to run provider
# SDK code. The only container with model credentials is pi-runner-live.
FROM python:3.12.4-slim-bookworm@sha256:a3e58f9399353be051735f09be0316bfdeab571a5c6a24fd78b92df85bcb2d85

RUN groupadd --gid 65532 ctfmesh-proxy \
    && useradd --uid 65532 --gid 65532 --create-home --shell /usr/sbin/nologin ctfmesh-proxy

WORKDIR /app
COPY services/provider-proxy/src /app/src
USER 65532:65532
ENV PYTHONPATH=/app/src PYTHONUNBUFFERED=1

EXPOSE 3128
CMD ["python", "-m", "ctfmesh_provider_proxy.server"]
