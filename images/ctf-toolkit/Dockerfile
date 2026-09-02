# Reviewed Power toolkit image. The digest-pinned Alpine base and exact package
# versions keep the slim CTF action surface reproducible without baking in any
# challenge, credential, provider client, or Docker tooling.
FROM alpine:3.21.3@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c

LABEL org.opencontainers.image.title="CTFMesh Power CTF toolkit" \
      org.opencontainers.image.description="Reviewed local-only tooling for authorized CTF workspaces" \
      org.opencontainers.image.licenses="MIT"

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TERM=xterm

# Keep the broadly useful tooling in a single lightweight image. Ghidra and
# Sage are intentionally excluded from this slim tag: they are large, optional
# P5 follow-ons and must never make the default local Power profile unusable.
COPY images/ctf-toolkit/requirements.lock /tmp/ctfmesh-toolkit-requirements.lock

RUN apk add --no-cache \
      bash=5.2.37-r0 \
      binutils=2.43.1-r3 \
      build-base=0.5-r3 \
      capstone=5.0.3-r0 \
      coreutils=9.5-r2 \
      curl=8.14.1-r2 \
      exiftool=13.03-r0 \
      file=5.46-r2 \
      gdb=15.2-r0 \
      git=2.47.3-r0 \
      gmp-dev=6.3.0-r2 \
      jq=1.7.1-r0 \
      ltrace=0.7.3-r6 \
      mpc1-dev=1.3.1-r1 \
      mpfr-dev=4.2.1-r0 \
      py3-beautifulsoup4=4.12.3-r3 \
      py3-pip=24.3.1-r0 \
      py3-pycryptodome=3.20.0-r1 \
      py3-requests=2.33.1-r0 \
      py3-z3=4.13.3-r0 \
      python3=3.12.14-r0 \
      radare2=5.9.8-r0 \
      ripgrep=14.1.1-r0 \
      strace=6.12-r0 \
      tmux=3.5a-r0 \
      tshark=4.4.2-r0 \
      wget=1.25.0-r0 \
      httpie=3.2.4-r0 \
    && python3 -m pip install --break-system-packages \
      --requirement /tmp/ctfmesh-toolkit-requirements.lock \
    && python3 -m pip check \
    && addgroup --gid 1000 ctf \
    && adduser --disabled-password --gecos "" --uid 1000 --ingroup ctf ctf \
    && mkdir -p /challenge /work \
    && chown ctf:ctf /challenge /work \
    && chmod 0755 /challenge /work

# Prompt packs stay in the signed orchestrator package and arrive as bounded
# context. Keeping them out of this image leaves the workspace with tools and
# challenge data only, never a second mutable source of agent instructions.

USER 1000:1000
WORKDIR /work
CMD ["tail", "-f", "/dev/null"]
