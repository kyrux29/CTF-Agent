# Narrow compatibility fixture for P1–P4 smoke tests. The deployed Power
# workspace now uses `images/ctf-toolkit/Dockerfile`; retain this image only so
# earlier milestone proofs stay fast and independently reproducible.
FROM alpine:3.21.3@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c

# coreutils provides a predictable `timeout` implementation for the manager's
# in-container wall-clock guard. No Docker CLI, credential, agent code or
# challenge content is baked into this image.
RUN apk add --no-cache build-base coreutils gdb python3 \
    && addgroup --gid 1000 ctf \
    && adduser --disabled-password --gecos "" --uid 1000 --ingroup ctf ctf \
    && mkdir -p /challenge /work \
    && chown ctf:ctf /challenge /work

USER 1000:1000
WORKDIR /work
CMD ["tail", "-f", "/dev/null"]
