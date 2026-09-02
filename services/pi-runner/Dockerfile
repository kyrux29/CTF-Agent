# The digest-pinned Node base matches the web build image and satisfies Pi 0.84.4's
# Node >=22.21 is required for the built-in --use-env-proxy guard. This service
# never receives a challenge mount.
FROM node:22.23.1-alpine3.23@sha256:8516dce0483394d5708d4b2ee6cacb79fb1d617ea4e2787c2120bcca92ce372e

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
ENV NODE_ENV=production
# Pi normally uses a home-directory agent config. The runner passes an explicit
# in-memory settings manager and a fixed agent dir, so HOME is only a fail-closed
# fallback rather than an operator-home mount.
ENV HOME=/nonexistent

WORKDIR /workspace

RUN corepack enable && corepack prepare pnpm@10.18.3 --activate

# Copy lock inputs first so changing application code does not invalidate the
# dependency layer. `--ignore-scripts` avoids an install-time package hook.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY services/pi-runner/package.json ./services/pi-runner/package.json
RUN pnpm --filter @ctfmesh/pi-runner... install --frozen-lockfile --ignore-scripts

COPY services/pi-runner/tsconfig.json ./services/pi-runner/tsconfig.json
COPY services/pi-runner/src ./services/pi-runner/src
RUN pnpm --filter @ctfmesh/pi-runner build

# The root filesystem is mounted read-only at runtime. The only mutable data is
# the named session volume at /data/pi-sessions, prepared by pi-session-init.
RUN addgroup -S -g 10001 ctfmesh \
    && adduser -S -D -H -u 10001 -G ctfmesh ctfmesh \
    && mkdir -p /opt/ctfmesh/empty-cwd /opt/ctfmesh/agent /data/pi-sessions \
    && chown -R ctfmesh:ctfmesh /opt/ctfmesh /data/pi-sessions

USER 10001:10001
WORKDIR /workspace/services/pi-runner

CMD ["node", "dist/index.js"]
