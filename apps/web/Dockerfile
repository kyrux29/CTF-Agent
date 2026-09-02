FROM node:22.23.1-alpine3.23@sha256:8516dce0483394d5708d4b2ee6cacb79fb1d617ea4e2787c2120bcca92ce372e AS build

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH

WORKDIR /workspace

RUN corepack enable && corepack prepare pnpm@10.18.3 --activate

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web/package.json ./apps/web/package.json
RUN pnpm --filter @ctfmesh/web... install --frozen-lockfile --ignore-scripts

COPY apps/web/index.html apps/web/tsconfig.json apps/web/vite.config.ts ./apps/web/
COPY apps/web/src ./apps/web/src

RUN pnpm --filter @ctfmesh/web build

FROM nginx:1.30.4-alpine3.24@sha256:97d490c12ba55b4946b01546d1c3ed324e8d41ab1c9fcb2a616aa470620e5b46 AS runtime

LABEL org.opencontainers.image.title="CTFMesh Evidence Workbench" \
      org.opencontainers.image.description="Evidence-centric console for authorized CTFMesh runs"

COPY --chown=nginx:nginx apps/web/nginx.conf /etc/nginx/nginx.conf
COPY --chown=nginx:nginx apps/web/security-headers.conf /etc/nginx/security-headers.conf
COPY --from=build --chown=nginx:nginx /workspace/apps/web/dist /usr/share/nginx/html

USER nginx:nginx

EXPOSE 8080
STOPSIGNAL SIGQUIT

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/sbin/nginx"]
CMD ["-g", "daemon off;"]
