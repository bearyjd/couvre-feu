# Couvre-feu parent app image. No build step: Node runs the TypeScript directly.
# Build from the repository root:  docker build -f deploy/docker/Dockerfile -t couvrefeu:local .
# The base is pinned by exact Node version AND the multi-arch index digest (verified 2026-10-17);
# refresh both together when package.json "engines.node" changes.
FROM node:26.13.1-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts

FROM node:26.13.1-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc
# openssh-client is the router transport (the service runs `ssh`). uid/gid 10001 is fixed so that
# host-owned private files (manifest, data directory, agent socket) can be owned by the same uid.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 couvrefeu \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin couvrefeu
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json LICENSE VERSION* ./
COPY shared/src ./shared/src
COPY service/src ./service/src
COPY service/migrations ./service/migrations
COPY web/public ./web/public
COPY deploy/docker/healthcheck.mjs ./healthcheck.mjs
ENV NODE_ENV=production
USER 10001:10001
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["node", "/app/healthcheck.mjs"]
ENTRYPOINT ["node", "/app/service/src/integration-main.ts"]
CMD ["/etc/couvrefeu/manifest.json"]
