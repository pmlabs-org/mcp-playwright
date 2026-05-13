ARG PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# ------------------------------
# Base
# ------------------------------
# Installs Node prod dependencies and Chromium system libraries.
# Rewritten without --mount=type=cache/bind for Cloud Build compatibility.
FROM node:22-bookworm-slim AS base

ARG PLAYWRIGHT_BROWSERS_PATH
ENV PLAYWRIGHT_BROWSERS_PATH=${PLAYWRIGHT_BROWSERS_PATH}

WORKDIR /app

# Copy workspace manifests so npm ci can resolve all packages
COPY package.json package-lock.json ./
COPY packages/playwright-mcp/package.json     ./packages/playwright-mcp/
COPY packages/playwright-cli-stub/package.json ./packages/playwright-cli-stub/
COPY packages/extension/package.json          ./packages/extension/

RUN npm ci --omit=dev && \
    npx -y playwright-core install-deps chromium

# ------------------------------
# Browser
# ------------------------------
# Downloads the Chromium binary into a cacheable layer.
FROM base AS browser

RUN npx -y playwright-core install chromium

# ------------------------------
# Runtime
# ------------------------------
FROM base

ARG PLAYWRIGHT_BROWSERS_PATH
ARG USERNAME=node
ENV NODE_ENV=production

RUN chown -R ${USERNAME}:${USERNAME} node_modules && \
    mkdir -p /app/.playwright-mcp && \
    chown ${USERNAME}:${USERNAME} /app/.playwright-mcp

USER ${USERNAME}

COPY --from=browser --chown=${USERNAME}:${USERNAME} ${PLAYWRIGHT_BROWSERS_PATH} ${PLAYWRIGHT_BROWSERS_PATH}
COPY --chown=${USERNAME}:${USERNAME} packages/playwright-mcp/cli.js packages/playwright-mcp/oauth-server.js packages/playwright-mcp/package.json ./


# OAuth proxy spawns playwright-mcp on port 8081 internally and exposes OAuth + MCP on $PORT
ENTRYPOINT ["node", "oauth-server.js"]
