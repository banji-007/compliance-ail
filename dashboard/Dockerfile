# Stage 1: Install dependencies
# npm install (not npm ci) because no package-lock.json is committed.
# The lock file is generated here and carried into the builder stage.
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm install --prefer-offline

# Stage 2: Build the Next.js application
FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/package-lock.json ./package-lock.json
COPY . .
# NEXT_PUBLIC_* vars are baked into the JS bundle at build time - only a UI
# default belongs here. CONTROL_PLANE_READ_KEY/WRITE_KEY and
# DASHBOARD_READ/WRITE_USER/PASSWORD are never build ARGs; they are read
# from runtime environment variables by app/api/*/route.ts and
# middleware.ts, which run server-side in the standalone Node server (see
# docker-compose.yml).
ARG NEXT_PUBLIC_TENANT_ID=tenant_default
ENV NEXT_PUBLIC_TENANT_ID=$NEXT_PUBLIC_TENANT_ID
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# Stage 3: Production runtime (standalone output)
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3001
# Docker sets HOSTNAME to the container ID by default; the standalone
# server.js binds to process.env.HOSTNAME if set, which would otherwise make
# it listen only on the container's own network IP - unreachable via
# localhost from inside the container (breaks the healthcheck) even though
# the published port would still work from the host.
ENV HOSTNAME=0.0.0.0

# next.config.ts sets output: "standalone" — copy the minimal self-contained bundle
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

EXPOSE 3001
CMD ["node", "server.js"]
