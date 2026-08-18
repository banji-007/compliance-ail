# Single image reused for agent, proxy, and upstream roles. Which role a container
# plays is decided entirely by its command in docker-compose, not by the image.
FROM node:24-alpine

# procps gives a real `ps`; iproute2/busybox give ip/netstat for the network probes.
RUN apk add --no-cache procps iproute2 curl

WORKDIR /opt/ail
COPY package.json package-lock.json* ./
RUN npm install --no-audit --no-fund

COPY proxy ./proxy
COPY agent ./agent

# Ledger is a shared volume mounted at /ledger by compose.
ENV AIL_LEDGER=/ledger/proxy-ledger.jsonl
CMD ["node", "--version"]
