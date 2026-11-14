# Agent "muse" — zkVerify Agent Games (Node 22, TypeScript).
# Two-stage: tsc is a devDependency, so TypeScript is built in the builder
# stage and only dist/ + production deps ship in the runtime stage.
# The OFFICIAL platform circuit artifacts (circuits/artifacts/) are copied
# into the runtime image — the server proves locally with snarkjs.

FROM node:22-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=builder /app/dist ./dist
# Official platform Groth16 artifacts (wasm/zkey/vkey) — needed at runtime.
# The .wasm/.zkey binaries are NOT stored in git (the GitHub connector
# cannot push binary files), so they are fetched here at image build time
# from the platform's own URLs by scripts/download-artifacts.sh, which
# verifies each file's expected size. The text files (vkey.json, CHECKSUMS,
# INSPECT/PROBE notes) come from the repo via the COPY below.
COPY circuits ./circuits
COPY scripts/download-artifacts.sh ./scripts/download-artifacts.sh
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/* \
  && bash scripts/download-artifacts.sh
USER node
EXPOSE 3000
# No curl in the slim image: health-check with node's built-in fetch.
# GET /health needs no signature (see src/server.ts).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/health').then(r=>{process.exit(r.ok?0:1)}).catch(()=>process.exit(1))"
CMD ["node", "dist/server.js"]
