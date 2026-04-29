# syntax=docker/dockerfile:1.7

FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY tsconfig.json ./
COPY src ./src
RUN npx tsc -p tsconfig.json
RUN npm prune --omit=dev

FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8080
ENV HOST=0.0.0.0

# Run as a non-root user.
RUN addgroup -S relay && adduser -S relay -G relay

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY public ./public
COPY package.json ./

USER relay
EXPOSE 8080

# A simple healthcheck so platforms like Fly.io / Railway can probe the app.
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${PORT}/healthz" >/dev/null || exit 1

CMD ["node", "dist/index.js"]
