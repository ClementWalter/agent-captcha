# syntax=docker/dockerfile:1
# Why: ship the TypeScript Express server + static frontend as a minimal image.
# tsx compiles on-the-fly so we skip a separate build stage; runtime footprint
# is small enough to fit Scaleway Serverless Container cold-start budgets.

FROM node:22-alpine

WORKDIR /app

# Install deps against the committed package-lock for reproducible builds.
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm install --production
# tsx is a dev dependency; add it back explicitly for runtime.
RUN npm install tsx@^4.19.3

COPY src ./src
COPY public ./public
COPY tsconfig.json ./

ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080

CMD ["npx", "tsx", "src/server/index.ts"]
