FROM node:20-alpine

WORKDIR /app

# Install build dependencies for better-sqlite3
RUN apk add --no-cache python3 make g++

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source
COPY tsconfig.json ./
COPY src ./src

# Build
RUN npm run build

# Create data directory
RUN mkdir -p /app/data

# Environment
ENV RELAY_PORT=8080
ENV DB_PATH=/app/data/dojo-relay.db

EXPOSE 8080

CMD ["node", "dist/index.js"]
