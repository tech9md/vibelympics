# Build stage - use Chainguard node -dev image (has npm, shell)
FROM cgr.dev/chainguard/node:latest-dev AS builder

# Switch to root to handle file permissions
USER root

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY frontend/package*.json ./frontend/
COPY backend/package*.json ./backend/

# Change ownership to node user so npm can write
RUN chown -R node:node /app

# Switch back to node user for npm operations
USER node

# Install all dependencies (including dev dependencies for build)
RUN npm install && \
    cd frontend && npm install && \
    cd ../backend && npm install

# Copy source code (as root to ensure we can copy, then fix ownership)
USER root
COPY frontend/ ./frontend/
COPY backend/ ./backend/
RUN chown -R node:node /app

# Switch back to node for build
USER node

# Build the frontend
RUN cd frontend && npm run build

# Create initial data file
RUN echo "[]" > /app/backend/data.json

# Production stage - use minimal Chainguard node image (distroless)
FROM cgr.dev/chainguard/node:latest

WORKDIR /app

# Copy backend (server, package.json, node_modules, data.json) from builder
# Use --chown=node:node to ensure the node user can write to data.json
COPY --from=builder --chown=node:node /app/backend/ ./backend/

# Copy built frontend
COPY --from=builder --chown=node:node /app/frontend/dist ./frontend/dist

WORKDIR /app/backend

# Expose port
EXPOSE 3000

# Health check - verifies the API is responding
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["node", "-e", "require('http').get('http://localhost:3000/api/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"]

# Start the server - Chainguard node image has ENTRYPOINT ["node"], so we just specify the script
CMD ["server.js"]
