# Multi-stage build for PyShield with Chainguard images
# Chainguard provides minimal, secure, distroless container images

# Stage 1: Build frontend
FROM cgr.dev/chainguard/node:latest AS frontend-builder

WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm install

COPY frontend/ ./
RUN npm run build

# Stage 2: Python backend with Wolfi (Python 3.12)
FROM cgr.dev/chainguard/wolfi-base:latest AS builder

WORKDIR /app

# Install Python 3.12 and pip
RUN apk add --no-cache python-3.12 py3.12-pip

# Install Python dependencies
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Stage 3: Minimal runtime with Wolfi (Python 3.12)
FROM cgr.dev/chainguard/wolfi-base:latest

WORKDIR /app

# Install only Python runtime (no build tools)
RUN apk add --no-cache python-3.12

# Copy Python dependencies from builder
COPY --from=builder /usr/lib/python3.12/site-packages /usr/lib/python3.12/site-packages

# Copy backend code
COPY backend/app ./app

# Copy frontend build from stage 1
COPY --from=frontend-builder /app/frontend/dist ./static

# Create temp directory for package downloads
RUN mkdir -p /tmp/pyshield && \
    mkdir -p /data && \
    chmod 777 /tmp/pyshield /data

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Expose port
EXPOSE 8000

# Health check using Python (minimal dependencies!)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3.12 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health', timeout=5)" || exit 1

# Run the application
CMD ["python3.12", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
