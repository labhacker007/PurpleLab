FROM python:3.12-slim

WORKDIR /app

# System dependencies: curl for healthcheck, libpq-dev + gcc for asyncpg/cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq-dev \
    gcc \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies (separate layer for caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create persistent data directories
RUN mkdir -p /app/data/chroma /app/data/mitre_attack /app/data/sigma_rules /app/data/log_schemas

# Make entrypoint executable
RUN chmod +x /app/backend/entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/app/backend/entrypoint.sh"]
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
