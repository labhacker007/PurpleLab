#!/bin/bash
set -e

echo "Running Alembic migrations (heads)..."
alembic upgrade heads

echo "Starting application..."
exec "$@"
