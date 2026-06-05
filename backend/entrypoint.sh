#!/bin/bash
set -e

echo "Running Alembic migrations..."
alembic upgrade heads

echo "Starting application..."
exec "$@"
