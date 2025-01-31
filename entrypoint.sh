#!/bin/bash
set -e

# Wait for Redis
while ! nc -z redis 6379; do
  echo "Waiting for Redis to be ready..."
  sleep 1
done

echo "Redis is ready. Starting Celery worker."
celery -A UrbanJungle worker --loglevel=info