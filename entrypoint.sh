#!/bin/sh
set -e

# If starting the main backend uvicorn server, wait for MySQL and run database migrations
if [ "$1" = "uvicorn" ]; then
    echo "[Entrypoint] Checking MySQL connectivity at ${MYSQL_HOST:-mysql}:${MYSQL_PORT:-3306}..."
    while ! nc -z "${MYSQL_HOST:-mysql}" "${MYSQL_PORT:-3306}"; do
        echo "[Entrypoint] Waiting for MySQL..."
        sleep 1
    done
    echo "[Entrypoint] MySQL is available. Running Alembic migrations..."
    alembic upgrade head
    echo "[Entrypoint] Migrations complete. Starting FastAPI server..."
fi

exec "$@"
