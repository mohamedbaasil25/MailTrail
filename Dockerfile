FROM python:3.11-slim

WORKDIR /app

# Upgrade pip itself - pip-audit flags old pip versions (this is the build
# tool, not a project dependency, so it isn't controlled by requirements.txt).
RUN pip install --no-cache-dir --upgrade pip

# Install dependencies first so this layer is cached across code-only changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application (test suite, dev requirements, .env, etc. are all
# excluded via .dockerignore - see that file for why)
COPY . .

# Ensure the reports directory exists and is writable by the app user
RUN mkdir -p reports

# Run as a non-root user - the image otherwise runs as root by default,
# which is unnecessary privilege for a process that only needs to listen
# on a port and write to ./reports.
RUN groupadd -r mailtrail && useradd -r -g mailtrail -d /app -s /sbin/nologin mailtrail \
    && chown -R mailtrail:mailtrail /app
USER mailtrail

# Cloud platforms (Render, Railway, Heroku-style) commonly inject a dynamic
# $PORT and expect the app to bind to it; 8000 is the local/docker-compose
# default when $PORT isn't set.
ENV PORT=8000
EXPOSE 8000

# Hits the readiness endpoint (checks DB connectivity, not just "is the
# process alive") so `docker ps` / orchestrators reflect real health.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python scripts/docker_healthcheck.py

# gunicorn with uvicorn worker(s) for a real production ASGI server -
# `uvicorn main:app` directly (the old CMD) is single-process and is
# uvicorn's own docs recommend gunicorn as the production process manager.
# WEB_CONCURRENCY lets an operator tune worker count per-instance (default
# 2: safe for small/free-tier instances given torch/transformers already
# use meaningful memory per worker).
CMD gunicorn main:app \
    --worker-class uvicorn.workers.UvicornWorker \
    --workers ${WEB_CONCURRENCY:-2} \
    --bind 0.0.0.0:${PORT:-8000} \
    --timeout 60 \
    --access-logfile - \
    --error-logfile -
