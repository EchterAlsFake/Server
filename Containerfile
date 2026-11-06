FROM docker.io/library/python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# The same committed resolution is used by development and deployment.
COPY --from=ghcr.io/astral-sh/uv:0.13.7 /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock /app/
RUN uv sync --locked --no-dev --no-install-project
ENV PATH="/app/.venv/bin:$PATH" PF_SERVER_DATA_DIR=/data

# Copy application source
COPY main.py /app/
COPY pf_server /app/pf_server
COPY templates /app/templates
COPY static /app/static
COPY migrations /app/migrations
COPY i18n /app/i18n

# Create unprivileged user and required directories
RUN useradd -u 1000 -U -d /app -s /bin/sh app && \
    mkdir -p /data /geoip && \
    chown -R app:app /app /data /geoip

USER app

EXPOSE 8000

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:8000", "main:app"]
