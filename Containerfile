FROM docker.io/library/python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install runtime dependencies
COPY pyproject.toml /app/
RUN pip install --no-cache-dir \
    "cryptography" \
    "flask" \
    "flask-limiter" \
    "flask-migrate>=4.1.0" \
    "flask-sqlalchemy>=3.1.1" \
    "flask-talisman>=1.1.0" \
    "flask-wtf>=1.3.0" \
    "fpdf2>=2.8.7" \
    "gunicorn" \
    "httpx" \
    "markdown" \
    "maxminddb>=3.0.0" \
    "python-dotenv>=1.2.2" \
    "redis>=5.0.0" \
    "werkzeug"

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
