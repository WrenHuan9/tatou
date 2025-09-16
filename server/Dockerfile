# Server image: minimal Flask + Gunicorn
FROM python:3.12-slim


ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates openssh-client \
 && rm -rf /var/lib/apt/lists/*

# Copy project description, to install dependencies
COPY pyproject.toml /app/pyproject.toml

# Install runtime dependencies
RUN pip install --no-cache-dir -e .

# Copy sources after dependencies installation
COPY src /app/server/src
COPY flag /app/flag
COPY entrypoint.sh /app/entrypoint.sh
RUN pip install --no-cache-dir -e .

# todo: temporarily health check for phase 1
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/healthz || exit 1

EXPOSE 5000

# Default command runs the web server
CMD ["./entrypoint.sh"]

