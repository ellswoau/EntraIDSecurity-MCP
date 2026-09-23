# Entra ID MCP server — containerised.
# Runs as a non-root user. stdio (embedded MCP client) by default; override the
# CMD to run as a network daemon: --transport http|sse|streamable-http.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Create an unprivileged runtime user.
RUN groupadd -r entraid && useradd -r -g entraid -d /app entraid

# Install dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source.
COPY entraid_mcp ./entraid_mcp
# Normalise modes: a checkout created under a restrictive umask (e.g. 077)
# yields 0600 files that the unprivileged runtime user cannot read.
RUN chmod -R a+rX entraid_mcp
RUN python -m compileall -q entraid_mcp

USER entraid

# HTTP/SSE transports bind here.
EXPOSE 8000

# Default: stdio transport. Override CMD for a daemon:
#   docker run -p 8007:8000 entraid-mcp --transport http --port 8000
ENTRYPOINT ["python", "-m", "entraid_mcp"]
CMD []

# Healthcheck: succeeds only when the daemon is listening and /health returns
# HTTP 200 (matters for the http/sse daemon modes; harmless otherwise).
HEALTHCHECK --interval=30s --timeout=6s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=6)" || exit 1