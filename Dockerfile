# ── Stage 1: dependency builder ───────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install deps into a prefix we can copy cleanly
COPY requirements.txt .
RUN pip install --upgrade pip --quiet \
 && pip install --prefix=/install --no-cache-dir -r requirements.txt

# ── Stage 2: runtime image ────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Non-root user for security
RUN addgroup --system cyberx \
 && adduser  --system --ingroup cyberx --no-create-home cyberx

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source (no venv, no __pycache__)
COPY app.py         .
COPY scanner/       ./scanner/
COPY templates/     ./templates/
COPY static/        ./static/

# Reports dir: owned by non-root user
RUN mkdir -p /app/reports && chown -R cyberx:cyberx /app

USER cyberx

EXPOSE 5000

# Health check – hits the /health route you already have
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

# Gunicorn: 4 workers, bind all interfaces
CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:5000", \
     "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", \
     "app:app"]
