FROM python:3.11-slim

# System deps for headless Firefox (Camoufox)
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl bzip2 libgtk-3-0 libdbus-glib-1-2 libxt6 libasound2 \
    libx11-xcb1 libxcomposite1 libxdamage1 libxrandr2 libgbm1 \
    libxfixes3 libxcursor1 libxi6 libxss1 libxtst6 \
    ca-certificates fonts-liberation xvfb procps \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download Camoufox browser binary at build time
# so the container starts instantly and never needs network at runtime
RUN python3 -m camoufox fetch

COPY main.py .

# PORT is injected by Render; fallback 10000 for local testing
ENV HOST=0.0.0.0 \
    PYTHONUNBUFFERED=1

EXPOSE 10000

CMD ["python3", "main.py"]
