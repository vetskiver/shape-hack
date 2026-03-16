FROM python:3.11-slim

WORKDIR /app

# System dependencies required by Playwright's Chromium inside the TEE.
# --no-install-recommends keeps the image lean.
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Chromium runtime libs
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
    libgbm1 libasound2 libpango-1.0-0 libcairo2 libatspi2.0-0 \
    # Font support (avoids Chromium rendering warnings)
    fonts-liberation \
    # SSL certs for TLS fingerprint verification
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright's bundled Chromium binary.
# This runs AFTER pip install so playwright is available.
# Only Chromium — skip Firefox/WebKit to keep image size down.
RUN playwright install chromium

# Copy app code
COPY app/ .

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
