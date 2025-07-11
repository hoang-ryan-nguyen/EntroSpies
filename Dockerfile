# EntroSpies Telegram Bot Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies including archive tools
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    curl \
    wget \
    unrar-free \
    p7zip-full \
    unzip \
    tar \
    gzip \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 entrospies && \
    chown -R entrospies:entrospies /app

# Copy requirements first for better Docker layer caching
COPY requirements.txt /app/
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy project files for bot operation
COPY telegram_bots/ /app/telegram_bots/
COPY CLAUDE.md /app/
COPY README.md /app/

# Create necessary directories with proper structure and permissions
RUN mkdir -p /app/telegram_bots/download \
             /app/telegram_bots/logs \
             /app/telegram_bots/session \
             /app/telegram_bots/config \
             /app/telegram_bots/elasticsearch \
             /app/telegram_bots/infostealer_parser \
             /app/telegram_bots/scripts && \
    chown -R entrospies:entrospies /app

# Switch to non-root user
USER entrospies

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV TZ=UTC

# Health check - check if the bot process is responsive
HEALTHCHECK --interval=60s --timeout=30s --start-period=10s --retries=3 \
    CMD python3 -c "import os; import sys; sys.exit(0 if os.path.exists('/app/telegram_bots/logs/message_collector.log') else 1)" || exit 1

# Default command with proper session and config
CMD ["python3", "telegram_bots/infostealer_bot.py", \
     "-s", "session/qualgolab_telegram.session", \
     "-c", "config.json", \
     "--api-config", "api_config.json", \
     "-v"]