# EntroSpies Telegram Bot Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 entrospies && \
    chown -R entrospies:entrospies /app

# Copy requirements first for better Docker layer caching
COPY requirements.txt /app/
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy only necessary project files for bot operation
COPY telegram_bots/ /app/telegram_bots/
COPY CLAUDE.md /app/
COPY README.md /app/

# Create necessary directories with proper structure
RUN mkdir -p /app/telegram_bots/download \
             /app/telegram_bots/logs \
             /app/telegram_bots/session \
             /app/telegram_bots/infostealer_parser \
             /app/telegram_bots/scripts

# Set proper permissions
RUN chown -R entrospies:entrospies /app

# Switch to non-root user
USER entrospies

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV TZ=UTC

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import sys; sys.exit(0)" || exit 1

# Default command
CMD ["python3", "telegram_bots/infostealer_bot.py", "--help"]