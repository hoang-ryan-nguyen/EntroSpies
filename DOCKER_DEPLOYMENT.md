# EntroSpies Docker Deployment Guide

## Overview
This guide covers deploying the EntroSpies Telegram Bot using Docker Compose. The containerized setup includes all necessary dependencies and proper volume mounts for persistent data.

## Prerequisites

### 1. Docker and Docker Compose
Ensure you have Docker and Docker Compose installed:
```bash
# Check Docker installation
docker --version
docker-compose --version
```

### 2. Required Files
Before deployment, ensure these files exist and are configured:

#### Configuration Files:
- `telegram_bots/api_config.json` - Telegram API credentials
- `.env` - Environment variables (contains all configuration)

#### Required Directories:
- `telegram_bots/download/` - For downloaded files (will be created if not exists)
- `telegram_bots/logs/` - For application logs (will be created if not exists)
- `telegram_bots/session/` - For Telegram session files (must exist with session file)

## Quick Start

### 1. Clone and Navigate
```bash
git clone <repository-url>
cd EntroSpies
```

### 2. Configure Environment
```bash
# Copy and edit environment variables
cp .env.template .env
nano .env
```

### 3. Configure API Credentials
```bash
# Copy and edit API configuration
cp telegram_bots/api_config.json.template telegram_bots/api_config.json
nano telegram_bots/api_config.json
```

### 4. Build and Deploy
```bash
# Build and start the container
docker-compose up -d --build

# Check container status
docker-compose ps

# View logs
docker-compose logs -f entrospies-bot
```

## Container Features

### System Dependencies
- **Python 3.11** - Latest Python runtime
- **Archive Tools**: unrar, p7zip-full, unzip, tar, gzip
- **System Tools**: gcc, g++, libffi-dev, libssl-dev, curl, wget

### Python Dependencies
- **telethon** - Telegram client library
- **requests** - HTTP requests
- **beautifulsoup4** - HTML parsing
- **elasticsearch** - Elasticsearch client
- **python-dotenv** - Environment variable loading
- **colorama** - Terminal colors
- **aiofiles** - Async file operations

### Security Features
- **Non-root user**: Runs as user `entrospies` (UID 1000)
- **Read-only mounts**: Code directories mounted as read-only
- **Resource limits**: Memory and CPU limits applied
- **Network isolation**: Dedicated Docker network

## Volume Mounts

### Persistent Data (Read-Write)
- `./telegram_bots/download` → `/app/telegram_bots/download`
- `./telegram_bots/logs` → `/app/telegram_bots/logs`
- `./telegram_bots/session` → `/app/telegram_bots/session`

### Configuration (Read-Only)
- `./telegram_bots/api_config.json` → `/app/telegram_bots/api_config.json`
- `./telegram_bots/config/` → `/app/telegram_bots/config/` (includes channel_list.json)
- `./telegram_bots/elasticsearch/` → `/app/telegram_bots/elasticsearch/`

### Code (Read-Only)
- `./telegram_bots/infostealer_parser/` → `/app/telegram_bots/infostealer_parser/`
- `./telegram_bots/scripts/` → `/app/telegram_bots/scripts/`
- Individual bot files (infostealer_bot.py, logger.py, etc.)

## Environment Variables

### Required Variables (from .env)
```bash
# Telegram API
TELEGRAM_API_ID=your_api_id
TELEGRAM_API_HASH=your_api_hash

# Elasticsearch (optional)
ELASTICSEARCH_ENABLED=true
ELASTICSEARCH_HOST=your_elasticsearch_host
ELASTICSEARCH_PORT=9200
ELASTICSEARCH_USERNAME=elastic
ELASTICSEARCH_PASSWORD=your_password
ELASTICSEARCH_INDEX_NAME=infostealer-data-pool

# Logging
LOG_LEVEL=INFO
LOG_MAX_SIZE=10485760
LOG_BACKUP_COUNT=5

# Download Configuration
DEFAULT_MAX_FILE_SIZE=1073741824
MAX_CONCURRENT_DOWNLOADS=5
DOWNLOAD_RATE_LIMIT=0.1

# Archive Processing
MAX_EXTRACTION_SIZE=104857600
EXTRACTION_TIMEOUT=300
MAX_PASSWORD_ATTEMPTS=10
```

## Management Commands

### Container Management
```bash
# Start container
docker-compose up -d

# Stop container
docker-compose down

# Restart container
docker-compose restart entrospies-bot

# Rebuild container
docker-compose up -d --build

# Remove container and volumes
docker-compose down -v
```

### Monitoring
```bash
# View real-time logs
docker-compose logs -f entrospies-bot

# View container status
docker-compose ps

# Check container health
docker-compose exec entrospies-bot python3 -c "import os; print('Health OK' if os.path.exists('/app/telegram_bots/logs/message_collector.log') else 'Health FAIL')"

# Access container shell
docker-compose exec entrospies-bot bash
```

### Data Management
```bash
# Backup session files
tar -czf session_backup.tar.gz telegram_bots/session/

# Backup downloaded data
tar -czf download_backup.tar.gz telegram_bots/download/

# View logs from host
tail -f telegram_bots/logs/message_collector.log
```

## Troubleshooting

### Common Issues

#### 1. Permission Errors
```bash
# Fix permissions for mounted directories
sudo chown -R 1000:1000 telegram_bots/download/
sudo chown -R 1000:1000 telegram_bots/logs/
sudo chown -R 1000:1000 telegram_bots/session/
```

#### 2. Container Won't Start
```bash
# Check logs for errors
docker-compose logs entrospies-bot

# Check configuration files
docker-compose exec entrospies-bot ls -la /app/telegram_bots/
```

#### 3. Network Issues
```bash
# Test Elasticsearch connection
docker-compose exec entrospies-bot python3 -c "
import os
print('ES Host:', os.getenv('ELASTICSEARCH_HOST'))
print('ES Port:', os.getenv('ELASTICSEARCH_PORT'))
"
```

#### 4. Build Issues
```bash
# Clean build
docker-compose down
docker system prune -f
docker-compose build --no-cache
docker-compose up -d
```

### Health Checks
The container includes health checks that verify:
- Log file creation (`message_collector.log`)
- Python process responsiveness
- File system accessibility

Health check runs every 60 seconds with 30-second timeout.

## Resource Usage

### Default Limits
- **Memory**: 2GB limit, 512MB reservation
- **CPU**: 1.0 CPU limit, 0.5 CPU reservation
- **Logs**: 100MB max size, 3 files maximum

### Monitoring Resource Usage
```bash
# View resource usage
docker stats entrospies-bot

# View detailed container info
docker inspect entrospies-bot
```

## Production Deployment

### Recommended Settings
1. **Enable log rotation**: Already configured (100MB, 3 files)
2. **Monitor disk usage**: Set up alerts for download directory
3. **Backup strategy**: Regular backups of session and download data
4. **Network security**: Use firewall rules for Elasticsearch access
5. **Update strategy**: Blue-green deployment for updates

### Security Considerations
- Store sensitive data in `.env` file with proper permissions (600)
- Use Docker secrets for production deployments
- Regularly update base images and dependencies
- Monitor container logs for security events
- Implement log aggregation for production monitoring

## Advanced Configuration

### Custom Bot Commands
To run custom bot commands:
```bash
# Access container and run custom command
docker-compose exec entrospies-bot python3 telegram_bots/infostealer_bot.py -s session/qualgolab_telegram.session --api-config api_config.json -c config/channel_list.json -m 10 --dry-run
```

### Elasticsearch Integration
If using Elasticsearch:
1. Ensure Elasticsearch is accessible from container
2. Configure proper authentication in `.env`
3. Test connection using provided scripts
4. Monitor index growth and performance

This deployment setup provides a robust, scalable, and secure environment for the EntroSpies Telegram Bot.