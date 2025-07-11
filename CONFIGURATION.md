# EntroSpies Configuration Guide

## Overview
This document explains how to configure EntroSpies for secure operation using environment variables and configuration files.

## Security Improvements
The codebase has been updated to remove hard-coded credentials and make configuration more flexible and secure.

## Configuration Methods

### 1. Environment Variables (Recommended)
Create a `.env` file in the project root (copy from `.env.template`):

```bash
# Telegram API Credentials
TELEGRAM_API_ID=your_api_id_here
TELEGRAM_API_HASH=your_api_hash_here

# Logging Configuration
LOG_LEVEL=INFO
LOG_MAX_SIZE=10485760          # 10MB
LOG_BACKUP_COUNT=5
LOGS_DIR=logs

# Download Configuration
DEFAULT_MAX_FILE_SIZE=1073741824  # 1GB
MAX_CONCURRENT_DOWNLOADS=5
DOWNLOAD_RATE_LIMIT=0.1
DOWNLOAD_DIR=download

# Archive Processing
MAX_EXTRACTION_SIZE=104857600  # 100MB
EXTRACTION_TIMEOUT=300         # 5 minutes
MAX_PASSWORD_ATTEMPTS=10

# Session Configuration
SESSION_NAME=entrospies_session
SESSION_DIR=session

# Configuration Files
CONFIG_FILE=config.json
API_CONFIG_FILE=api_config.json
```

### 2. Configuration Files
Alternatively, you can use configuration files:

- `api_config.json`: API credentials (use template as guide)
- `config.json`: Channel configuration

### 3. Command Line Arguments
Most settings can be overridden via command line arguments when running the bot.

## API Credentials Setup

### Option 1: Environment Variables (Recommended)
```bash
export TELEGRAM_API_ID=your_api_id
export TELEGRAM_API_HASH=your_api_hash
```

### Option 2: Configuration File
Copy `api_config.json.template` to `api_config.json` and fill in your credentials:

```json
{
  "telegram_api": {
    "api_id": your_api_id,
    "api_hash": "your_api_hash"
  }
}
```

## Security Best Practices

1. **Never commit credentials to version control**
2. **Use environment variables for production**
3. **Keep api_config.json in .gitignore**
4. **Use template files for documentation**
5. **Regularly rotate API credentials**

## Migration from Hard-coded Values

If you were using hard-coded values previously:

1. Copy your API credentials from the old `api_config.json` to environment variables
2. Update your deployment scripts to use environment variables
3. Remove sensitive data from version control history if needed

## Environment Variables Reference

| Variable | Description | Default |
|----------|-------------|---------|
| `TELEGRAM_API_ID` | Telegram API ID | Required |
| `TELEGRAM_API_HASH` | Telegram API Hash | Required |
| `LOG_LEVEL` | Logging level | INFO |
| `LOG_MAX_SIZE` | Max log file size in bytes | 10485760 |
| `LOG_BACKUP_COUNT` | Number of log backup files | 5 |
| `LOGS_DIR` | Directory for log files | logs |
| `DEFAULT_MAX_FILE_SIZE` | Default max file size for downloads | 1073741824 |
| `MAX_CONCURRENT_DOWNLOADS` | Max concurrent downloads | 5 |
| `DOWNLOAD_RATE_LIMIT` | Delay between downloads | 0.1 |
| `DOWNLOAD_DIR` | Download directory | download |
| `MAX_EXTRACTION_SIZE` | Max size for archive extraction | 104857600 |
| `EXTRACTION_TIMEOUT` | Archive extraction timeout | 300 |
| `MAX_PASSWORD_ATTEMPTS` | Max password attempts for archives | 10 |
| `SESSION_NAME` | Session file name | entrospies_session |
| `SESSION_DIR` | Session directory | session |
| `CONFIG_FILE` | Configuration file path | config.json |
| `API_CONFIG_FILE` | API configuration file path | api_config.json |

## Troubleshooting

### Common Issues

1. **API credentials not found**: Ensure environment variables are set or api_config.json exists
2. **Template file errors**: Make sure to copy template files and replace placeholders
3. **Permission errors**: Check file permissions for session and log directories

### Debug Mode

Enable verbose logging to troubleshoot configuration issues:

```bash
python3 infostealer_bot.py -vvv
```

## Production Deployment

For production deployment:

1. Use environment variables for all sensitive configuration
2. Set up proper log rotation
3. Configure appropriate file size limits
4. Use secure session storage
5. Implement proper monitoring and alerting

## Configuration Validation

The application will validate configuration on startup and provide helpful error messages if required settings are missing or invalid.