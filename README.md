# EntroSpies - Telegram Infostealer Intelligence Collector

[![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)](https://docker.com)
[![Python](https://img.shields.io/badge/Python-3.11+-green?logo=python)](https://python.org)
[![Telegram](https://img.shields.io/badge/Telegram-Bot-blue?logo=telegram)](https://telegram.org)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

EntroSpies is a threat intelligence collector focused on gathering leaked credentials from Telegram infostealer channels for **defensive security purposes**. The system monitors and downloads threat intelligence data from configured Telegram channels to support cybersecurity defense operations.

## 🚀 Features

### Core Capabilities
- **Real-time Message Listening** - Continuous monitoring for new messages with instant processing
- **Fast Multi-threaded Downloads** - Optimized telethon-based concurrent downloads (5 workers)
- **Smart Channel Management** - Automated channel discovery and parser-based filtering
- **Message-Attachment Pairing** - Guaranteed data integrity with linked message metadata
- **Comprehensive CLI** - Full-featured command-line interface with extensive options
- **Dual Operation Modes** - Real-time listening or batch processing of historical messages
- **Compliance Logging** - Comprehensive audit trails for security compliance

### Advanced Features
- **Docker Containerization** - Production-ready deployment with Docker Compose
- **Session Management** - Persistent Telegram sessions with secure storage
- **Parser Integration** - Modular parser system for different channel formats
- **Rate Limiting** - Telegram ToS compliant request throttling
- **File Size Controls** - Configurable download limits and pre-validation
- **Dry Run Mode** - Preview operations without actual downloads

### Intelligence Processing
- **Generic Password Patterns** - JSON-configurable password extraction patterns
- **Multi-Channel Support** - Optimized for BoxedPw, RedLine, Raccoon, Mars, Lumma, and generic formats
- **Credential Parsing** - Automated extraction of credentials from SOFT:/URL:/USER:/PASS: formats
- **Archive Processing** - Full support for RAR, ZIP, 7Z, TAR extraction with password handling
- **Elasticsearch Integration** - Optional upload to Elasticsearch with deduplication
- **Country Code Extraction** - Automatic geolocation tagging from folder paths

## 📋 Prerequisites

### Required
- **Python 3.11+**
- **Docker & Docker Compose** (for containerized deployment)
- **Telegram API Credentials** (api_id and api_hash)
- **Active Telegram Account** with channel access

### System Requirements
- **Memory**: Minimum 2GB RAM (4GB recommended)
- **Storage**: 10GB+ free space for downloads
- **Network**: Stable internet connection for Telegram API access

## 🛠️ Installation

### Method 1: Docker Deployment (Recommended)

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd EntroSpies
   ```

2. **Configure API credentials**
   ```bash
   cp telegram_bots/api_config.json.example telegram_bots/api_config.json
   # Edit api_config.json with your Telegram API credentials
   ```

3. **Setup environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Deploy with Docker**
   ```bash
   docker-compose up -d
   ```

### Method 2: Native Python Installation

1. **Setup virtual environment**
   ```bash
   python3 -m venv venv_entrospies
   source venv_entrospies/bin/activate
   ```

2. **Install dependencies**
   ```bash
   pip3 install -r requirements.txt
   ```

3. **Configure credentials**
   ```bash
   cd telegram_bots
   cp api_config.json.example api_config.json
   # Edit with your credentials
   ```

## ⚙️ Configuration

### API Configuration (`telegram_bots/api_config.json`)
```json
{
  "telegram_api": {
    "api_id": YOUR_API_ID,
    "api_hash": "YOUR_API_HASH"
  },
  "description": "Telegram API credentials for EntroSpies project",
  "note": "Keep this file secure and do not commit to version control"
}
```

### Channel Configuration
- Channel configuration is stored in `telegram_bots/config/channel_list.json`
- Channels are auto-discovered and processed based on available parsers
- Environment variables control behavior, channel list defines targets

### Environment Variables (`.env`)
```bash
# Telegram API Credentials
TELEGRAM_API_ID=your_api_id
TELEGRAM_API_HASH=your_api_hash

# Elasticsearch Configuration (optional)
ELASTICSEARCH_ENABLED=true
ELASTICSEARCH_HOST=your-elasticsearch-host
ELASTICSEARCH_PORT=9200
ELASTICSEARCH_USERNAME=elastic
ELASTICSEARCH_PASSWORD=your_password
ELASTICSEARCH_INDEX_NAME=infostealer-data-pool

# Logging Configuration
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

# Directory Configuration
DOWNLOAD_DIR=download
LOGS_DIR=logs
SESSION_DIR=session
```

## 🚀 Usage

### Docker Commands

```bash
# Start the bot
docker-compose up -d

# View logs
docker-compose logs -f entrospies-bot

# Stop the bot
docker-compose down

# Rebuild and restart
docker-compose up -d --build
```

### Native Python Commands

```bash
# Navigate to working directory
cd telegram_bots
source ../venv_entrospies/bin/activate

# Basic usage (real-time listening)
python3 infostealer_bot.py

# Download latest messages from each channel
python3 infostealer_bot.py -m 10

# Advanced usage examples
python3 infostealer_bot.py -s session/qualgolab_telegram.session -c config/channel_list.json -vvv -m 10

# Download with file size limits
python3 infostealer_bot.py --max-file-size 500MB -m 5

# Real-time listening with verbose logging
python3 infostealer_bot.py -vvv

# Dry run mode (preview only)
python3 infostealer_bot.py --dry-run -vvv

# Process specific channels
python3 infostealer_bot.py --channels "channel1,channel2"
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-s, --session` | Session file path | `entrospies_session` |
| `-m, --messages` | Messages per channel | `Real-time listening` |
| `-v, --verbose` | Logging verbosity | Warning level |
| `-c, --config` | Channel list file | `config/channel_list.json` |
| `--prevent-big-files` | Skip files >1GB | `False` |
| `--max-file-size` | Custom size limit | None |
| `--dry-run` | Preview mode | `False` |
| `--channels` | Specific channels | All |
| `--exclude` | Exclude channels | None |

## 📁 Project Structure

```
EntroSpies/
├── README.md                          # This file
├── DOCKER_DEPLOYMENT.md               # Docker deployment guide
├── docker-compose.yml                 # Docker deployment
├── Dockerfile                         # Container build
├── requirements.txt                   # Python dependencies
├── CLAUDE.md                          # Development guide
├── .env.template                      # Environment variables template
├── .dockerignore                      # Docker build exclusions
└── telegram_bots/                     # Main application
    ├── infostealer_bot.py             # Main bot implementation
    ├── telethon_download_manager.py   # Fast download engine
    ├── logger.py                      # Logging system
    ├── archive_decompressor.py        # Archive extraction engine
    ├── api_config.json                # API credentials
    ├── config/                        # Configuration files
    │   ├── channel_list.json          # Channel configuration and parser mappings
    │   ├── password_patterns.json     # Generic password patterns
    │   └── README.md                  # Pattern documentation
    ├── elasticsearch/                 # Elasticsearch integration
    │   ├── infostealer_elasticsearch_client.py  # Generic ES client
    │   └── example_usage.py           # Usage examples
    ├── download/                      # Downloaded content
    │   └── <channel>/<date>/          # Organized by channel/date
    ├── logs/                          # Application logs
    ├── session/                       # Telegram sessions
    ├── infostealer_parser/            # Parser modules
    │   ├── generic_password_extractor.py  # Generic password extractor
    │   └── boxedpw/                   # BoxedPw specific parsers
    │       ├── boxedpw_workflow.py    # Complete workflow
    │       ├── boxedpw_log_parser.py  # Log parsing
    │       └── boxedpw_password_extractor.py  # Password extraction
    └── scripts/                       # Utility scripts
```

## 📊 Monitoring & Logs

### Log Files
- **`logs/message_collector.log`** - Main application logs
- **`logs/compliance.log`** - Audit trail and compliance
- **`logs/errors.log`** - Error tracking and debugging

### Download Organization
```
download/
├── <channel_name>/
│   └── <date>/
│       ├── <timestamp>_msg_<id>_message.json     # Message metadata
│       ├── <timestamp>_msg_<id>_<filename>       # Downloaded file
│       └── <filename>_extracted/                 # Extracted archive contents
│           ├── [CC]<ip>[@username]/              # Country code folders
│           │   ├── All Passwords.txt             # Credential files
│           │   ├── Browser data/                 # Browser information
│           │   └── System.txt                    # System information
│           └── ...
```

### Docker Monitoring
```bash
# Container status
docker-compose ps

# Resource usage
docker stats entrospies-bot

# Follow logs
docker-compose logs -f --tail=100 entrospies-bot

# Health check
docker-compose exec entrospies-bot python3 -c "import os; print('Health OK' if os.path.exists('/app/telegram_bots/logs/message_collector.log') else 'Health FAIL')"
```

### Elasticsearch Integration
```bash
# Check Elasticsearch status
curl -X GET "elasticsearch-host:9200/_cluster/health"

# View indexed credentials
curl -X GET "elasticsearch-host:9200/infostealer-data-pool/_search?size=10"

# Test client connection
cd telegram_bots/elasticsearch
python3 infostealer_elasticsearch_client.py --test-connection
```

## 🔒 Security & Compliance

### Best Practices
- **API Credentials**: Store in separate `api_config.json`, never commit to version control
- **Rate Limiting**: Automatic compliance with Telegram ToS (0.1s delays)
- **Audit Logging**: Comprehensive compliance logs for security review
- **Container Security**: Non-root user execution in containers
- **Data Isolation**: Persistent volumes for data separation

### Telegram ToS Compliance
- Only joins channels for legitimate defensive security research
- Implements proper rate limiting between requests
- Maintains detailed audit logs for compliance verification
- Focuses solely on defensive threat intelligence collection
- Never uses collected data for offensive purposes

## 🐛 Troubleshooting

### Common Issues

**Authentication Errors**
```bash
# Check API credentials
cat telegram_bots/api_config.json

# Verify session file
ls -la telegram_bots/session/

# Test generic password extractor
cd telegram_bots/infostealer_parser
python3 generic_password_extractor.py --info --channel boxed.pw --text "test"
```

**Docker Issues**
```bash
# Check container logs
docker-compose logs entrospies-bot

# Rebuild container
docker-compose down
docker system prune -f
docker-compose up -d --build

# Check mounted volumes
docker-compose exec entrospies-bot ls -la /app/telegram_bots/
```

**Download Issues**
```bash
# Check permissions
ls -la telegram_bots/download/

# Monitor disk space
df -h

# Test archive extraction
python3 archive_decompressor.py --test-extraction
```

**Elasticsearch Issues**
```bash
# Test connection
cd telegram_bots/elasticsearch
python3 infostealer_elasticsearch_client.py --test-connection --parser-version boxedpw-1.0

# Check index health
curl -X GET "elasticsearch-host:9200/_cat/indices/infostealer-data-pool"
```

### Debug Mode
```bash
# Maximum verbosity
python3 infostealer_bot.py -vvv --dry-run

# Check specific channel
python3 infostealer_bot.py --channels "channel_name" -vvv

# Test password patterns
python3 generic_password_extractor.py --channel boxed.pw --text "[🔑 .pass:] ```@LOGACTIVE```"
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Follow the development guidelines in `CLAUDE.md`
4. Test your changes thoroughly
5. Submit a pull request

### Development Setup
```bash
# Clone and setup
git clone <repository-url>
cd EntroSpies
python3 -m venv venv_entrospies
source venv_entrospies/bin/activate
pip3 install -r requirements.txt
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

**EntroSpies is designed exclusively for defensive security purposes.** This tool is intended for:

- Threat intelligence collection and analysis
- Cybersecurity defense and monitoring
- Security research and education
- Compliance with organizational security policies

**NOT for:**
- Offensive security operations
- Unauthorized data collection
- Privacy violations
- Any malicious activities

Users are responsible for ensuring compliance with all applicable laws, regulations, and terms of service. Always obtain proper authorization before monitoring any channels or collecting data.

## 📞 Support

- **Documentation**: See `CLAUDE.md` for detailed development guidelines
- **Docker Guide**: See `DOCKER_DEPLOYMENT.md` for containerized deployment
- **Pattern Documentation**: See `telegram_bots/config/README.md` for password patterns
- **Issues**: Report bugs and feature requests via GitHub Issues
- **Security**: Report security vulnerabilities privately to maintainers

## 🆕 Recent Updates

### v2.0.0 - Enhanced Intelligence Processing
- **Generic Password Patterns**: JSON-configurable patterns for multiple infostealer formats
- **Elasticsearch Integration**: Optional upload with deduplication and flexible schema
- **Enhanced Docker**: Production-ready containerization with volume mounts
- **Archive Processing**: Full RAR/ZIP/7Z support with automated password extraction
- **Credential Parsing**: SOFT:/URL:/USER:/PASS: format support with country tagging
- **Multi-Channel Support**: Optimized for BoxedPw, RedLine, Raccoon, Mars, Lumma

### v1.0.0 - Core Platform
- **Telethon Integration**: Fast multi-threaded downloads
- **Session Management**: Persistent Telegram authentication
- **Compliance Logging**: Comprehensive audit trails
- **CLI Interface**: Full-featured command-line operations

---

**Built with ❤️ for the cybersecurity community**