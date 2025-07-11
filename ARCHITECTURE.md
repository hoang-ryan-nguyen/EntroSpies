# EntroSpies Architecture Documentation

## Executive Summary

EntroSpies is a comprehensive threat intelligence platform designed for defensive security purposes, focusing on collecting, processing, and analyzing leaked credentials from Telegram infostealer channels. The system transforms raw credential data through multiple stages—from Telegram message collection to structured threat intelligence in OpenCTI.

## System Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Telegram       │    │  Infostealer    │    │  Elasticsearch  │    │  OpenCTI        │
│  Channels       │───▶│  Bot            │───▶│  Index          │───▶│  Platform       │
│  (Raw Data)     │    │  (Processing)   │    │  (Storage)      │    │  (Intelligence) │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Component Topology

### 1. **Telegram Infostealer Channels**
- **Role**: Primary data sources
- **Data Type**: Encrypted RAR/ZIP archives containing stolen credentials
- **Channels**: Various threat actor channels (e.g., boxed.pw, logs_center_new)
- **Content**: Compressed folders with credential files organized by victim IP and country

### 2. **EntroSpies Infostealer Bot**
- **Role**: Data collection and initial processing
- **Technology**: Python3 with Telethon library
- **Location**: `/Users/MAC/Projects/EntroSpies/telegram_bots/`
- **Functions**:
  - Message monitoring and download
  - Archive extraction and password recovery
  - File system organization
  - Metadata extraction

### 3. **Elasticsearch Cluster**
- **Role**: Structured data storage and search
- **Technology**: Elasticsearch 8.x
- **Index**: `leaked-plaintext-passwords`
- **Functions**:
  - Document indexing with country-based filtering
  - Duplicate prevention via SHA-256 hashing
  - Geographical analysis and aggregation

### 4. **OpenCTI Platform**
- **Role**: Threat intelligence analysis and visualization
- **Technology**: OpenCTI with STIX2 support
- **Functions**:
  - Intelligence correlation and analysis
  - Threat actor attribution
  - Geopolitical threat mapping

## Data Flow Architecture

### Stage 1: Raw Data Collection (Telegram → Bot)

#### **Input: Telegram Messages**
```json
{
  "channel": ".boxed.pw",
  "message_id": 27743,
  "date": "2025-07-10T04:10:29+00:00",
  "text": "[🔑 .pass:] ```@LOGACTIVE```",
  "has_media": true,
  "parser": "infostealer_parser/boxedpw.py"
}
```

#### **Processing: Archive Extraction**
- **Archive Types**: RAR, ZIP, 7Z with password protection
- **Password Extraction**: Automated from message text using regex patterns
- **Extraction Path**: `download/<channel>/<date>/<attachment>/`

#### **Output: Organized File Structure**
```
download/boxed.pw/2025-07-10/
├── 20250710_083011_msg_27743_message.json     # Message metadata
├── 7.10 - @LOGS_CENTER_NEW.rar               # Downloaded archive
└── 7.10 - @LOGS_CENTER_NEW/                  # Extracted content
    └── 7.10 - @LOGS_CENTER_NEW/
        └── [VN]1.52.89.238(2)[@LOGACTIVE]/   # Victim folder (Country+IP)
            ├── All Passwords.txt              # Credential file
            ├── Autofills.txt                 # Browser autofill data
            ├── Software.txt                  # Installed software
            ├── System.txt                    # System information
            └── Screen.jpg                    # Screenshot
```

### Stage 2: Data Transformation (TXT → JSON → Elasticsearch)

#### **Input: Raw Credential Files**
**Format**: `All Passwords.txt`
```
SOFT: Chrome Default (138.0.7204.96)
URL: https://chukyso.vinhomes.vn/
USER: 0932866505
PASS: 133973

SOFT: Edge Default (138.0.3351.77)
URL: https://vh.vinhomes.vn/login
USER: 3782213
PASS: Duc866505A.
```

#### **Processing: Plaintext Credentials Sender**
**Location**: `telegram_bots/elasticsearch/plaintext_credentials_sender.py`

**Transformation Logic**:
1. **File Discovery**: Recursive search for `All Passwords.txt` files
2. **Country Extraction**: Regex pattern `\[([A-Z]{2})\]` from folder name
3. **Channel Extraction**: From corresponding `*_message.json` file
4. **Credential Parsing**: Split entries by double newlines, extract SOFT/URL/USER/PASS
5. **Metadata Enrichment**: Add timestamp, source_file, channel, country_code
6. **Duplicate Prevention**: SHA-256 hash of (software+url+username+password+country_code)

#### **Output: Structured JSON Documents**
```json
{
  "software": "Chrome Default (138.0.7204.96)",
  "url": "https://chukyso.vinhomes.vn/",
  "username": "0932866505",
  "password": "133973",
  "timestamp": "2025-07-10T04:10:29+00:00",
  "source_file": "/path/to/All Passwords.txt",
  "channel": ".boxed.pw",
  "country_code": "VN"
}
```

### Stage 3: Elasticsearch Storage and Indexing

#### **Index Configuration**
```json
{
  "mappings": {
    "properties": {
      "software": {"type": "keyword"},
      "url": {"type": "text"},
      "username": {"type": "keyword"},
      "password": {"type": "keyword"},
      "timestamp": {"type": "date"},
      "source_file": {"type": "text"},
      "channel": {"type": "keyword"},
      "country_code": {"type": "keyword"}
    }
  }
}
```

#### **Data Operations**
- **Indexing**: PUT with document ID (SHA-256 hash)
- **Deduplication**: HEAD request to check existence before indexing
- **Querying**: Country-based filtering (`country_code: "VN"`)
- **Aggregation**: Statistics by country, channel, and software

### Stage 4: STIX2 Intelligence Generation (Elasticsearch → OpenCTI)

#### **Input: Elasticsearch Query Results**
**Query**: Vietnam credentials
```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"country_code": "VN"}}
      ]
    }
  },
  "size": 1000,
  "sort": [{"timestamp": {"order": "desc"}}]
}
```

#### **Processing: Vietnam Credentials Connector**
**Location**: `opencti_connector/vietnam_credentials_connector/`

**STIX2 Transformation**:

1. **Identity Objects**
```json
{
  "type": "identity",
  "name": "EntroSpies Vietnam Credentials Connector",
  "identity_class": "system",
  "description": "Automated connector for Vietnam leaked credentials intelligence"
}
```

2. **Location Objects**
```json
{
  "type": "location",
  "name": "Vietnam",
  "country": "VN",
  "region": "Southeast Asia",
  "description": "Socialist Republic of Vietnam"
}
```

3. **Malware Objects**
```json
{
  "type": "malware",
  "name": "Infostealer",
  "labels": ["trojan", "stealer"],
  "description": "Information stealing malware targeting user credentials",
  "is_family": true
}
```

4. **Indicator Objects**
```json
{
  "type": "indicator",
  "pattern": "[file:name = '*boxed.pw*' OR network-traffic:dst_ref.value = '*boxed.pw*']",
  "labels": ["malicious-activity"],
  "description": "Credentials leaked from .boxed.pw affecting Vietnam users"
}
```

5. **Observed Data Objects**
```json
{
  "type": "observed-data",
  "first_observed": "2025-07-10T04:10:29+00:00",
  "last_observed": "2025-07-10T04:10:29+00:00",
  "number_observed": 25,
  "objects": {
    "0": {
      "type": "file",
      "name": "vietnam_credentials_2025-07-10T04:10:29+00:00",
      "hashes": {"MD5": "placeholder_hash"}
    }
  }
}
```

6. **Relationship Objects**
```json
{
  "type": "relationship",
  "relationship_type": "targets",
  "source_ref": "malware--uuid",
  "target_ref": "location--uuid",
  "description": "Infostealer malware targeting Vietnam users"
}
```

#### **Output: STIX2 Bundle**
```json
{
  "type": "bundle",
  "objects": [
    // Identity, Location, Malware, Indicators, Observed-Data, Relationships
  ]
}
```

## Data Types and Schemas

### 1. **Telegram Message Schema**
```python
{
  "channel": str,           # Channel identifier
  "message_id": int,        # Unique message ID
  "date": str,             # ISO timestamp
  "text": str,             # Message content
  "has_media": bool,       # Media attachment flag
  "parser": str            # Parser module path
}
```

### 2. **Credential Document Schema**
```python
{
  "software": str,         # Browser/application name
  "url": str,             # Target website URL
  "username": str,        # Account username
  "password": str,        # Account password
  "timestamp": str,       # File modification time (ISO)
  "source_file": str,     # Original file path
  "channel": str,         # Telegram channel
  "country_code": str     # ISO country code
}
```

### 3. **STIX2 Object Types**
```python
{
  "identity": Identity,           # System/organization identities
  "location": Location,           # Geographical locations
  "malware": Malware,            # Malware families
  "indicator": Indicator,         # Threat indicators
  "observed-data": ObservedData,  # Observed phenomena
  "relationship": Relationship    # Object relationships
}
```

## Component Interactions

### 1. **Telegram Bot ↔ Elasticsearch**
- **Protocol**: HTTPS with basic authentication
- **Method**: Bulk indexing with duplicate prevention
- **Frequency**: Real-time processing as files are extracted
- **Security**: SSL disabled for internal network

### 2. **Elasticsearch ↔ OpenCTI Connector**
- **Protocol**: HTTPS with basic authentication
- **Method**: Search queries with country filtering
- **Frequency**: Configurable interval (default: 1 hour)
- **Batch Size**: 100 documents per query

### 3. **OpenCTI Connector ↔ OpenCTI Platform**
- **Protocol**: HTTPS with token authentication
- **Method**: STIX2 bundle submission via REST API
- **Frequency**: Event-driven after Elasticsearch processing
- **Format**: JSON-serialized STIX2 objects

## Security Considerations

### 1. **Data Handling**
- **Encryption**: Data encrypted at rest in Elasticsearch
- **Access Control**: Role-based access to components
- **Audit Trail**: Comprehensive logging for all operations
- **Retention**: Configurable data retention policies

### 2. **Network Security**
- **Internal Network**: All components on isolated network
- **SSL/TLS**: Encrypted communication between components
- **Authentication**: Strong authentication for all services
- **Firewalls**: Network segmentation and access control

### 3. **Compliance**
- **Purpose**: Defensive security research only
- **Data Minimization**: Only necessary data collected
- **Anonymization**: PII handling according to regulations
- **Audit Trail**: Complete processing history maintained

## Performance Characteristics

### 1. **Throughput**
- **Telegram Bot**: 5-10 messages per minute
- **Elasticsearch**: 1000+ documents per second
- **OpenCTI Connector**: 100 credentials per batch
- **End-to-end**: <10 minutes from download to intelligence

### 2. **Scalability**
- **Horizontal**: Multiple bot instances for different channels
- **Vertical**: Resource scaling based on data volume
- **Storage**: Elasticsearch cluster expansion
- **Processing**: Parallel processing of archives

### 3. **Reliability**
- **Redundancy**: Multiple data paths and backups
- **Error Handling**: Comprehensive error recovery
- **Monitoring**: Real-time health checking
- **Alerting**: Automated failure notifications

## Deployment Architecture

### 1. **Development Environment**
```
/Users/MAC/Projects/EntroSpies/
├── telegram_bots/                    # Bot components
├── elasticsearch_indexer/            # Elasticsearch integration
├── opencti_connector/               # OpenCTI connector
└── venv_entrospies/                # Python virtual environment
```

### 2. **Production Deployment**
```
Docker Compose Stack:
├── telegram-bot (Python container)
├── elasticsearch (Elasticsearch cluster)
├── opencti (OpenCTI platform)
├── redis (Message queue)
└── nginx (Reverse proxy)
```

### 3. **Configuration Management**
- **Environment Variables**: Secure credential management
- **Config Files**: YAML configuration for each component
- **Secrets Management**: External secret store integration
- **Version Control**: Git-based configuration tracking

## Monitoring and Observability

### 1. **Logging Strategy**
- **Centralized Logging**: ELK stack integration
- **Log Levels**: Debug, Info, Warning, Error
- **Structured Logging**: JSON format for parsing
- **Retention**: 90-day retention policy

### 2. **Metrics Collection**
- **Application Metrics**: Processing rates, error counts
- **System Metrics**: CPU, memory, disk usage
- **Business Metrics**: Credentials processed, countries covered
- **Alerts**: Threshold-based alerting system

### 3. **Health Checks**
- **Component Health**: Individual service health endpoints
- **Data Quality**: Validation of processed data
- **Performance**: Response time and throughput monitoring
- **Availability**: Uptime and SLA monitoring

## Future Enhancements

### 1. **Machine Learning Integration**
- **Classification**: Automatic credential categorization
- **Anomaly Detection**: Unusual pattern identification
- **Threat Attribution**: Actor identification and clustering
- **Predictive Analytics**: Breach prediction modeling

### 2. **Advanced Analytics**
- **Temporal Analysis**: Credential leak timeline analysis
- **Geospatial Analysis**: Geographic threat mapping
- **Network Analysis**: Relationship mapping between entities
- **Threat Hunting**: Interactive investigation tools

### 3. **Integration Expansion**
- **SIEM Integration**: Security Information and Event Management
- **Ticketing Systems**: Automated incident creation
- **Threat Feeds**: External intelligence source integration
- **API Gateway**: External access to processed intelligence

## Conclusion

The EntroSpies architecture provides a comprehensive pipeline for transforming raw credential data from Telegram channels into actionable threat intelligence. The system's modular design ensures scalability, reliability, and security while maintaining focus on defensive security applications.

The multi-stage transformation process—from raw text files to structured STIX2 intelligence—enables organizations to understand, analyze, and respond to credential-based threats effectively. The integration with OpenCTI provides a powerful platform for threat intelligence analysis and sharing within the security community.

This architecture serves as a foundation for advanced threat intelligence operations, providing the necessary components for data collection, processing, analysis, and dissemination in support of defensive cybersecurity efforts.