# Vietnam Credentials OpenCTI Connector

This connector extracts leaked credentials from Vietnam (country code: VN) stored in Elasticsearch and transforms them into STIX2 threat intelligence objects for OpenCTI.

## Features

- **Elasticsearch Integration**: Queries credentials with country_code="VN"
- **STIX2 Transformation**: Converts credentials into proper threat intelligence objects
- **OpenCTI Integration**: Sends intelligence via OpenCTI connector framework
- **Docker Support**: Containerized deployment with Docker Compose
- **Configurable**: Flexible configuration via YAML and environment variables

## STIX2 Objects Created

### Core Objects
- **Identity**: Connector identity and Vietnam location
- **Location**: Vietnam country object with ISO code "VN"
- **Malware**: Infostealer malware family objects
- **Indicator**: Credential leak patterns by channel
- **Observed-Data**: Credential leak observations grouped by timestamp

### Relationships
- **Malware** → **targets** → **Location** (Vietnam)
- **Indicator** → **indicates** → **Malware** (infostealer activity)
- **Observed-Data** → **related-to** → **Location** (Vietnam credential leaks)

## Configuration

### Environment Variables

#### OpenCTI Configuration
- `OPENCTI_URL`: OpenCTI platform URL
- `OPENCTI_TOKEN`: OpenCTI API token

#### Connector Configuration
- `CONNECTOR_ID`: Unique connector identifier
- `CONNECTOR_TYPE`: EXTERNAL_IMPORT
- `CONNECTOR_NAME`: Display name
- `CONNECTOR_SCOPE`: STIX object types
- `CONNECTOR_AUTO`: Auto-trigger (true/false)
- `CONNECTOR_CONFIDENCE_LEVEL`: Confidence score (0-100)
- `CONNECTOR_LOG_LEVEL`: Logging level (debug/info/warning/error)
- `CONNECTOR_INTERVAL`: Run interval in seconds

#### Elasticsearch Configuration
- `ELASTICSEARCH_URL`: Elasticsearch server URL
- `ELASTICSEARCH_USERNAME`: Authentication username
- `ELASTICSEARCH_PASSWORD`: Authentication password
- `ELASTICSEARCH_INDEX`: Index name (leaked-plaintext-passwords)
- `ELASTICSEARCH_VERIFY_SSL`: SSL verification (true/false)

#### Vietnam Credentials Configuration
- `VIETNAM_COUNTRY_CODE`: Country code filter (VN)
- `VIETNAM_BATCH_SIZE`: Processing batch size
- `VIETNAM_MAX_RESULTS`: Maximum results per query

## Installation

### Prerequisites
- OpenCTI platform running
- Elasticsearch with Vietnam credentials data
- Docker and Docker Compose

### Deployment

1. **Clone and Configure**
   ```bash
   cd /Users/MAC/Projects/EntroSpies/opencti_connector/vietnam_credentials_connector
   cp config.yml.example config.yml
   # Edit config.yml with your settings
   ```

2. **Environment Variables**
   ```bash
   # Create .env file
   cat > .env << EOF
   OPENCTI_TOKEN=your_opencti_token
   ELASTICSEARCH_URL=https://your-elasticsearch:9200
   ELASTICSEARCH_USERNAME=elastic
   ELASTICSEARCH_PASSWORD=your_password
   EOF
   ```

3. **Build and Run**
   ```bash
   docker-compose up -d
   ```

4. **Monitor Logs**
   ```bash
   docker-compose logs -f vietnam-credentials-connector
   ```

### Manual Installation

1. **Install Dependencies**
   ```bash
   pip3 install -r requirements.txt
   ```

2. **Configure**
   ```bash
   # Edit config.yml with your settings
   vim config.yml
   ```

3. **Run Connector**
   ```bash
   python3 src/vietnam_credentials_connector.py
   ```

## Usage

### OpenCTI Integration

1. **Register Connector**: The connector auto-registers with OpenCTI
2. **Trigger Processing**: OpenCTI triggers the connector based on interval
3. **View Intelligence**: Check OpenCTI for new Vietnam credential intelligence

### Query Examples

The connector queries Elasticsearch for Vietnam credentials:

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
  "sort": [
    {"timestamp": {"order": "desc"}}
  ]
}
```

## Troubleshooting

### Common Issues

1. **Connection Errors**
   - Check Elasticsearch URL and credentials
   - Verify SSL/TLS settings
   - Ensure network connectivity

2. **No Data Found**
   - Verify Vietnam credentials exist in Elasticsearch
   - Check country_code field contains "VN"
   - Review Elasticsearch index name

3. **OpenCTI Integration**
   - Verify OpenCTI token and URL
   - Check connector registration in OpenCTI
   - Review OpenCTI connector logs

### Debugging

Enable debug logging:
```yaml
connector:
  log_level: 'debug'
```

Or via environment variable:
```bash
CONNECTOR_LOG_LEVEL=debug
```

## Security Considerations

- Store credentials securely (use environment variables)
- Use SSL/TLS for Elasticsearch connections
- Implement proper network security
- Regular security updates for dependencies

## License

This connector is part of the EntroSpies threat intelligence project focused on defensive security purposes.