#!/usr/bin/env python3
"""
Generic Elasticsearch Client for EntroSpies project.
Handles uploading parsed credentials from any infostealer channel to Elasticsearch.
"""

import os
import json
import logging
import hashlib
from datetime import datetime
from typing import List, Dict, Optional, Tuple

# Try to import Elasticsearch - make it optional
try:
    from elasticsearch import Elasticsearch
    from elasticsearch.exceptions import ConnectionError, RequestError
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    ELASTICSEARCH_AVAILABLE = False
    Elasticsearch = None
    ConnectionError = Exception
    RequestError = Exception


class InfostealerElasticsearchClient:
    """
    Generic Elasticsearch client for infostealer credential uploads.
    Handles connection, index management, and document uploads with deduplication.
    Supports any infostealer workflow by accepting configurable index names and parser versions.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None, index_name: Optional[str] = None, parser_version: Optional[str] = None):
        """
        Initialize the Elasticsearch client with configuration from environment variables.
        
        Args:
            logger: Optional logger instance
            index_name: Optional custom index name (overrides environment variable)
            parser_version: Optional parser version identifier (e.g., 'boxedpw-1.0', 'redline-1.0')
        """
        self.logger = logger or logging.getLogger(__name__)
        
        # Load configuration from environment variables
        self.enabled = os.getenv('ELASTICSEARCH_ENABLED', 'false').lower() == 'true'
        self.host = os.getenv('ELASTICSEARCH_HOST', 'localhost')
        self.port = int(os.getenv('ELASTICSEARCH_PORT', '9200'))
        self.username = os.getenv('ELASTICSEARCH_USERNAME', 'elastic')
        self.password = os.getenv('ELASTICSEARCH_PASSWORD', '')
        self.index_name = index_name or os.getenv('ELASTICSEARCH_INDEX_NAME', 'leaked-plaintext-passwords')
        self.parser_version = parser_version or 'generic-1.0'
        
        # Build URL
        self.elasticsearch_url = f"http://{self.host}:{self.port}"
        
        # Client and stats
        self.es_client = None
        self.connected = False
        self.index_exists = False
        
        # Upload statistics
        self.successful_uploads = 0
        self.failed_uploads = 0
        self.duplicate_skipped = 0
        
        self.logger.info(f"Infostealer Elasticsearch client initialized (enabled: {self.enabled})")
        if self.enabled:
            self.logger.info(f"ES URL: {self.elasticsearch_url}, Index: {self.index_name}, Parser: {self.parser_version}")
    
    def is_enabled(self) -> bool:
        """Check if Elasticsearch integration is enabled."""
        return self.enabled
    
    def connect(self) -> bool:
        """
        Connect to Elasticsearch server.
        
        Returns:
            True if connection successful, False otherwise
        """
        if not self.enabled:
            self.logger.info("Elasticsearch integration is disabled")
            return False
        
        if not self.password:
            self.logger.error("Elasticsearch password not configured")
            return False
        
        try:
            self.es_client = Elasticsearch(
                [self.elasticsearch_url],
                basic_auth=(self.username, self.password),
                verify_certs=False,
                ssl_show_warn=False,
                request_timeout=30
            )
            
            # Test connection
            if self.es_client.ping():
                self.connected = True
                self.logger.info(f"Successfully connected to Elasticsearch at {self.elasticsearch_url}")
                return True
            else:
                self.logger.error("Failed to ping Elasticsearch server")
                return False
                
        except ConnectionError as e:
            self.logger.error(f"Connection error: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error connecting to Elasticsearch: {e}")
            return False
    
    def setup_index(self) -> bool:
        """
        Setup the Elasticsearch index with proper mapping.
        
        Returns:
            True if index setup successful, False otherwise
        """
        if not self.connected:
            self.logger.error("Not connected to Elasticsearch")
            return False
        
        try:
            # Check if index exists
            if self.es_client.indices.exists(index=self.index_name):
                self.index_exists = True
                self.logger.info(f"Index '{self.index_name}' already exists. Using existing index.")
                return True
            
            # Create index with flexible mapping for any infostealer format
            mapping = {
                "mappings": {
                    "properties": {
                        # Core credential fields (common to all infostealers)
                        "software": {"type": "keyword"},
                        "url": {"type": "text"},
                        "username": {"type": "keyword"},
                        "password": {"type": "keyword"},
                        
                        # Metadata fields
                        "timestamp": {"type": "date"},
                        "source_file": {"type": "text"},
                        "channel": {"type": "keyword"},
                        "channel_username": {"type": "keyword"},
                        "channel_id": {"type": "long"},
                        "message_id": {"type": "long"},
                        "country_code": {"type": "keyword"},
                        "extraction_date": {"type": "date"},
                        "parser_version": {"type": "keyword"},
                        
                        # Additional flexible fields for different infostealer formats
                        "host": {"type": "text"},
                        "port": {"type": "integer"},
                        "protocol": {"type": "keyword"},
                        "browser": {"type": "keyword"},
                        "profile": {"type": "keyword"},
                        "application": {"type": "keyword"},
                        "service": {"type": "keyword"},
                        "domain": {"type": "keyword"},
                        "email": {"type": "keyword"},
                        "phone": {"type": "keyword"},
                        "notes": {"type": "text"},
                        "tags": {"type": "keyword"},
                        "os": {"type": "keyword"},
                        "ip_address": {"type": "ip"},
                        "mac_address": {"type": "keyword"},
                        "user_agent": {"type": "text"},
                        "file_hash": {"type": "keyword"},
                        "file_size": {"type": "long"},
                        
                        # Dynamic fields for unknown/additional data
                        "additional_data": {"type": "object", "enabled": False}
                    }
                }
            }
            
            self.es_client.indices.create(index=self.index_name, body=mapping)
            self.index_exists = True
            self.logger.info(f"Created new index '{self.index_name}' with flexible mapping")
            return True
            
        except RequestError as e:
            self.logger.error(f"Request error creating index: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error creating index: {e}")
            return False
    
    def generate_document_id(self, credential: Dict[str, str]) -> str:
        """
        Generate a unique document ID based on credential fields to prevent duplicates.
        Uses flexible field selection to work with any infostealer format.
        
        Args:
            credential: Credential dictionary
            
        Returns:
            SHA-256 hash as document ID
        """
        # Create a unique key using core fields that are most likely to be present
        # Priority order: software, url, username, password, host, domain, service, country_code
        unique_parts = []
        
        # Core fields for uniqueness
        core_fields = ['software', 'url', 'username', 'password', 'host', 'domain', 'service', 'country_code']
        
        for field in core_fields:
            value = credential.get(field, '')
            if value:
                unique_parts.append(f"{field}:{value}")
        
        # If no core fields found, use all available fields
        if not unique_parts:
            for key, value in credential.items():
                if key not in ['timestamp', 'extraction_date', 'source_file', 'message_id', 'parser_version']:
                    unique_parts.append(f"{key}:{value}")
        
        # Create unique string and generate hash
        unique_key = "|".join(unique_parts)
        document_id = hashlib.sha256(unique_key.encode('utf-8')).hexdigest()
        
        return document_id
    
    def check_document_exists(self, document_id: str) -> bool:
        """
        Check if a document with the given ID already exists in Elasticsearch.
        
        Args:
            document_id: Document ID to check
            
        Returns:
            True if document exists, False otherwise
        """
        try:
            response = self.es_client.exists(index=self.index_name, id=document_id)
            return response
        except Exception as e:
            self.logger.warning(f"Error checking document existence: {e}")
            return False
    
    def upload_credentials(self, credentials: List[Dict[str, str]]) -> Dict[str, int]:
        """
        Upload credentials to Elasticsearch with deduplication.
        
        Args:
            credentials: List of credential dictionaries
            
        Returns:
            Dictionary with upload statistics
        """
        if not self.enabled:
            self.logger.info("Elasticsearch integration is disabled, skipping upload")
            return {
                'uploaded': 0,
                'duplicates_skipped': 0,
                'errors': 0,
                'total_processed': 0
            }
        
        if not self.connected or not self.index_exists:
            self.logger.error("Elasticsearch not properly initialized")
            return {
                'uploaded': 0,
                'duplicates_skipped': 0,
                'errors': 1,
                'total_processed': 0
            }
        
        success_count = 0
        failure_count = 0
        duplicate_count = 0
        
        for credential in credentials:
            try:
                # Generate unique document ID
                document_id = self.generate_document_id(credential)
                
                # Check if document already exists
                if self.check_document_exists(document_id):
                    duplicate_count += 1
                    self.logger.debug(f"Skipping duplicate credential: {credential.get('username', 'unknown')}@{credential.get('url', 'unknown')} [{credential.get('country_code', 'unknown')}]")
                    continue
                
                # Add metadata
                credential_with_metadata = credential.copy()
                credential_with_metadata['extraction_date'] = datetime.now().isoformat()
                credential_with_metadata['parser_version'] = self.parser_version
                
                # Index the document with the generated ID
                response = self.es_client.index(
                    index=self.index_name,
                    id=document_id,
                    body=credential_with_metadata
                )
                
                if response.get('result') in ['created', 'updated']:
                    success_count += 1
                    self.logger.debug(f"Successfully indexed credential: {credential.get('username', 'unknown')}@{credential.get('url', 'unknown')} [{credential.get('country_code', 'unknown')}]")
                else:
                    failure_count += 1
                    self.logger.warning(f"Unexpected response: {response}")
                    
            except Exception as e:
                failure_count += 1
                self.logger.error(f"Error indexing credential: {e}")
        
        # Update statistics
        self.successful_uploads += success_count
        self.failed_uploads += failure_count
        self.duplicate_skipped += duplicate_count
        
        result = {
            'uploaded': success_count,
            'duplicates_skipped': duplicate_count,
            'errors': failure_count,
            'total_processed': len(credentials)
        }
        
        self.logger.info(f"Elasticsearch upload completed: {success_count} uploaded, {duplicate_count} duplicates skipped, {failure_count} errors")
        
        return result
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Get upload statistics.
        
        Returns:
            Dictionary with cumulative statistics
        """
        return {
            'total_successful_uploads': self.successful_uploads,
            'total_failed_uploads': self.failed_uploads,
            'total_duplicates_skipped': self.duplicate_skipped
        }
    
    def get_client_status(self) -> Dict[str, any]:
        """
        Get current client status.
        
        Returns:
            Dictionary with client status information
        """
        return {
            'enabled': self.enabled,
            'connected': self.connected,
            'index_exists': self.index_exists,
            'elasticsearch_url': self.elasticsearch_url,
            'index_name': self.index_name,
            'statistics': self.get_statistics()
        }
    
    def test_connection(self) -> bool:
        """
        Test the Elasticsearch connection and index setup.
        
        Returns:
            True if everything is working, False otherwise
        """
        if not self.enabled:
            return True  # Consider it successful if disabled
        
        if not self.connect():
            return False
        
        if not self.setup_index():
            return False
        
        self.logger.info("Elasticsearch connection and index setup successful")
        return True
    
    def close(self):
        """Close the Elasticsearch client connection."""
        if self.es_client:
            try:
                self.es_client.close()
                self.connected = False
                self.logger.info("Elasticsearch connection closed")
            except Exception as e:
                self.logger.warning(f"Error closing Elasticsearch connection: {e}")


def main():
    """
    Command-line interface for testing the Elasticsearch client.
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Test Infostealer Elasticsearch client')
    parser.add_argument('--test-connection', action='store_true', help='Test connection to Elasticsearch')
    parser.add_argument('--show-status', action='store_true', help='Show client status')
    parser.add_argument('--parser-version', default='test-1.0', help='Parser version identifier')
    parser.add_argument('--index-name', help='Custom index name')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')
    
    # Create client
    client = InfostealerElasticsearchClient(
        index_name=args.index_name,
        parser_version=args.parser_version
    )
    
    try:
        if args.test_connection:
            print("Testing Elasticsearch connection...")
            if client.test_connection():
                print("✅ Connection test successful")
            else:
                print("❌ Connection test failed")
        
        if args.show_status:
            status = client.get_client_status()
            print("\nElasticsearch Client Status:")
            print("=" * 40)
            print(f"Enabled: {status['enabled']}")
            print(f"Connected: {status['connected']}")
            print(f"Index Exists: {status['index_exists']}")
            print(f"URL: {status['elasticsearch_url']}")
            print(f"Index Name: {status['index_name']}")
            print(f"Statistics: {status['statistics']}")
        
        if not args.test_connection and not args.show_status:
            print("Use --test-connection or --show-status to test the client")
            print(f"Example: python3 {__file__} --test-connection --parser-version boxedpw-1.0")
    
    finally:
        client.close()


if __name__ == "__main__":
    main()