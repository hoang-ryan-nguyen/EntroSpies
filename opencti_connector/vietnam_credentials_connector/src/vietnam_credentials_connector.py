#!/usr/bin/env python3

import os
import sys
import time
import yaml
import json
from datetime import datetime
from typing import List, Dict, Optional

# OpenCTI imports
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import Bundle, Identity, Location, Malware, Indicator, ObservedData, Relationship

# Elasticsearch imports
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, RequestError

class VietnamCredentialsConnector:
    def __init__(self):
        # Initialize configuration
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/../config.yml"
        config = yaml.load(open(config_file_path), Loader=yaml.FullLoader) if os.path.isfile(config_file_path) else {}
        
        # OpenCTI connector helper initialization
        self.helper = OpenCTIConnectorHelper(config)
        
        # Elasticsearch configuration
        self.elasticsearch_url = get_config_variable(
            "ELASTICSEARCH_URL", ["elasticsearch", "url"], config, default="https://localhost:9200"
        )
        self.elasticsearch_username = get_config_variable(
            "ELASTICSEARCH_USERNAME", ["elasticsearch", "username"], config, default="elastic"
        )
        self.elasticsearch_password = get_config_variable(
            "ELASTICSEARCH_PASSWORD", ["elasticsearch", "password"], config, default="changeme"
        )
        self.elasticsearch_index = get_config_variable(
            "ELASTICSEARCH_INDEX", ["elasticsearch", "index"], config, default="leaked-plaintext-passwords"
        )
        self.elasticsearch_verify_ssl = get_config_variable(
            "ELASTICSEARCH_VERIFY_SSL", ["elasticsearch", "verify_ssl"], config, default=False
        )
        
        # Vietnam credentials configuration
        self.country_code = get_config_variable(
            "VIETNAM_COUNTRY_CODE", ["vietnam_credentials", "country_code"], config, default="VN"
        )
        self.batch_size = get_config_variable(
            "VIETNAM_BATCH_SIZE", ["vietnam_credentials", "batch_size"], config, default=100
        )
        self.max_results = get_config_variable(
            "VIETNAM_MAX_RESULTS", ["vietnam_credentials", "max_results"], config, default=1000
        )
        
        # Initialize Elasticsearch client
        self.es_client = None
        self._connect_to_elasticsearch()
        
        # STIX2 identities
        self.author = Identity(
            name="EntroSpies Vietnam Credentials Connector",
            identity_class="system",
            description="Automated connector for Vietnam leaked credentials intelligence"
        )
        
        # Vietnam location object
        self.vietnam_location = Location(
            name="Vietnam",
            country="VN",
            region="Southeast Asia",
            description="Socialist Republic of Vietnam"
        )

    def _connect_to_elasticsearch(self) -> bool:
        """Connect to Elasticsearch server"""
        try:
            self.es_client = Elasticsearch(
                [self.elasticsearch_url],
                basic_auth=(self.elasticsearch_username, self.elasticsearch_password),
                verify_certs=self.elasticsearch_verify_ssl,
                ssl_show_warn=False,
                request_timeout=30
            )
            
            if self.es_client.ping():
                self.helper.log_info("Successfully connected to Elasticsearch")
                return True
            else:
                self.helper.log_error("Failed to ping Elasticsearch server")
                return False
                
        except ConnectionError as e:
            self.helper.log_error(f"Elasticsearch connection error: {e}")
            return False
        except Exception as e:
            self.helper.log_error(f"Unexpected error connecting to Elasticsearch: {e}")
            return False

    def _get_vietnam_credentials(self) -> List[Dict]:
        """Query Elasticsearch for Vietnam credentials"""
        try:
            # Query for Vietnam credentials
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"country_code": self.country_code}}
                        ]
                    }
                },
                "size": self.max_results,
                "sort": [
                    {"timestamp": {"order": "desc"}}
                ]
            }
            
            response = self.es_client.search(
                index=self.elasticsearch_index,
                body=query
            )
            
            credentials = []
            for hit in response['hits']['hits']:
                credentials.append(hit['_source'])
            
            self.helper.log_info(f"Retrieved {len(credentials)} Vietnam credentials from Elasticsearch")
            return credentials
            
        except Exception as e:
            self.helper.log_error(f"Error querying Vietnam credentials: {e}")
            return []

    def _create_malware_objects(self, credentials: List[Dict]) -> List[Malware]:
        """Create malware objects from credentials"""
        malware_objects = []
        
        # Create generic infostealer malware
        infostealer_malware = Malware(
            name="Infostealer",
            labels=["trojan", "stealer"],
            description="Information stealing malware targeting user credentials",
            is_family=True
        )
        malware_objects.append(infostealer_malware)
        
        return malware_objects

    def _create_indicators(self, credentials: List[Dict]) -> List[Indicator]:
        """Create indicators from credentials"""
        indicators = []
        
        # Group credentials by channel for better threat intelligence
        channels = set(cred.get('channel', 'unknown') for cred in credentials)
        
        for channel in channels:
            if channel == 'unknown':
                continue
                
            # Create indicator for credential leak pattern
            indicator = Indicator(
                pattern=f"[file:name = '*{channel}*' OR network-traffic:dst_ref.value = '*{channel}*']",
                labels=["malicious-activity"],
                description=f"Credentials leaked from {channel} affecting Vietnam users"
            )
            indicators.append(indicator)
        
        return indicators

    def _create_observed_data(self, credentials: List[Dict]) -> List[ObservedData]:
        """Create observed data objects from credentials"""
        observed_data_objects = []
        
        # Group credentials by timestamp for batching
        timestamp_groups = {}
        for cred in credentials:
            timestamp = cred.get('timestamp', datetime.now().isoformat())
            if timestamp not in timestamp_groups:
                timestamp_groups[timestamp] = []
            timestamp_groups[timestamp].append(cred)
        
        for timestamp, creds in timestamp_groups.items():
            # Create observed data for each timestamp group
            observed_data = ObservedData(
                first_observed=timestamp,
                last_observed=timestamp,
                number_observed=len(creds),
                objects={
                    "0": {
                        "type": "file",
                        "name": f"vietnam_credentials_{timestamp}",
                        "hashes": {
                            "MD5": "placeholder_hash"
                        }
                    }
                }
            )
            observed_data_objects.append(observed_data)
        
        return observed_data_objects

    def _create_relationships(self, malware_objects: List[Malware], indicators: List[Indicator], observed_data_objects: List[ObservedData]) -> List[Relationship]:
        """Create relationships between STIX objects"""
        relationships = []
        
        # Create relationships between malware and location
        for malware in malware_objects:
            relationship = Relationship(
                relationship_type="targets",
                source_ref=malware.id,
                target_ref=self.vietnam_location.id,
                description="Infostealer malware targeting Vietnam users"
            )
            relationships.append(relationship)
        
        # Create relationships between indicators and malware
        for indicator in indicators:
            for malware in malware_objects:
                relationship = Relationship(
                    relationship_type="indicates",
                    source_ref=indicator.id,
                    target_ref=malware.id,
                    description="Indicator suggests presence of infostealer malware"
                )
                relationships.append(relationship)
        
        # Create relationships between observed data and location
        for observed_data in observed_data_objects:
            relationship = Relationship(
                relationship_type="related-to",
                source_ref=observed_data.id,
                target_ref=self.vietnam_location.id,
                description="Observed credential leaks from Vietnam"
            )
            relationships.append(relationship)
        
        return relationships

    def _create_stix2_bundle(self, credentials: List[Dict]) -> Bundle:
        """Transform credentials into STIX2 bundle"""
        if not credentials:
            return None
        
        # Create STIX2 objects
        malware_objects = self._create_malware_objects(credentials)
        indicators = self._create_indicators(credentials)
        observed_data_objects = self._create_observed_data(credentials)
        relationships = self._create_relationships(malware_objects, indicators, observed_data_objects)
        
        # Combine all objects
        bundle_objects = [
            self.author,
            self.vietnam_location
        ] + malware_objects + indicators + observed_data_objects + relationships
        
        # Create and return bundle
        bundle = Bundle(objects=bundle_objects)
        return bundle

    def _process_message(self, data: Dict) -> str:
        """Process connector message"""
        try:
            self.helper.log_info("Starting Vietnam credentials processing")
            
            # Get Vietnam credentials from Elasticsearch
            credentials = self._get_vietnam_credentials()
            
            if not credentials:
                self.helper.log_info("No Vietnam credentials found")
                return "No Vietnam credentials found"
            
            # Create STIX2 bundle
            bundle = self._create_stix2_bundle(credentials)
            
            if bundle:
                # Send bundle to OpenCTI
                bundle_json = bundle.serialize(pretty=True)
                self.helper.log_info(f"Sending STIX2 bundle with {len(bundle.objects)} objects")
                
                bundles_sent = self.helper.send_stix2_bundle(bundle_json)
                
                self.helper.log_info(f"Successfully sent {bundles_sent} bundles to OpenCTI")
                return f"Processed {len(credentials)} Vietnam credentials"
            else:
                self.helper.log_error("Failed to create STIX2 bundle")
                return "Failed to create STIX2 bundle"
                
        except Exception as e:
            self.helper.log_error(f"Error processing Vietnam credentials: {e}")
            return f"Error: {str(e)}"

    def run(self):
        """Main connector loop"""
        self.helper.log_info("Starting Vietnam Credentials Connector")
        
        while True:
            try:
                # Listen for messages
                self.helper.listen(self._process_message)
                
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stopped")
                sys.exit(0)
            except Exception as e:
                self.helper.log_error(f"Connector error: {e}")
                time.sleep(60)  # Wait before retrying

if __name__ == "__main__":
    connector = VietnamCredentialsConnector()
    connector.run()