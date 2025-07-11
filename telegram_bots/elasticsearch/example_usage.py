#!/usr/bin/env python3
"""
Example usage of the generic InfostealerElasticsearchClient for different infostealer workflows.
This demonstrates how to use the client with different parsers and credential formats.
"""

import logging
from pathlib import Path
from infostealer_elasticsearch_client import InfostealerElasticsearchClient

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def example_boxedpw_usage():
    """Example usage for BoxedPw workflow."""
    print("\n🔧 BoxedPw Workflow Example")
    print("=" * 40)
    
    # Initialize client for BoxedPw
    client = InfostealerElasticsearchClient(
        parser_version='boxedpw-1.0',
        index_name='boxedpw-credentials'
    )
    
    # Example credentials from BoxedPw format
    credentials = [
        {
            'software': 'Chrome Default (137.0.7151.120)',
            'url': 'https://login.live.com/login.srf',
            'username': 'user@example.com',
            'password': 'example_password',
            'country_code': 'VN',
            'channel': '.boxed.pw',
            'channel_username': 'boxed_pw',
            'channel_id': 1234567890,
            'message_id': 12345
        }
    ]
    
    # Upload credentials (will be skipped since ES is disabled)
    result = client.upload_credentials(credentials)
    print(f"Upload result: {result}")
    
    # Show client status
    status = client.get_client_status()
    print(f"Client status: {status}")

def example_redline_usage():
    """Example usage for RedLine Stealer workflow."""
    print("\n🔧 RedLine Stealer Workflow Example")
    print("=" * 40)
    
    # Initialize client for RedLine
    client = InfostealerElasticsearchClient(
        parser_version='redline-2.0',
        index_name='redline-credentials'
    )
    
    # Example credentials from RedLine format (different structure)
    credentials = [
        {
            'software': 'Firefox',
            'url': 'https://facebook.com',
            'username': 'user123',
            'password': 'password123',
            'browser': 'Firefox',
            'profile': 'default',
            'host': 'facebook.com',
            'country_code': 'US',
            'channel': 'redline_channel',
            'ip_address': '192.168.1.100',
            'os': 'Windows 10'
        }
    ]
    
    # Upload credentials
    result = client.upload_credentials(credentials)
    print(f"Upload result: {result}")

def example_raccoon_usage():
    """Example usage for Raccoon Stealer workflow."""
    print("\n🔧 Raccoon Stealer Workflow Example")
    print("=" * 40)
    
    # Initialize client for Raccoon
    client = InfostealerElasticsearchClient(
        parser_version='raccoon-1.5',
        index_name='raccoon-credentials'
    )
    
    # Example credentials from Raccoon format
    credentials = [
        {
            'application': 'Discord',
            'username': 'gamer123',
            'password': 'secret123',
            'url': 'https://discord.com',
            'service': 'Discord',
            'domain': 'discord.com',
            'country_code': 'CA',
            'channel': 'raccoon_logs',
            'tags': ['gaming', 'social'],
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    ]
    
    # Upload credentials
    result = client.upload_credentials(credentials)
    print(f"Upload result: {result}")

def example_generic_usage():
    """Example usage for a generic/unknown infostealer workflow."""
    print("\n🔧 Generic Infostealer Workflow Example")
    print("=" * 40)
    
    # Initialize client for generic usage
    client = InfostealerElasticsearchClient(
        parser_version='generic-1.0'
    )
    
    # Example credentials with mixed/unknown format
    credentials = [
        {
            'host': 'mail.google.com',
            'port': 993,
            'protocol': 'IMAP',
            'username': 'user@gmail.com',
            'password': 'app_password',
            'email': 'user@gmail.com',
            'service': 'Gmail',
            'country_code': 'UK',
            'channel': 'unknown_stealer',
            'additional_data': {
                'encryption': 'SSL/TLS',
                'last_used': '2025-01-01'
            }
        }
    ]
    
    # Upload credentials
    result = client.upload_credentials(credentials)
    print(f"Upload result: {result}")

def example_custom_index_usage():
    """Example usage with custom index for specific use case."""
    print("\n🔧 Custom Index Example")
    print("=" * 40)
    
    # Initialize client with custom index for banking credentials
    client = InfostealerElasticsearchClient(
        parser_version='custom-banking-1.0',
        index_name='banking-credentials-high-priority'
    )
    
    # Example banking credentials (high priority)
    credentials = [
        {
            'software': 'Chrome Banking Extension',
            'url': 'https://banking.example.com',
            'username': 'account_holder',
            'password': 'banking_password',
            'domain': 'banking.example.com',
            'service': 'Online Banking',
            'country_code': 'US',
            'channel': 'banking_stealer',
            'tags': ['banking', 'financial', 'high-priority'],
            'notes': 'Contains banking credentials - high priority'
        }
    ]
    
    # Upload credentials
    result = client.upload_credentials(credentials)
    print(f"Upload result: {result}")

def main():
    """Run all examples."""
    print("🧪 InfostealerElasticsearchClient Usage Examples")
    print("=" * 60)
    
    print("This demonstrates how the generic Elasticsearch client can be used")
    print("with different infostealer workflows and credential formats.")
    print("\nNote: Elasticsearch is disabled by default, so uploads will be skipped.")
    print("Set ELASTICSEARCH_ENABLED=true in .env to enable actual uploads.")
    
    # Run examples
    example_boxedpw_usage()
    example_redline_usage()
    example_raccoon_usage()
    example_generic_usage()
    example_custom_index_usage()
    
    print("\n✅ All examples completed successfully!")
    print("\nTo use this in your own workflow:")
    print("1. Import: from elasticsearch.infostealer_elasticsearch_client import InfostealerElasticsearchClient")
    print("2. Initialize: client = InfostealerElasticsearchClient(parser_version='your-parser-1.0')")
    print("3. Upload: result = client.upload_credentials(your_credentials)")

if __name__ == "__main__":
    main()