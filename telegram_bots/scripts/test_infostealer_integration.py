#!/usr/bin/env python3
"""
Test script for Infostealer integration with credential parsing and Elasticsearch upload.
"""

import sys
import os
import logging
from pathlib import Path

# Add the project root to the path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_imports():
    """Test that all imports work correctly."""
    try:
        # Test importing the workflow
        from telegram_bots.infostealer_parser.boxedpw.boxedpw_workflow import BoxedPwWorkflow
        print("✅ BoxedPwWorkflow imported successfully")
        
        # Test importing the log parser
        from telegram_bots.infostealer_parser.boxedpw.boxedpw_log_parser import BoxedPwLogParser
        print("✅ BoxedPwLogParser imported successfully")
        
        # Test importing the Elasticsearch client
        from telegram_bots.elasticsearch.infostealer_elasticsearch_client import InfostealerElasticsearchClient
        print("✅ InfostealerElasticsearchClient imported successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ Import error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_workflow_creation():
    """Test creating workflow instances."""
    try:
        from telegram_bots.infostealer_parser.boxedpw.boxedpw_workflow import BoxedPwWorkflow
        
        # Create workflow instance
        workflow = BoxedPwWorkflow()
        print("✅ BoxedPwWorkflow instantiated successfully")
        
        # Test that workflow has all required components
        assert hasattr(workflow, 'password_extractor'), "Workflow should have password_extractor"
        assert hasattr(workflow, 'archive_decompressor'), "Workflow should have archive_decompressor"
        assert hasattr(workflow, 'log_parser'), "Workflow should have log_parser"
        assert hasattr(workflow, 'elasticsearch_client'), "Workflow should have elasticsearch_client"
        print("✅ All workflow components initialized")
        
        # Test workflow status
        status = workflow.get_workflow_status()
        print(f"✅ Workflow status: {status}")
        
        return True
        
    except Exception as e:
        print(f"❌ Workflow creation error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_elasticsearch_client():
    """Test Elasticsearch client functionality."""
    try:
        from telegram_bots.elasticsearch.infostealer_elasticsearch_client import InfostealerElasticsearchClient
        
        # Create client instance with boxedpw parser version
        client = InfostealerElasticsearchClient(parser_version='boxedpw-1.0')
        print("✅ InfostealerElasticsearchClient instantiated successfully")
        
        # Test client status
        status = client.get_client_status()
        print(f"✅ Elasticsearch client status: {status}")
        
        # Test if enabled (should be false by default)
        assert not client.is_enabled(), "Client should be disabled by default"
        print("✅ Client correctly disabled by default")
        
        # Test different parser versions
        redline_client = InfostealerElasticsearchClient(parser_version='redline-1.0')
        assert redline_client.parser_version == 'redline-1.0', "Parser version should be configurable"
        print("✅ Parser version is configurable")
        
        return True
        
    except Exception as e:
        print(f"❌ Elasticsearch client error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_log_parser_credential_methods():
    """Test the new credential parsing methods in log parser."""
    try:
        from telegram_bots.infostealer_parser.boxedpw.boxedpw_log_parser import BoxedPwLogParser
        
        # Create parser instance
        parser = BoxedPwLogParser()
        print("✅ BoxedPwLogParser instantiated successfully")
        
        # Test that new methods exist
        assert hasattr(parser, 'find_credential_files'), "Parser should have find_credential_files method"
        assert hasattr(parser, 'parse_credentials_file'), "Parser should have parse_credentials_file method"
        assert hasattr(parser, 'parse_all_credential_files'), "Parser should have parse_all_credential_files method"
        assert hasattr(parser, 'extract_country_code'), "Parser should have extract_country_code method"
        print("✅ All new credential parsing methods exist")
        
        # Test country code extraction
        test_path = "/path/to/[AE]some_folder/file.txt"
        country_code = parser.extract_country_code(test_path)
        assert country_code == "AE", f"Expected 'AE', got '{country_code}'"
        print("✅ Country code extraction works")
        
        # Test with no country code
        test_path_no_code = "/path/to/some_folder/file.txt"
        country_code = parser.extract_country_code(test_path_no_code)
        assert country_code == "unknown", f"Expected 'unknown', got '{country_code}'"
        print("✅ Country code extraction handles missing codes")
        
        return True
        
    except Exception as e:
        print(f"❌ Log parser credential methods error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_credential_file_parsing():
    """Test parsing actual credential files if they exist."""
    try:
        from telegram_bots.infostealer_parser.boxedpw.boxedpw_log_parser import BoxedPwLogParser
        
        # Look for existing credential files
        download_dir = Path("telegram_bots/download/boxed.pw")
        if not download_dir.exists():
            print("⚠️  No download directory found, skipping credential file parsing test")
            return True
        
        # Find credential files
        credential_files = []
        for file_path in download_dir.rglob("All Passwords.txt"):
            credential_files.append(file_path)
            if len(credential_files) >= 1:  # Just test one file
                break
        
        if not credential_files:
            print("⚠️  No credential files found, skipping parsing test")
            return True
        
        print(f"📁 Found credential file: {credential_files[0]}")
        
        # Create parser and test parsing
        parser = BoxedPwLogParser()
        credentials = parser.parse_credentials_file(credential_files[0])
        
        print(f"✅ Parsed {len(credentials)} credentials from file")
        
        if credentials:
            # Check credential structure
            first_cred = credentials[0]
            expected_fields = ['software', 'url', 'username', 'password', 'country_code', 'channel']
            for field in expected_fields:
                assert field in first_cred, f"Missing field: {field}"
            print("✅ Credential structure is correct")
            
            # Show sample credential (without sensitive data)
            sample = {
                'software': first_cred.get('software', ''),
                'url': first_cred.get('url', '')[:50] + '...' if len(first_cred.get('url', '')) > 50 else first_cred.get('url', ''),
                'username': first_cred.get('username', '')[:10] + '...' if len(first_cred.get('username', '')) > 10 else first_cred.get('username', ''),
                'country_code': first_cred.get('country_code', ''),
                'channel': first_cred.get('channel', '')
            }
            print(f"✅ Sample credential: {sample}")
        
        return True
        
    except Exception as e:
        print(f"❌ Credential file parsing error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_generic_elasticsearch_usage():
    """Test that the Elasticsearch client can be used with different parsers."""
    try:
        from telegram_bots.elasticsearch.infostealer_elasticsearch_client import InfostealerElasticsearchClient
        
        # Test different parser configurations
        parsers = [
            ('boxedpw-1.0', 'boxedpw-credentials'),
            ('redline-1.0', 'redline-credentials'),
            ('raccoon-1.0', 'raccoon-credentials'),
            ('generic-1.0', 'infostealer-credentials')
        ]
        
        for parser_version, index_name in parsers:
            client = InfostealerElasticsearchClient(
                parser_version=parser_version,
                index_name=index_name
            )
            
            # Verify configuration
            assert client.parser_version == parser_version, f"Parser version mismatch: {client.parser_version} != {parser_version}"
            assert client.index_name == index_name, f"Index name mismatch: {client.index_name} != {index_name}"
            
            print(f"✅ {parser_version} client configured correctly")
        
        print("✅ Generic Elasticsearch client supports multiple parsers")
        return True
        
    except Exception as e:
        print(f"❌ Generic Elasticsearch usage error: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests."""
    print("🧪 Testing Infostealer Integration")
    print("=" * 50)
    
    # Setup logging
    logging.basicConfig(level=logging.WARNING)  # Reduce noise
    
    tests = [
        ("Import Tests", test_imports),
        ("Workflow Creation", test_workflow_creation),
        ("Elasticsearch Client", test_elasticsearch_client),
        ("Log Parser Credential Methods", test_log_parser_credential_methods),
        ("Credential File Parsing", test_credential_file_parsing),
        ("Generic Elasticsearch Usage", test_generic_elasticsearch_usage)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n🔍 Running {test_name}...")
        try:
            success = test_func()
            results.append((test_name, success))
            if success:
                print(f"✅ {test_name} passed")
            else:
                print(f"❌ {test_name} failed")
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Summary:")
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"  {status} {test_name}")
    
    print(f"\n🎯 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Integration is working correctly.")
        return True
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)