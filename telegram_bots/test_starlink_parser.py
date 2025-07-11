#!/usr/bin/env python3
"""
Test script for Starlink credential parsing with the enhanced boxedpw parser.
"""

import sys
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from infostealer_parser.boxedpw.boxedpw_log_parser import BoxedPwLogParser

def test_starlink_parsing():
    """Test parsing the STARLINK credential file."""
    # Setup logging
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
    
    # Create parser
    parser = BoxedPwLogParser()
    
    # Test file path - use smaller sample
    starlink_file = Path("/Users/MAC/Projects/EntroSpies/telegram_bots/test_starlink_sample.txt")
    
    # Test both URL credential file and non-URL file
    non_url_file = Path("/Users/MAC/Projects/EntroSpies/telegram_bots/test_non_url_sample.txt")
    traditional_file = Path("/Users/MAC/Projects/EntroSpies/telegram_bots/test_traditional_sample.txt")
    
    if not starlink_file.exists():
        print(f"Error: Starlink file not found: {starlink_file}")
        return
    
    print(f"Testing Starlink file: {starlink_file}")
    print(f"File size: {starlink_file.stat().st_size} bytes")
    
    # Test if it's detected as credential dump file
    is_credential_dump = parser._is_credential_dump_file(starlink_file)
    print(f"Detected as credential dump: {is_credential_dump}")
    
    # Test URL credential pattern detection specifically
    is_url_pattern = parser._detect_url_credential_pattern(starlink_file)
    print(f"Detected URL credential pattern: {is_url_pattern}")
    
    # Test parsing as single log file
    result = parser.parse_single_log_file(starlink_file)
    
    print("\nParsing Results:")
    print("=" * 50)
    print(f"File Type: {result['file_type']}")
    print(f"File Size: {result['file_size']} bytes")
    print(f"Parsing Successful: {result['parsing_successful']}")
    print(f"Credentials Found: {result['credentials_count']}")
    
    # Show first few credentials
    if result['credentials'] and len(result['credentials']) > 0:
        print(f"\nFirst 5 credentials:")
        for i, cred in enumerate(result['credentials'][:5]):
            print(f"  {i+1}. URL: {cred.get('url', 'N/A')}")
            print(f"      Username: {cred.get('username', 'N/A')}")
            print(f"      Password: {cred.get('password', 'N/A')}")
            print(f"      Format: {cred.get('format', 'N/A')}")
            print()
    
    # Test non-URL credential file
    print(f"\n{'='*50}")
    print("Testing non-URL credential file...")
    print(f"{'='*50}")
    
    if non_url_file.exists():
        print(f"Testing non-URL file: {non_url_file}")
        
        # Test URL credential pattern detection
        is_url_pattern_non = parser._detect_url_credential_pattern(non_url_file)
        print(f"Detected URL credential pattern: {is_url_pattern_non}")
        
        # Test general credential dump detection
        is_credential_dump_non = parser._is_credential_dump_file(non_url_file)
        print(f"Detected as credential dump: {is_credential_dump_non}")
    
    # Test traditional credential file
    print(f"\n{'='*50}")
    print("Testing traditional credential file...")
    print(f"{'='*50}")
    
    if traditional_file.exists():
        print(f"Testing traditional file: {traditional_file}")
        
        # Test traditional credential pattern detection
        is_traditional_pattern = parser._detect_traditional_credential_pattern(traditional_file)
        print(f"Detected traditional credential pattern: {is_traditional_pattern}")
        
        # Test general credential dump detection
        is_credential_dump_trad = parser._is_credential_dump_file(traditional_file)
        print(f"Detected as credential dump: {is_credential_dump_trad}")
        
        # Test parsing traditional credentials
        result_trad = parser.parse_single_log_file(traditional_file)
        print(f"Parsing successful: {result_trad['parsing_successful']}")
        print(f"Credentials found: {result_trad['credentials_count']}")
        
        # Show first few credentials
        if result_trad['credentials'] and len(result_trad['credentials']) > 0:
            print(f"\nFirst 3 traditional credentials:")
            for i, cred in enumerate(result_trad['credentials'][:3]):
                print(f"  {i+1}. Software: {cred.get('software', 'N/A')}")
                print(f"      URL: {cred.get('url', 'N/A')}")
                print(f"      Username: {cred.get('username', 'N/A')}")
                print(f"      Password: {cred.get('password', 'N/A')}")
                print(f"      Format: {cred.get('format', 'N/A')}")
                print()

if __name__ == "__main__":
    test_starlink_parsing()