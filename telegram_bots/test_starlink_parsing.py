#!/usr/bin/env python3
"""
Test script for STARLINK credential parsing.
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
    
    # Path to STARLINK file
    starlink_file = Path("/Users/MAC/Projects/EntroSpies/telegram_bots/download/STARLINK[ULP] 11+ kk.txt")
    
    if not starlink_file.exists():
        print(f"STARLINK file not found: {starlink_file}")
        return
    
    print(f"Testing STARLINK credential parsing...")
    print(f"File: {starlink_file}")
    print(f"File size: {starlink_file.stat().st_size} bytes")
    print()
    
    # Parse the credentials file
    try:
        credentials = parser.parse_credentials_file(starlink_file)
        
        print(f"Parsing Results:")
        print(f"Total credentials found: {len(credentials)}")
        print()
        
        # Show first 10 credentials
        for i, cred in enumerate(credentials[:10]):
            print(f"Credential {i+1}:")
            print(f"  URL: {cred.get('url', 'N/A')}")
            print(f"  Username: {cred.get('username', 'N/A')}")
            print(f"  Password: {cred.get('password', 'N/A')}")
            print(f"  Format: {cred.get('format', 'N/A')}")
            print(f"  Software: {cred.get('software', 'N/A')}")
            print()
        
        if len(credentials) > 10:
            print(f"... and {len(credentials) - 10} more credentials")
        
    except Exception as e:
        print(f"Error parsing STARLINK file: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_starlink_parsing()