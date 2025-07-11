#!/usr/bin/env python3
"""
Test script for no credentials found logging functionality.
"""

import sys
import logging
import tempfile
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from infostealer_parser.boxedpw.boxedpw_log_parser import BoxedPwLogParser
from parsing_failure_logger import ParsingFailureLogger

def test_no_credentials_logging():
    """Test the no credentials found logging functionality."""
    
    # Setup logging
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
    
    # Create temporary directories and files for testing
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create test scenario 1: No credential files found
        print("="*60)
        print("Test 1: No credential files found")
        print("="*60)
        
        # Create some non-credential files
        (temp_path / "readme.txt").write_text("This is a readme file")
        (temp_path / "config.ini").write_text("[settings]\nkey=value")
        (temp_path / "random.dat").write_bytes(b"binary data")
        
        # Create fake message file
        message_file = temp_path / "message.json"
        message_data = {
            "channel_info": {"title": "test_channel", "username": "test", "id": 123},
            "message_id": 456
        }
        message_file.write_text(json.dumps(message_data))
        
        # Create parser with failure logger
        failure_logger = ParsingFailureLogger(logs_dir="logs")
        parser = BoxedPwLogParser(failure_logger=failure_logger)
        
        # Test parsing
        extracted_files = ["readme.txt", "config.ini", "random.dat"]
        result = parser.parse_all_credential_files(
            extract_dir=temp_path,
            extracted_files=extracted_files,
            message_file_path=str(message_file),
            channel_name="test_channel",
            message_id=456
        )
        
        print(f"Result: {result}")
        print(f"Credential files found: {result['credential_files_found']}")
        print(f"Total credentials: {result['total_credentials']}")
        
        # Test scenario 2: Credential files found but no credentials extracted
        print("\n" + "="*60)
        print("Test 2: Credential files found but no credentials extracted")
        print("="*60)
        
        # Create a file that looks like credentials but isn't valid
        fake_cred_file = temp_path / "fake_credentials.txt"
        fake_cred_file.write_text("SOFT: Some Browser\nURL: invalid format\nUSER: incomplete\n")
        
        extracted_files.append("fake_credentials.txt")
        
        result = parser.parse_all_credential_files(
            extract_dir=temp_path,
            extracted_files=extracted_files,
            message_file_path=str(message_file),
            channel_name="test_channel",
            message_id=456
        )
        
        print(f"Result: {result}")
        print(f"Credential files found: {result['credential_files_found']}")
        print(f"Total credentials: {result['total_credentials']}")
        
        # Test scenario 3: Test log file parsing with no credentials
        print("\n" + "="*60)
        print("Test 3: Log files found but no credentials extracted")
        print("="*60)
        
        # Create a log file that doesn't contain credentials
        log_file = temp_path / "browser.log"
        log_file.write_text("Some log entries\nNo credentials here\nJust regular log data")
        
        extracted_files.append("browser.log")
        
        result = parser.parse_extracted_logs(
            extract_dir=temp_path,
            extracted_files=extracted_files,
            message_file_path=str(message_file),
            channel_name="test_channel",
            message_id=456
        )
        
        print(f"Result: {result}")
        print(f"Log files processed: {result['log_files_processed']}")
        print(f"Credentials found: {result['credentials_found']}")
        
        print("\n" + "="*60)
        print("Check logs/failed_parsing_message.log for detailed failure logs")
        print("="*60)

if __name__ == "__main__":
    test_no_credentials_logging()