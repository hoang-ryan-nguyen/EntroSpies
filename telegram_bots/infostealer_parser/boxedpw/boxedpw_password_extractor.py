#!/usr/bin/env python3
"""
BoxedPw Password Extractor Module for EntroSpies project.
Wrapper around the generic password extractor, optimized for boxed.pw channel.
"""

import re
import json
import logging
import sys
from typing import Optional, List, Dict, Union
from pathlib import Path

# Import the generic password extractor
try:
    from ..generic_password_extractor import GenericPasswordExtractor
except ImportError:
    # Try importing from project root
    current_dir = Path(__file__).parent
    sys.path.insert(0, str(current_dir.parent))
    from generic_password_extractor import GenericPasswordExtractor

class PasswordExtractor:
    """
    BoxedPw-specific password extractor wrapper around the generic extractor.
    Maintains backward compatibility while using the new JSON-based pattern system.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize the password extractor using the generic extractor optimized for boxed.pw.
        
        Args:
            logger: Optional logger instance for debugging
        """
        self.logger = logger or logging.getLogger(__name__)
        
        # Initialize the generic extractor with boxed.pw channel optimization
        self.generic_extractor = GenericPasswordExtractor(
            logger=self.logger,
            channel_name='boxed.pw'
        )
        
        # Maintain backward compatibility properties
        self.password_patterns = []
        self.false_positives = set()
        self.min_password_length = 3
        self.max_password_length = 50
        
        # Load properties from generic extractor for compatibility
        self._sync_properties()
        
        self.logger.info("BoxedPw password extractor initialized using generic patterns")
    
    def _sync_properties(self):
        """Sync properties from generic extractor for backward compatibility."""
        try:
            validation_rules = self.generic_extractor.validation_rules
            self.min_password_length = validation_rules.get('min_length', 3)
            self.max_password_length = validation_rules.get('max_length', 50)
            self.false_positives = set(validation_rules.get('false_positives', []))
            
            # Convert generic patterns to old format for compatibility
            self.password_patterns = []
            for pattern in self.generic_extractor.password_patterns:
                self.password_patterns.append({
                    'name': pattern['name'],
                    'pattern': pattern['pattern'],
                    'flags': pattern['compiled_flags']
                })
        except Exception as e:
            self.logger.warning(f"Could not sync properties from generic extractor: {e}")
    
    def extract_password(self, message_text: str) -> Optional[str]:
        """
        Extract password from message text using the generic extractor.
        
        Args:
            message_text: The message text to analyze
            
        Returns:
            Extracted password string or None if no password found
        """
        return self.generic_extractor.extract_password(message_text)
    
    def extract_passwords_batch(self, message_texts: List[str]) -> List[Optional[str]]:
        """
        Extract passwords from multiple message texts.
        
        Args:
            message_texts: List of message texts to analyze
            
        Returns:
            List of extracted passwords (None for messages without passwords)
        """
        return self.generic_extractor.extract_passwords_batch(message_texts)
    
    def extract_from_json_file(self, json_file_path: Union[str, Path]) -> Optional[str]:
        """
        Extract password from a JSON message file.
        
        Args:
            json_file_path: Path to the JSON file containing message data
            
        Returns:
            Extracted password string or None if no password found
        """
        return self.generic_extractor.extract_from_json_file(json_file_path)
    
    def extract_from_directory(self, directory_path: Union[str, Path]) -> Dict[str, Optional[str]]:
        """
        Extract passwords from all JSON files in a directory.
        
        Args:
            directory_path: Path to directory containing JSON message files
            
        Returns:
            Dictionary mapping file paths to extracted passwords
        """
        # Use generic extractor's directory processing
        results = {}
        directory = Path(directory_path)
        
        if not directory.exists():
            self.logger.error(f"Directory not found: {directory_path}")
            return results
        
        # Find all JSON files
        json_files = list(directory.glob("**/*message.json"))
        if not json_files:
            json_files = list(directory.glob("**/*.json"))
        
        self.logger.info(f"Processing {len(json_files)} JSON files in {directory_path}")
        
        for json_file in json_files:
            try:
                password = self.generic_extractor.extract_from_json_file(json_file)
                results[str(json_file)] = password
            except Exception as e:
                self.logger.error(f"Error processing {json_file}: {e}")
                results[str(json_file)] = None
        
        return results
    
    def _clean_password(self, password: str) -> str:
        """
        Clean and normalize extracted password (delegated to generic extractor).
        
        Args:
            password: Raw extracted password string
            
        Returns:
            Cleaned password string
        """
        return self.generic_extractor._clean_password(password)
    
    def _is_valid_password(self, password: str) -> bool:
        """
        Validate if extracted string is likely a real password (delegated to generic extractor).
        
        Args:
            password: Password string to validate
            
        Returns:
            True if password appears valid, False otherwise
        """
        return self.generic_extractor._is_valid_password(password)
    
    def get_pattern_statistics(self, message_texts: List[str]) -> Dict[str, int]:
        """
        Get statistics about which patterns are most successful.
        
        Args:
            message_texts: List of message texts to analyze
            
        Returns:
            Dictionary with pattern names and success counts
        """
        return self.generic_extractor.get_pattern_statistics(message_texts)
    
    def extract_and_save_password(self, message_text: str, message_file_path: Union[str, Path]) -> Optional[str]:
        """
        Extract password and save it to a .password file next to the message file.
        This method is designed for integration with infostealer_bot.py
        
        Args:
            message_text: The message text to analyze
            message_file_path: Path to the message JSON file
            
        Returns:
            Extracted password string or None if no password found
        """
        password = self.generic_extractor.extract_password(message_text)
        
        if password:
            # Create .password file next to the message file
            message_path = Path(message_file_path)
            password_file_path = message_path.with_suffix('.password')
            
            try:
                with open(password_file_path, 'w', encoding='utf-8') as f:
                    f.write(password)
                
                self.logger.info(f"Password saved to: {password_file_path}")
                return password
                
            except Exception as e:
                self.logger.error(f"Failed to save password file {password_file_path}: {e}")
                return password  # Still return the password even if file save failed
        
        return None
    
    @staticmethod
    def integrate_with_message_storage(message_data: Dict, message_text: str, logger: Optional[logging.Logger] = None) -> Dict:
        """
        Static method to integrate password extraction into message storage workflow.
        This can be called directly from infostealer_bot.py during message processing.
        
        Args:
            message_data: The message data dictionary being prepared for storage
            message_text: The message text to analyze for passwords
            logger: Optional logger instance
            
        Returns:
            Updated message_data dictionary with password information
        """
        extractor = PasswordExtractor(logger)
        password = extractor.extract_password(message_text)
        
        if password:
            message_data['extracted_password'] = password
            message_data['has_password'] = True
            if logger:
                logger.info(f"Password extracted for message {message_data.get('message_id', 'unknown')}: {password}")
        else:
            message_data['extracted_password'] = None
            message_data['has_password'] = False
        
        return message_data
    
    def get_extractor_info(self) -> Dict:
        """
        Get information about the extractor configuration.
        
        Returns:
            Dictionary with extractor configuration details
        """
        return self.generic_extractor.get_extractor_info()


def main():
    """
    Command-line interface for testing the BoxedPw password extractor.
    """
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description='Extract passwords from Telegram message files (BoxedPw)')
    parser.add_argument('input', help='JSON file or directory path')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('-s', '--stats', action='store_true', help='Show pattern statistics')
    parser.add_argument('-i', '--info', action='store_true', help='Show extractor configuration info')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')
    
    # Create extractor
    extractor = PasswordExtractor()
    
    if args.info:
        info = extractor.get_extractor_info()
        print("BoxedPw Password Extractor Configuration:")
        print("=" * 50)
        for key, value in info.items():
            print(f"{key}: {value}")
        print()
    
    input_path = Path(args.input)
    
    if input_path.is_file():
        # Single file
        password = extractor.extract_from_json_file(input_path)
        if password:
            print(f"Password found: {password}")
        else:
            print("No password found")
            sys.exit(1)
    
    elif input_path.is_dir():
        # Directory
        results = extractor.extract_from_directory(input_path)
        
        print(f"\nProcessed {len(results)} files:")
        passwords_found = 0
        
        for file_path, password in results.items():
            if password:
                print(f"  {file_path}: {password}")
                passwords_found += 1
            elif args.verbose:
                print(f"  {file_path}: No password")
        
        print(f"\nSummary: {passwords_found}/{len(results)} files contained passwords")
        
        if args.stats and results:
            # Collect all message texts for statistics
            message_texts = []
            for file_path in results.keys():
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if 'text' in data:
                            message_texts.append(data['text'])
                except Exception:
                    continue
            
            if message_texts:
                stats = extractor.get_pattern_statistics(message_texts)
                print(f"\nPattern Statistics:")
                for pattern_name, count in stats.items():
                    if count > 0:
                        print(f"  {pattern_name}: {count}")
    
    else:
        print(f"Error: {input_path} is neither a file nor a directory")
        sys.exit(1)


if __name__ == "__main__":
    main()