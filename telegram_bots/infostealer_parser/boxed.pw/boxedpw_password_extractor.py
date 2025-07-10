#!/usr/bin/env python3
"""
Password Extractor Module for EntroSpies project.
Extracts passwords from Telegram message text using various patterns commonly found in infostealer channels.
"""

import re
import json
import logging
from typing import Optional, List, Dict, Union
from pathlib import Path

class PasswordExtractor:
    """
    Extracts passwords from Telegram message text using multiple pattern matching techniques.
    Designed to handle various password formats found in infostealer channels.
    
    This class can be integrated into the main infostealer_bot.py for automatic password extraction.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize the password extractor with predefined patterns.
        
        Args:
            logger: Optional logger instance for debugging
        """
        self.logger = logger or logging.getLogger(__name__)
        
        # Define password extraction patterns (ordered by specificity)
        self.password_patterns = [
            # Pattern 1: [🔑 .pass:](link) ```password```
            {
                'name': 'emoji_pass_code_block',
                'pattern': r'🔑\s*\.?pass:?\]\([^)]*\)\s*```([^`]+)```',
                'flags': re.IGNORECASE | re.MULTILINE
            },
            
            # Pattern 2: [🔑 .pass:](link) password (without code blocks)
            {
                'name': 'emoji_pass_simple',
                'pattern': r'🔑\s*\.?pass:?\]\([^)]*\)\s*([^\n\s]+)',
                'flags': re.IGNORECASE | re.MULTILINE
            },
            
            # Pattern 3: Password: ```password```
            {
                'name': 'password_label_code_block',
                'pattern': r'password\s*:?\s*```([^`]+)```',
                'flags': re.IGNORECASE | re.MULTILINE
            },
            
            # Pattern 4: Pass: password
            {
                'name': 'pass_label_simple',
                'pattern': r'pass\s*:?\s*([^\n\s]+)',
                'flags': re.IGNORECASE | re.MULTILINE
            },
            
            # Pattern 5: .pass: password
            {
                'name': 'dot_pass_simple',
                'pattern': r'\.pass\s*:?\s*([^\n\s]+)',
                'flags': re.IGNORECASE | re.MULTILINE
            },
            
            # Pattern 6: 🔑 password (emoji followed by password, but not in markdown link format)
            {
                'name': 'emoji_direct',
                'pattern': r'🔑\s+(?![.\w]*:?\]\()([^\n\s]+)',
                'flags': re.IGNORECASE | re.MULTILINE
            },
            
            # Pattern 7: Code block containing only password-like string
            {
                'name': 'standalone_code_block',
                'pattern': r'```([A-Za-z0-9@#$%^&*!_+-]+)```',
                'flags': re.MULTILINE
            },
            
            # Pattern 8: Archive password indicators
            {
                'name': 'archive_password',
                'pattern': r'(?:archive|zip|rar)\s*password\s*:?\s*([^\n\s]+)',
                'flags': re.IGNORECASE | re.MULTILINE
            }
        ]
        
        # Common false positives to filter out
        self.false_positives = {
            'password', 'pass', '123456', 'admin', 'user', 'test', 'demo',
            'example', 'sample', 'default', 'none', 'null', 'empty'
        }
        
        # Minimum password length
        self.min_password_length = 3
        
        # Maximum password length (to avoid extracting entire text blocks)
        self.max_password_length = 50
    
    def extract_password(self, message_text: str) -> Optional[str]:
        """
        Extract password from message text using multiple patterns.
        
        Args:
            message_text: The message text to analyze
            
        Returns:
            Extracted password string or None if no password found
        """
        if not message_text or not isinstance(message_text, str):
            return None
        
        self.logger.debug(f"Analyzing message text for passwords: {message_text[:100]}...")
        
        # Try each pattern in order of specificity
        for pattern_info in self.password_patterns:
            pattern = pattern_info['pattern']
            flags = pattern_info['flags']
            name = pattern_info['name']
            
            try:
                matches = re.findall(pattern, message_text, flags)
                if matches:
                    # Get the first match and clean it
                    password = self._clean_password(matches[0])
                    if self._is_valid_password(password):
                        self.logger.info(f"Password extracted using pattern '{name}': {password}")
                        return password
                    else:
                        self.logger.debug(f"Pattern '{name}' matched but password failed validation: {password}")
            except Exception as e:
                self.logger.error(f"Error applying pattern '{name}': {e}")
        
        self.logger.debug("No valid password found in message text")
        return None
    
    def extract_passwords_batch(self, message_texts: List[str]) -> List[Optional[str]]:
        """
        Extract passwords from multiple message texts.
        
        Args:
            message_texts: List of message texts to analyze
            
        Returns:
            List of extracted passwords (None for messages without passwords)
        """
        return [self.extract_password(text) for text in message_texts]
    
    def extract_from_json_file(self, json_file_path: Union[str, Path]) -> Optional[str]:
        """
        Extract password from a JSON message file.
        
        Args:
            json_file_path: Path to the JSON file containing message data
            
        Returns:
            Extracted password string or None if no password found
        """
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                message_data = json.load(f)
            
            # Extract text from various possible fields
            message_text = message_data.get('text', '')
            if not message_text:
                # Try alternative field names
                message_text = message_data.get('message', '') or message_data.get('content', '')
            
            if message_text:
                password = self.extract_password(message_text)
                if password:
                    self.logger.info(f"Password extracted from {json_file_path}: {password}")
                return password
            else:
                self.logger.warning(f"No text content found in {json_file_path}")
                return None
                
        except FileNotFoundError:
            self.logger.error(f"JSON file not found: {json_file_path}")
            return None
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in file {json_file_path}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error reading JSON file {json_file_path}: {e}")
            return None
    
    def extract_from_directory(self, directory_path: Union[str, Path]) -> Dict[str, Optional[str]]:
        """
        Extract passwords from all JSON files in a directory.
        
        Args:
            directory_path: Path to directory containing JSON message files
            
        Returns:
            Dictionary mapping file paths to extracted passwords
        """
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
                password = self.extract_from_json_file(json_file)
                results[str(json_file)] = password
            except Exception as e:
                self.logger.error(f"Error processing {json_file}: {e}")
                results[str(json_file)] = None
        
        return results
    
    def _clean_password(self, password: str) -> str:
        """
        Clean and normalize extracted password.
        
        Args:
            password: Raw extracted password string
            
        Returns:
            Cleaned password string
        """
        if not password:
            return ""
        
        # Remove common unwanted characters and whitespace
        cleaned = password.strip()
        
        # Remove markdown formatting
        cleaned = re.sub(r'[*_`~]', '', cleaned)
        
        # Remove URLs if accidentally captured (but preserve Telegram links as they can be passwords)
        if 't.me/' not in cleaned:
            cleaned = re.sub(r'https?://[^\s]+', '', cleaned)
        
        # Remove newlines and extra whitespace
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        
        return cleaned
    
    def _is_valid_password(self, password: str) -> bool:
        """
        Validate if extracted string is likely a real password.
        
        Args:
            password: Password string to validate
            
        Returns:
            True if password appears valid, False otherwise
        """
        if not password:
            return False
        
        # Check length
        if len(password) < self.min_password_length or len(password) > self.max_password_length:
            return False
        
        # Check for false positives
        if password.lower() in self.false_positives:
            return False
        
        # Allow passwords that start with @ (common in Telegram)
        if password.startswith('@') and len(password) > 1:
            return True
        
        # Allow Telegram links as they are commonly used as passwords in infostealer channels
        if password.startswith(('http://', 'https://', 'www.')):
            if 't.me/' in password:
                return True
            # Reject other URLs
            return False
        
        # Check if it contains only whitespace or special characters
        if not re.search(r'[A-Za-z0-9]', password):
            return False
        
        # Password seems valid
        return True
    
    def get_pattern_statistics(self, message_texts: List[str]) -> Dict[str, int]:
        """
        Get statistics about which patterns are most successful.
        
        Args:
            message_texts: List of message texts to analyze
            
        Returns:
            Dictionary with pattern names and success counts
        """
        stats = {pattern['name']: 0 for pattern in self.password_patterns}
        
        for text in message_texts:
            for pattern_info in self.password_patterns:
                pattern = pattern_info['pattern']
                flags = pattern_info['flags']
                name = pattern_info['name']
                
                try:
                    matches = re.findall(pattern, text, flags)
                    if matches:
                        password = self._clean_password(matches[0])
                        if self._is_valid_password(password):
                            stats[name] += 1
                            break  # Only count first successful pattern per message
                except Exception:
                    continue
        
        return stats
    
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
        password = self.extract_password(message_text)
        
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


def main():
    """
    Command-line interface for testing the password extractor.
    """
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description='Extract passwords from Telegram message files')
    parser.add_argument('input', help='JSON file or directory path')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('-s', '--stats', action='store_true', help='Show pattern statistics')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')
    
    # Create extractor
    extractor = PasswordExtractor()
    
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