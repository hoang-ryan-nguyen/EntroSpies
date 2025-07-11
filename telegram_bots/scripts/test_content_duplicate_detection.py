#!/usr/bin/env python3
"""
Test script for content-based duplicate detection functionality.
Demonstrates how the enhanced duplicate detection works.
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from infostealer_bot import (
    normalize_message_text, 
    generate_content_hash, 
    find_content_duplicate,
    is_message_already_downloaded_enhanced
)

def test_normalize_message_text():
    """Test message text normalization."""
    print("Testing message text normalization...")
    
    test_cases = [
        ("[🔑 .pass:](https://t.me/c/1935880746/28) ```@LOGACTIVE``` 2025-01-11 14:30:00", 
         "pass: logactive"),
        ("**NEW LOGS** @admin_user https://example.com/file.zip", 
         "new logs"),
        ("Download: file.rar (Password: 123abc)", 
         "download: file.rar password: 123abc"),
        ("@channel_name 15:30:25 - New update available", 
         "- new update available"),
    ]
    
    for original, expected in test_cases:
        normalized = normalize_message_text(original)
        print(f"Original: {original}")
        print(f"Normalized: {normalized}")
        print(f"Expected: {expected}")
        print(f"Match: {normalized == expected}")
        print("-" * 50)

def test_content_hash():
    """Test content hash generation."""
    print("\nTesting content hash generation...")
    
    # Test identical content
    text1 = "[🔑 .pass:](https://t.me/c/1935880746/28) ```@LOGACTIVE```"
    text2 = "[🔑 .pass:](https://t.me/c/1935880746/28) ```@LOGACTIVE```"
    
    hash1 = generate_content_hash(text1, "MessageMediaDocument", 1024000)
    hash2 = generate_content_hash(text2, "MessageMediaDocument", 1024000)
    
    print(f"Text 1: {text1}")
    print(f"Text 2: {text2}")
    print(f"Hash 1: {hash1}")
    print(f"Hash 2: {hash2}")
    print(f"Hashes match: {hash1 == hash2}")
    print("-" * 50)
    
    # Test similar content with different timestamps
    text3 = "[🔑 .pass:](https://t.me/c/1935880746/28) ```@LOGACTIVE``` 2025-01-11"
    text4 = "[🔑 .pass:](https://t.me/c/1935880746/28) ```@LOGACTIVE``` 2025-01-12"
    
    hash3 = generate_content_hash(text3, "MessageMediaDocument", 1024000)
    hash4 = generate_content_hash(text4, "MessageMediaDocument", 1024000)
    
    print(f"Text 3: {text3}")
    print(f"Text 4: {text4}")
    print(f"Hash 3: {hash3}")
    print(f"Hash 4: {hash4}")
    print(f"Hashes match (should be True due to timestamp removal): {hash3 == hash4}")
    print("-" * 50)

def test_media_size_tolerance():
    """Test media size tolerance in duplicate detection."""
    print("\nTesting media size tolerance...")
    
    text = "Download file.rar"
    
    # Similar sizes (within 5% tolerance)
    size1 = 1000000  # 1MB
    size2 = 1040000  # 1.04MB (4% difference)
    size3 = 1200000  # 1.2MB (20% difference)
    
    hash1 = generate_content_hash(text, "MessageMediaDocument", size1)
    hash2 = generate_content_hash(text, "MessageMediaDocument", size2)
    hash3 = generate_content_hash(text, "MessageMediaDocument", size3)
    
    print(f"Size 1: {size1} bytes")
    print(f"Size 2: {size2} bytes ({abs(size2-size1)/size1*100:.1f}% difference)")
    print(f"Size 3: {size3} bytes ({abs(size3-size1)/size1*100:.1f}% difference)")
    print(f"Hash 1: {hash1}")
    print(f"Hash 2: {hash2}")
    print(f"Hash 3: {hash3}")
    print(f"Hash 1 == Hash 2: {hash1 == hash2}")
    print(f"Hash 1 == Hash 3: {hash1 == hash3}")

def demonstrate_duplicate_detection():
    """Demonstrate the duplicate detection logic."""
    print("\nDemonstrating duplicate detection logic...")
    
    # Sample channel info
    channel_info = {
        'title': '.boxed.pw',
        'id': 1935880746,
        'username': 'boxedpw'
    }
    
    # Test messages
    messages = [
        {
            'id': 12345,
            'text': '[🔑 .pass:] ```@LOGACTIVE``` Download: file1.rar',
            'media_type': 'MessageMediaDocument',
            'media_size': 1024000
        },
        {
            'id': 12346,
            'text': '[🔑 .pass:] ```@LOGACTIVE``` Download: file1.rar',
            'media_type': 'MessageMediaDocument', 
            'media_size': 1024000
        },  # Exact duplicate
        {
            'id': 12347,
            'text': '[🔑 .pass:] ```@LOGACTIVE``` 2025-01-11 Download: file1.rar',
            'media_type': 'MessageMediaDocument',
            'media_size': 1040000
        },  # Similar content, different timestamp, similar size
        {
            'id': 12348,
            'text': 'Different message content',
            'media_type': 'MessageMediaDocument',
            'media_size': 1024000
        }   # Different content
    ]
    
    for i, msg in enumerate(messages):
        print(f"\nMessage {i+1} (ID: {msg['id']}):")
        print(f"  Text: {msg['text']}")
        print(f"  Media: {msg['media_type']}, Size: {msg['media_size']}")
        print(f"  Normalized: {normalize_message_text(msg['text'])}")
        print(f"  Hash: {generate_content_hash(msg['text'], msg['media_type'], msg['media_size'])}")
        
        # Check for duplicates against previous messages
        for j in range(i):
            prev_msg = messages[j]
            prev_hash = generate_content_hash(prev_msg['text'], prev_msg['media_type'], prev_msg['media_size'])
            current_hash = generate_content_hash(msg['text'], msg['media_type'], msg['media_size'])
            
            if prev_hash == current_hash:
                print(f"  -> DUPLICATE of Message {j+1} (exact hash match)")
            elif normalize_message_text(msg['text']) == normalize_message_text(prev_msg['text']):
                # Check media similarity
                if (msg['media_type'] == prev_msg['media_type'] and 
                    abs(msg['media_size'] - prev_msg['media_size']) / max(msg['media_size'], prev_msg['media_size']) <= 0.05):
                    print(f"  -> DUPLICATE of Message {j+1} (normalized text + similar media)")

if __name__ == "__main__":
    print("Content-based Duplicate Detection Test")
    print("=" * 50)
    
    test_normalize_message_text()
    test_content_hash()
    test_media_size_tolerance()
    demonstrate_duplicate_detection()
    
    print("\nTest completed!")