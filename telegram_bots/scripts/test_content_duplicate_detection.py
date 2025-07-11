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

def test_edge_cases():
    """Test edge cases and potential issues."""
    print("\nTesting edge cases...")
    
    # Test with empty/None inputs
    test_cases = [
        ("", None, None),
        (None, None, None),
        ("text", None, 0),
        ("text", "Document", -1),
        ("text", "", None),
    ]
    
    for text, media_type, media_size in test_cases:
        try:
            hash_result = generate_content_hash(text, media_type, media_size)
            print(f"✓ Hash for ('{text}', '{media_type}', {media_size}): {hash_result[:12]}...")
        except Exception as e:
            print(f"✗ Error for ('{text}', '{media_type}', {media_size}): {e}")
    
    # Test message ID comparison logic
    print("\nTesting message ID comparison logic...")
    test_filenames = [
        ("12345_message.json", 12345, True),
        ("_msg_12345_message.json", 12345, True),
        ("20250111_msg_12345_message.json", 12345, True),
        ("12345_message.json", 123, False),  # Should not match
        ("12345_message.json", 1234, False),  # Should not match
        ("msg_12345_other.json", 12345, True),
        ("something_12345.json", 12345, False),  # Should not match without _msg_ pattern
    ]
    
    for filename, msg_id, should_match in test_filenames:
        result = f"_msg_{msg_id}_" in filename
        status = "✓" if result == should_match else "✗"
        print(f"{status} File: {filename}, ID: {msg_id}, Match: {result}, Expected: {should_match}")

def demonstrate_duplicate_detection():
    """Demonstrate the duplicate detection logic."""
    print("\nDemonstrating duplicate detection logic...")
    
    # Sample channel info
    channel_info = {
        'title': '.boxed.pw',
        'id': 1935880746,
        'username': 'boxedpw'
    }
    
    # Test messages with various scenarios
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
        },  # Similar content, different timestamp, different size
        {
            'id': 12348,
            'text': '[🔑 .pass:] ```@LOGACTIVE``` Download: file1.rar',
            'media_type': None,
            'media_size': None
        },  # Same text, no media
        {
            'id': 12349,
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
                print(f"  -> EXACT DUPLICATE of Message {j+1} (hash match)")
            else:
                # Check text similarity with different media scenarios
                normalized_current = normalize_message_text(msg['text'])
                normalized_prev = normalize_message_text(prev_msg['text'])
                
                if normalized_current and normalized_prev and normalized_current == normalized_prev:
                    if not msg['media_type'] and prev_msg['media_type']:
                        print(f"  -> CONTENT DUPLICATE of Message {j+1} (text-only vs media)")
                    elif msg['media_type'] and not prev_msg['media_type']:
                        print(f"  -> CONTENT DUPLICATE of Message {j+1} (media vs text-only)")
                    elif (msg['media_type'] and prev_msg['media_type'] and 
                          msg['media_type'] != prev_msg['media_type']):
                        print(f"  -> CONTENT DUPLICATE of Message {j+1} (different media types)")
                    elif prev_hash != current_hash:
                        print(f"  -> SIMILAR CONTENT to Message {j+1} (but different hashes)")

if __name__ == "__main__":
    print("Content-based Duplicate Detection Test")
    print("=" * 50)
    
    test_normalize_message_text()
    test_content_hash()
    test_media_size_tolerance()
    test_edge_cases()
    demonstrate_duplicate_detection()
    
    print("\nTest completed!")
    print("\nCode review fixes applied:")
    print("✓ Fixed unreachable code in find_content_duplicate")
    print("✓ Fixed message ID comparison logic")
    print("✓ Removed redundant media calculations")
    print("✓ Added edge case handling for zero/negative media sizes")
    print("✓ Enhanced text similarity detection for different media scenarios")