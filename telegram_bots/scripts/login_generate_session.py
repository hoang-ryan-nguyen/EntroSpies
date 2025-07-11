#!/usr/bin/env python3
"""
Telethon connection test script for EntroSpies project.
Tests connection to Telegram and lists all joined channels/groups.
"""

import asyncio
import sys
import json
import os
from datetime import datetime
from telethon import TelegramClient
from telethon.tl.types import Channel, Chat, User
from telethon.errors import SessionPasswordNeededError

# Telegram API credentials from CLAUDE.md
API_ID = 24261682
API_HASH = 'c6c18b8be2b390849aa6ee4289de0270'

# Session file name
SESSION_NAME = 'entrospies_session'

# Output JSON file
OUTPUT_FILE = 'joined_channels_with_parsers.json'

def get_parser_path(channel_title, channel_username):
    """
    Map channel to appropriate parser file path.
    Returns the python file path for the parser.
    """
    # Create a mapping based on channel title or username
    parser_mapping = {
        'boxedpw': 'infostealer_parser/parser_boxedpw.py',
        # Add more mappings as needed
        # 'channel_name': 'infostealer_parser/parser_channel_name.py',
    }
    
    # Check if channel title or username matches any parser
    if channel_title:
        title_lower = channel_title.lower()
        for key, parser_path in parser_mapping.items():
            if key in title_lower:
                return parser_path
    
    if channel_username:
        username_lower = channel_username.lower()
        for key, parser_path in parser_mapping.items():
            if key in username_lower:
                return parser_path
    
    # Default parser if no specific match found
    return 'infostealer_parser/parser_default.py'

async def test_connection_and_list_channels():
    """Test Telegram connection and list all joined channels/groups."""
    
    # Create the client
    client = TelegramClient(SESSION_NAME, API_ID, API_HASH)
    
    try:
        print("🔄 Starting Telegram client...")
        await client.start()
        
        # Check if we're connected
        if await client.is_user_authorized():
            print("✅ Successfully connected to Telegram!")
            
            # Get current user info
            me = await client.get_me()
            print(f"📱 Logged in as: {me.first_name} {me.last_name or ''} (@{me.username or 'no username'})")
            print(f"📞 Phone: {me.phone or 'N/A'}")
            print("-" * 50)
            
            # Get all dialogs (conversations)
            print("📋 Fetching all joined channels and groups...")
            dialogs = await client.get_dialogs()
            
            channels = []
            groups = []
            users = []
            
            for dialog in dialogs:
                entity = dialog.entity
                
                if isinstance(entity, Channel):
                    if entity.broadcast:
                        # It's a channel
                        channels.append({
                            'title': entity.title,
                            'username': entity.username,
                            'id': entity.id,
                            'participants': entity.participants_count,
                            'verified': entity.verified,
                            'restricted': entity.restricted,
                            'parser': get_parser_path(entity.title, entity.username)
                        })
                    else:
                        # It's a supergroup
                        groups.append({
                            'title': entity.title,
                            'username': entity.username,
                            'id': entity.id,
                            'participants': entity.participants_count,
                            'verified': entity.verified,
                            'restricted': entity.restricted,
                            'parser': get_parser_path(entity.title, entity.username)
                        })
                elif isinstance(entity, Chat):
                    # It's a regular group
                    groups.append({
                        'title': entity.title,
                        'username': None,
                        'id': entity.id,
                        'participants': entity.participants_count,
                        'verified': False,
                        'restricted': False,
                        'parser': get_parser_path(entity.title, None)
                    })
                elif isinstance(entity, User):
                    # It's a private chat
                    users.append({
                        'name': f"{entity.first_name} {entity.last_name or ''}".strip(),
                        'username': entity.username,
                        'id': entity.id,
                        'verified': entity.verified,
                        'bot': entity.bot
                    })
            
            # Display results
            print(f"📊 Summary:")
            print(f"   Channels: {len(channels)}")
            print()
            
            if channels:
                print("📢 CHANNELS:")
                for i, channel in enumerate(channels, 1):
                    username_str = f"@{channel['username']}" if channel['username'] else "No username"
                    verified_str = "✅" if channel['verified'] else ""
                    restricted_str = "🚫" if channel['restricted'] else ""
                    print(f"   {i:2d}. {channel['title']} ({username_str})")
                    print(f"       ID: {channel['id']}")
                    print(f"       Participants: {channel['participants'] or 'Unknown'}")
                    print(f"       Status: {verified_str} {restricted_str}")
                    print(f"       Link: https://t.me/{channel['username']}" if channel['username'] else "       No public link")
                    print()
            
            print(f"✅ Total joined channels: {len(channels)}")
            
            # Save to JSON file
            output_data = {
                'timestamp': datetime.now().isoformat(),
                'user_info': {
                    'name': f"{me.first_name} {me.last_name or ''}".strip(),
                    'username': me.username,
                    'phone': me.phone,
                    'id': me.id
                },
                'summary': {
                    'total_channels': len(channels)
                },
                'channels': channels
            }
            
            try:
                with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, ensure_ascii=False)
                print(f"💾 Results saved to {OUTPUT_FILE}")
            except Exception as e:
                print(f"❌ Error saving JSON file: {e}")
            
        else:
            print("❌ Not authorized. Please check your credentials.")
            
    except SessionPasswordNeededError:
        print("🔐 Two-factor authentication is enabled. Please enter your password:")
        password = input("Password: ")
        await client.sign_in(password=password)
        print("✅ Successfully authenticated with 2FA!")
        
    except Exception as e:
        print(f"❌ Error occurred: {e}")
        print(f"Error type: {type(e).__name__}")
        
    finally:
        await client.disconnect()
        print("🔌 Disconnected from Telegram")

def main():
    """Main function to run the async test."""
    try:
        asyncio.run(test_connection_and_list_channels())
    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled by user")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()