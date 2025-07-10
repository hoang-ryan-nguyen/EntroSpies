#!/usr/bin/env python3
"""
Script to quit all joined Telegram channels and groups.
Uses Telethon library for EntroSpies project.
"""

import asyncio
import sys
from telethon import TelegramClient
from telethon.tl.types import Channel, Chat
from telethon.errors import SessionPasswordNeededError, ChatAdminRequiredError, UserNotParticipantError
from telethon.tl.functions.channels import LeaveChannelRequest
from telethon.tl.functions.messages import DeleteChatUserRequest

# Telegram API credentials from CLAUDE.md
API_ID = 24261682
API_HASH = 'c6c18b8be2b390849aa6ee4289de0270'
PHONE_NUMBER = '+84817662275'

# Session file name
SESSION_NAME = 'entrospies_session'

async def quit_all_channels():
    """Quit all joined channels and groups."""
    
    # Create the client
    client = TelegramClient(SESSION_NAME, API_ID, API_HASH)
    
    try:
        print("🔄 Starting Telegram client...")
        await client.start(phone=PHONE_NUMBER)
        
        # Check if we're connected
        if await client.is_user_authorized():
            print("✅ Successfully connected to Telegram!")
            
            # Get current user info
            me = await client.get_me()
            print(f"📱 Logged in as: {me.first_name} {me.last_name or ''} (@{me.username or 'no username'})")
            print("-" * 50)
            
            # Get all dialogs (conversations)
            print("📋 Fetching all joined channels and groups...")
            dialogs = await client.get_dialogs()
            
            channels_to_quit = []
            groups_to_quit = []
            
            for dialog in dialogs:
                entity = dialog.entity
                
                if isinstance(entity, Channel):
                    if entity.broadcast:
                        # It's a channel
                        channels_to_quit.append({
                            'entity': entity,
                            'title': entity.title,
                            'username': entity.username,
                            'id': entity.id,
                            'type': 'channel'
                        })
                    else:
                        # It's a supergroup
                        groups_to_quit.append({
                            'entity': entity,
                            'title': entity.title,
                            'username': entity.username,
                            'id': entity.id,
                            'type': 'supergroup'
                        })
                elif isinstance(entity, Chat):
                    # It's a regular group
                    groups_to_quit.append({
                        'entity': entity,
                        'title': entity.title,
                        'username': None,
                        'id': entity.id,
                        'type': 'group'
                    })
            
            total_to_quit = len(channels_to_quit) + len(groups_to_quit)
            
            if total_to_quit == 0:
                print("ℹ️  No channels or groups to quit.")
                return
            
            print(f"📊 Found {len(channels_to_quit)} channels and {len(groups_to_quit)} groups to quit")
            print()
            
            # Display what will be quit
            if channels_to_quit:
                print("📢 CHANNELS TO QUIT:")
                for i, channel in enumerate(channels_to_quit, 1):
                    username_str = f"@{channel['username']}" if channel['username'] else "No username"
                    print(f"   {i:2d}. {channel['title']} ({username_str})")
                print()
            
            if groups_to_quit:
                print("👥 GROUPS TO QUIT:")
                for i, group in enumerate(groups_to_quit, 1):
                    username_str = f"@{group['username']}" if group['username'] else "No username"
                    print(f"   {i:2d}. {group['title']} ({username_str})")
                print()
            
            # Safety confirmation
            print("⚠️  WARNING: This will quit ALL channels and groups!")
            print("This action cannot be undone easily.")
            print()
            
            confirmation = input("Are you sure you want to quit all channels and groups? (type 'YES' to confirm): ")
            
            if confirmation != 'YES':
                print("❌ Operation cancelled.")
                return
            
            print("\n🔄 Starting to quit channels and groups...")
            
            quit_count = 0
            failed_count = 0
            
            # Quit channels
            for channel_info in channels_to_quit:
                try:
                    print(f"🔄 Quitting channel: {channel_info['title']}")
                    await client(LeaveChannelRequest(channel_info['entity']))
                    print(f"✅ Successfully quit: {channel_info['title']}")
                    quit_count += 1
                    
                    # Small delay to avoid rate limiting
                    await asyncio.sleep(1)
                    
                except UserNotParticipantError:
                    print(f"ℹ️  Already not a member of: {channel_info['title']}")
                    quit_count += 1
                except ChatAdminRequiredError:
                    print(f"❌ Cannot quit (admin required): {channel_info['title']}")
                    failed_count += 1
                except Exception as e:
                    print(f"❌ Failed to quit {channel_info['title']}: {e}")
                    failed_count += 1
            
            # Quit groups
            for group_info in groups_to_quit:
                try:
                    print(f"🔄 Quitting group: {group_info['title']}")
                    
                    if group_info['type'] == 'supergroup':
                        # Use LeaveChannelRequest for supergroups
                        await client(LeaveChannelRequest(group_info['entity']))
                    else:
                        # Use DeleteChatUserRequest for regular groups
                        await client(DeleteChatUserRequest(
                            chat_id=group_info['id'],
                            user_id=me.id
                        ))
                    
                    print(f"✅ Successfully quit: {group_info['title']}")
                    quit_count += 1
                    
                    # Small delay to avoid rate limiting
                    await asyncio.sleep(1)
                    
                except UserNotParticipantError:
                    print(f"ℹ️  Already not a member of: {group_info['title']}")
                    quit_count += 1
                except ChatAdminRequiredError:
                    print(f"❌ Cannot quit (admin required): {group_info['title']}")
                    failed_count += 1
                except Exception as e:
                    print(f"❌ Failed to quit {group_info['title']}: {e}")
                    failed_count += 1
            
            print("\n" + "="*50)
            print(f"📊 SUMMARY:")
            print(f"   Total processed: {total_to_quit}")
            print(f"   Successfully quit: {quit_count}")
            print(f"   Failed to quit: {failed_count}")
            print("="*50)
            
            if quit_count > 0:
                print("✅ Channel/group quitting completed!")
            else:
                print("⚠️  No channels or groups were quit.")
                
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

async def list_channels_only():
    """List channels and groups without quitting (dry run)."""
    
    client = TelegramClient(SESSION_NAME, API_ID, API_HASH)
    
    try:
        print("🔄 Starting Telegram client (dry run mode)...")
        await client.start(phone=PHONE_NUMBER)
        
        if await client.is_user_authorized():
            print("✅ Successfully connected to Telegram!")
            
            dialogs = await client.get_dialogs()
            
            channels = []
            groups = []
            
            for dialog in dialogs:
                entity = dialog.entity
                
                if isinstance(entity, Channel):
                    if entity.broadcast:
                        channels.append(entity.title)
                    else:
                        groups.append(entity.title)
                elif isinstance(entity, Chat):
                    groups.append(entity.title)
            
            print(f"📊 Found {len(channels)} channels and {len(groups)} groups")
            
            if channels:
                print("\n📢 CHANNELS:")
                for i, channel in enumerate(channels, 1):
                    print(f"   {i:2d}. {channel}")
            
            if groups:
                print("\n👥 GROUPS:")
                for i, group in enumerate(groups, 1):
                    print(f"   {i:2d}. {group}")
                    
        else:
            print("❌ Not authorized.")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        
    finally:
        await client.disconnect()

def main():
    """Main function with options."""
    if len(sys.argv) > 1 and sys.argv[1] == '--dry-run':
        print("🔍 Running in dry-run mode (list only, no quitting)")
        asyncio.run(list_channels_only())
    else:
        print("🚨 QUIT ALL CHANNELS AND GROUPS MODE")
        print("Use --dry-run flag to see what would be quit without actually quitting")
        asyncio.run(quit_all_channels())

if __name__ == "__main__":
    main()