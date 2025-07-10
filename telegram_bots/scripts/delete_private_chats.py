#!/usr/bin/env python3
"""
Script to delete all private chats from Telegram account.
WARNING: This will permanently delete all private chat history.
"""

import asyncio
import sys
from telethon import TelegramClient
from telethon.tl.types import User
from telethon.tl.functions.messages import DeleteHistoryRequest
from telethon.errors import SessionPasswordNeededError

# Telegram API credentials from CLAUDE.md
API_ID = 24261682
API_HASH = 'c6c18b8be2b390849aa6ee4289de0270'

# Session file name
SESSION_NAME = 'entrospies_session'

async def delete_all_private_chats():
    """Delete all private chats from Telegram account."""
    
    # Create the client
    client = TelegramClient(SESSION_NAME, API_ID, API_HASH)
    
    try:
        print("🔄 Starting Telegram client...")
        await client.start()
        
        # Check if we're connected
        if not await client.is_user_authorized():
            print("❌ Not authorized. Please check your credentials.")
            return
            
        print("✅ Successfully connected to Telegram!")
        
        # Get current user info
        me = await client.get_me()
        print(f"📱 Logged in as: {me.first_name} {me.last_name or ''} (@{me.username or 'no username'})")
        print("-" * 50)
        
        # Get all dialogs (conversations)
        print("📋 Fetching all dialogs...")
        dialogs = await client.get_dialogs()
        
        # Find all private chats (users)
        private_chats = []
        for dialog in dialogs:
            entity = dialog.entity
            if isinstance(entity, User) and not entity.bot:
                private_chats.append({
                    'name': f"{entity.first_name} {entity.last_name or ''}".strip(),
                    'username': entity.username,
                    'id': entity.id,
                    'entity': entity
                })
        
        if not private_chats:
            print("✅ No private chats found to delete.")
            return
            
        print(f"⚠️  Found {len(private_chats)} private chats:")
        for i, chat in enumerate(private_chats, 1):
            username_str = f"@{chat['username']}" if chat['username'] else "No username"
            print(f"   {i:2d}. {chat['name']} ({username_str})")
        
        print("\n" + "="*50)
        print("⚠️  WARNING: This action will PERMANENTLY DELETE all chat history")
        print("⚠️  with these users. This action CANNOT be undone!")
        print("="*50)
        
        # Safety confirmation
        confirm = input("\nType 'DELETE ALL CHATS' to confirm deletion: ")
        if confirm != 'DELETE ALL CHATS':
            print("❌ Operation cancelled.")
            return
            
        print(f"\n🗑️  Deleting {len(private_chats)} private chats...")
        
        deleted_count = 0
        failed_count = 0
        
        for i, chat in enumerate(private_chats, 1):
            try:
                print(f"   Deleting chat {i}/{len(private_chats)}: {chat['name']}...")
                
                # Delete the chat history
                await client(DeleteHistoryRequest(
                    peer=chat['entity'],
                    max_id=0,
                    just_clear=False,
                    revoke=True
                ))
                
                deleted_count += 1
                print(f"   ✅ Deleted chat with {chat['name']}")
                
                # Small delay to avoid rate limiting
                await asyncio.sleep(0.5)
                
            except Exception as e:
                failed_count += 1
                print(f"   ❌ Failed to delete chat with {chat['name']}: {e}")
        
        print(f"\n📊 Summary:")
        print(f"   ✅ Successfully deleted: {deleted_count}")
        print(f"   ❌ Failed to delete: {failed_count}")
        print(f"   📱 Total processed: {len(private_chats)}")
        
        if deleted_count > 0:
            print(f"\n✅ Successfully deleted {deleted_count} private chats!")
        
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
    """Main function to run the async deletion."""
    try:
        asyncio.run(delete_all_private_chats())
    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled by user")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()