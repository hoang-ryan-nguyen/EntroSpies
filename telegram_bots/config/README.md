# Password Patterns Configuration

This directory contains the configuration files for the generic password extraction system used across all infostealer workflows in the EntroSpies project.

## Files

### password_patterns.json
This file contains the password extraction patterns that can be used by any infostealer workflow. The patterns are organized by channel type and include validation rules.

#### Structure:
- **patterns**: Array of pattern objects with regex patterns, flags, and metadata
- **validation_rules**: Rules for password validation (length, false positives, etc.)
- **channel_specific_configs**: Channel-specific optimizations and pattern preferences

#### Pattern Object Format:
```json
{
  "name": "pattern_name",
  "description": "Human-readable description",
  "pattern": "regex_pattern",
  "flags": ["IGNORECASE", "MULTILINE"],
  "priority": 1,
  "channels": ["boxed.pw", "redline", "generic"],
  "example": "Example message format"
}
```

## Usage

### Generic Password Extractor
The generic password extractor can be used directly:

```python
from infostealer_parser.generic_password_extractor import GenericPasswordExtractor

# Create extractor for specific channel
extractor = GenericPasswordExtractor(channel_name='boxed.pw')

# Extract password from message
password = extractor.extract_password(message_text)
```

### Channel-Specific Extractors
Each channel can have its own wrapper that uses the generic extractor:

```python
from infostealer_parser.boxedpw.boxedpw_password_extractor import PasswordExtractor

# BoxedPw extractor automatically uses boxed.pw channel optimization
extractor = PasswordExtractor()
password = extractor.extract_password(message_text)
```

## Supported Channels

### Currently Configured:
- **boxed.pw**: Optimized for BoxedPw channel formats
- **redline**: Optimized for RedLine Stealer formats
- **raccoon**: Optimized for Raccoon Stealer formats
- **mars**: Optimized for Mars Stealer formats
- **lumma**: Optimized for Lumma Stealer formats
- **generic**: Generic patterns for unknown channels

### Channel-Specific Optimizations:
Each channel has preferred patterns that are prioritized during extraction:

- **boxed.pw**: Focuses on emoji-based patterns with code blocks
- **redline**: Prioritizes stealer-specific formats and direct emoji patterns
- **raccoon**: Uses key emoji variants and stealer-specific formats
- **mars**: Emphasizes stealer formats and Telegram mention patterns
- **lumma**: Combines stealer formats with key emoji variants
- **generic**: Uses common password label patterns

## Pattern Types

### 1. Emoji-based Patterns
- `emoji_pass_code_block`: `[🔑 .pass:](link) ```password```
- `emoji_pass_simple`: `[🔑 .pass:](link) password`
- `emoji_direct`: `🔑 password`
- `key_emoji_variants`: `🔑🗝️🔐🔓 password`

### 2. Label-based Patterns
- `password_label_code_block`: `Password: ```password```
- `pass_label_simple`: `Pass: password`
- `dot_pass_simple`: `.pass: password`

### 3. Stealer-specific Patterns
- `stealer_specific_formats`: `[STEALER] password`
- `telegram_mention_password`: `@username password`
- `archive_password`: `Archive password: password`

### 4. Generic Patterns
- `standalone_code_block`: `\`\`\`password\`\`\``
- `colon_separated_password`: `: password`

## Adding New Patterns

To add new patterns:

1. Edit `password_patterns.json`
2. Add new pattern object with appropriate metadata
3. Update channel configurations if needed
4. Test with the generic extractor

Example:
```json
{
  "name": "new_pattern_name",
  "description": "Description of the new pattern",
  "pattern": "your_regex_pattern",
  "flags": ["IGNORECASE", "MULTILINE"],
  "priority": 10,
  "channels": ["channel1", "channel2"],
  "example": "Example message format"
}
```

## Adding New Channels

To add support for a new channel:

1. Add the channel name to relevant patterns' `channels` array
2. Add channel-specific configuration in `channel_specific_configs`
3. Create a channel-specific wrapper (optional)

Example channel config:
```json
"new_channel": {
  "preferred_patterns": ["pattern1", "pattern2"],
  "priority_boost": 1
}
```

## Testing

Test the password extraction system:

```bash
# Test generic extractor
python3 generic_password_extractor.py --channel boxed.pw --text "your_message"

# Test specific extractor
python3 boxedpw_password_extractor.py --info directory_path

# Show configuration
python3 generic_password_extractor.py --info --channel boxed.pw --text "test"
```

## Validation Rules

The validation rules help filter out false positives:

- **min_length**: Minimum password length (default: 3)
- **max_length**: Maximum password length (default: 50)
- **false_positives**: List of strings to reject as passwords
- **allow_telegram_links**: Allow t.me links as passwords
- **allow_at_symbols**: Allow passwords starting with @

## Performance

The pattern system is optimized for performance:
- Patterns are sorted by priority
- Channel-specific patterns are loaded first
- Regex compilation is cached
- Early termination on first match

## Maintenance

Regular maintenance tasks:
- Review pattern effectiveness using statistics
- Update false positive lists
- Add new patterns for emerging formats
- Optimize channel configurations based on usage data