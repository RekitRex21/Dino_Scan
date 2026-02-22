#!/usr/bin/env python3
"""
Credential Redaction Module
Detects and redacts secrets, API keys, tokens from text output
"""

import re
from typing import List, Tuple

# Patterns for common secret types
SECRET_PATTERNS = [
    # Generic API keys
    (r'(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)["\s:=]+["\']?([a-zA-Z0-9_\-\.]{16,})["\']?', 2),
    
    # AWS
    (r'AKIA[0-9A-Z]{16}', 0),
    
    # GitHub tokens
    (r'gh[pousr]_[A-Za-z0-9_]{36,}', 0),
    (r'github_pat_[A-Za-z0-9_]{22,}', 0),
    
    # OpenAI / Azure
    (r'sk-[A-Za-z0-9]{20,}', 0),
    (r'azure[a-z0-9_-]*\.azure\.net/[A-Za-z0-9\-\._~/?#&=]+', 0),
    
    # Anthropic / Claude
    (r'sk-ant-[A-Za-z0-9\-._]{20,}', 0),
    
    # Generic Bearer tokens
    (r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', 0),
    
    # JWT tokens
    (r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', 0),
    
    # Private keys
    (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 0),
    
    # Passwords in URLs
    (r'[a-zA-Z]+://[^:\s]+:[^@\s]+@', 1),  # redact password in URL
    
    # Environment variables
    (r'\$\{?[A-Z_][A-Z0-9_]*\}?=(["\']?)([a-zA-Z0-9_\-\.]{8,})\1', 3),
    
    # Slack tokens
    (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*', 0),
    
    # Telegram bot tokens
    (r'[0-9]{8,10}:[A-Za-z0-9_-]{35,}', 0),
    
    # Discord tokens
    (r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}', 0),
    
    # Database connection strings
    (r'(?i)(mongodb|postgres|mysql|redis)://[^:\s]+:[^@\s]+@', 1),
]

# Replacement patterns
SECRET_PLACEHOLDERS = {
    'api_key': '[REDACTED_API_KEY]',
    'token': '[REDACTED_TOKEN]',
    'password': '[REDACTED_PASSWORD]',
    'private_key': '[REDACTED_PRIVATE_KEY]',
    'aws_key': '[REDACTED_AWS_KEY]',
    'generic': '[REDACTED_SECRET]',
}

def redact_secrets(text: str, replacement: str = '[REDACTED_SECRET]') -> Tuple[str, List[str]]:
    """
    Redact all secrets from text.
    
    Returns: (redacted_text, list_of_redacted_types)
    """
    if not text:
        return text, []
    
    redacted_types = []
    result = text
    
    for pattern, group_idx in SECRET_PATTERNS:
        matches = re.finditer(pattern, result)
        for match in matches:
            if group_idx > 0 and len(match.groups()) >= group_idx:
                secret = match.group(group_idx)
                if secret and len(secret) > 4:
                    result = result.replace(secret, replacement)
                    redacted_types.append(pattern[:30])
    
    return result, list(set(redacted_types))

def redact_file(filepath: str, output_path: str = None) -> dict:
    """
    Redact secrets from a file.
    
    Returns: {
        'success': bool,
        'redacted_count': int,
        'types_found': list,
        'output_path': str
    }
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        redacted_content, types = redact_secrets(content)
        
        if output_path is None:
            output_path = filepath + '.redacted'
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(redacted_content)
        
        return {
            'success': True,
            'redacted_count': len(types),
            'types_found': list(set(types)),
            'output_path': output_path
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

def scan_for_secrets(text: str) -> dict:
    """
    Scan for secrets without redacting.
    
    Returns: {
        'has_secrets': bool,
        'findings': [{'type': str, 'match': str, 'location': int}]
    }
    """
    findings = []
    
    for pattern, group_idx in SECRET_PATTERNS:
        for match in re.finditer(pattern, text):
            secret_type = pattern[:40]
            if group_idx > 0 and len(match.groups()) >= group_idx:
                match_text = match.group(group_idx)
            else:
                match_text = match.group(0)[:20] + '...'
            
            findings.append({
                'type': secret_type,
                'match': match_text,
                'location': match.start()
            })
    
    return {
        'has_secrets': len(findings) > 0,
        'findings': findings
    }

if __name__ == '__main__':
    # Test
    test_text = '''
    API Key: sk-abc123defghijklmnopqrstuvwxyz
    GitHub Token: ghp_abcdefghijklmnopqrstuvwxyz1234567890
    AWS Key: AKIAIOSFODNN7EXAMPLE
    DB: mongodb://admin:password123@localhost:27017
    '''
    
    redacted, types = redact_secrets(test_text)
    print("Original:")
    print(test_text)
    print("\nRedacted:")
    print(redacted)
    print("\nTypes found:", types)
