# Skill Security Scanner

## Purpose
Audit skills from Clawhub or other sources for potential security risks before installation.

## What It Scans For

### Skill Scanner
- **Prompt Injection Patterns**: Hidden commands, manipulation attempts
- **Dangerous Operations**: File deletions, system commands, network calls
- **Data Exfiltration**: External URLs, data sending patterns
- **Privilege Escalation**: Attempts to gain elevated permissions
- **Obfuscated Code**: Base64, hex encoding of commands
- **Suspicious Imports**: subprocess, os.system, eval(), exec()

### Credential Redaction (`redact_secrets.py`)
Redacts API keys, tokens, passwords from logs and output.
- AWS keys, GitHub tokens, OpenAI keys
- JWT tokens, private keys
- Database connection strings
- Environment variables with secrets
- Telegram/Discord/Slack tokens

### Memory Integrity (`memory_integrity.py`)
Detects and blocks prompt injection in memory writes.
- Ignore previous instructions
- Role override attempts
- Jailbreak attempts (DAN, etc.)
- System prompt extraction
- Code injection attempts
- Authority impersonation

## Usage

### Scan a Skill
```bash
python skill_scanner.py --url "https://clawhub.com/skill/..."
# OR
python skill_scanner.py --file path/to/skill.py
```

### Redact Secrets from Logs
```bash
python redact_secrets.py --file path/to/log.txt
# OR
python -c "from redact_secrets import redact_secrets; print(redact_secrets(your_text))"
```

### Check Memory Integrity
```bash
python memory_integrity.py --file path/to/memory.md
# OR
python -c "from memory_integrity import check_memory_integrity; print(check_memory_integrity(your_text))"
```

## Output
- Risk score (1-10)
- List of findings with severity
- Recommendation (Safe / Review / Block)
