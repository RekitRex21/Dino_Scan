# Skill Security Scanner

## Purpose
Audit skills from Clawhub or other sources for potential security risks before installation.

## What It Scans For
- **Prompt Injection Patterns**: Hidden commands, manipulation attempts
- **Dangerous Operations**: File deletions, system commands, network calls
- **Data Exfiltration**: External URLs, data sending patterns
- **Privilege Escalation**: Attempts to gain elevated permissions
- **Obfuscated Code**: Base64, hex encoding of commands
- **Suspicious Imports**: subprocess, os.system, eval(), exec()

## Usage
```bash
python skill_scanner.py --url "https://clawhub.com/skill/..."
# OR
python skill_scanner.py --file path/to/skill.py
```

## Output
- Risk score (1-10)
- List of findings with severity
- Recommendation (Safe / Review / Block)
