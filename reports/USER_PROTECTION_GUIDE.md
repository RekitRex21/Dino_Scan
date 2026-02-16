# User Protection Guide - OpenClaw Skills Compromise

## Are You Affected?

If you've installed skills from `github.com/openclaw/skills` before 2026-02-16, you may be affected.

## How to Check

### 1. Search for Malicious IPs
Grep your skills for these C2 IP addresses:
```
91.92.242.30
54.91.154.110
```

### 2. Search for Malicious Domains
Grep for these exfiltration domains:
```
webhook.site
glot.io
```

### 3. Search for Dangerous Code Patterns
Look for:
- `eval(` - arbitrary code execution
- `exec(` - shell command execution  
- `compile(` - dynamic code generation
- `pickle.load` - deserialization attacks
- `urllib.request.urlopen` - direct HTTP requests

### 4. Search for Prompt Injection
Look for references to:
- `SOUL.md`
- `MEMORY.md`
- "ignore previous"
- "jailbreak"
- "developer mode"

### 5. Search for Destructive Commands
Look for:
- `rm -rf` - data deletion
- `shutdown` - system shutdown
- `reboot` - system restart

## What To Do If Compromised

### Immediate Actions
1. **Disconnect** affected systems from network
2. **Backup** any important data
3. **Rotate** ALL API keys and secrets (especially if you see .env references)
4. **Reinstall** OpenClaw from scratch
5. **Scan** all new skills before installing

### Monitoring
- Monitor for unusual network traffic to:
  - 91.92.242.30
  - 54.91.154.110
- Watch for unexpected data exfiltration to webhook.site or glot.io

### Prevention
- Only install skills from trusted sources
- Always review skill code before installing
- Use sandboxed environments for testing
- Keep API keys in secure vaults, never in code

## Report Suspicious Activity
- OpenClaw: https://discord.gg/openclaw
- Security: security@openclaw.ai (if available)
