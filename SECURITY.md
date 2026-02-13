# Security Policy

## Reporting Vulnerabilities

If you find malicious patterns or indicators using DinoScan, please report them so we can update the IOC list!

### How to Report

1. **Check existing issues** - Someone may have already reported it
2. **Open a new issue** with:
   - Repository name
   - Filename(s) flagged
   - SHA-256 hash (if available)
   - Detection type (Credential_Theft, ClawHavoc_C2, etc.)

### Supported Detection Types

- **ClawHavoc_C2** - AMOS stealer command & control
- **AuthTool_C2** - Reverse shell IP
- **Exfil_Domain** - Data exfiltration domains
- **Credential_Theft** - .env/creds.json targeting
- **Memory_Poison** - Personality hijacking (MEMORY.md/SOUL.md)
- **MacOS_Payload** - AMOS delivery (base64 -D | bash)
- **Shell_Injection** - Reverse shell patterns
- **Prompt_Injection** - AI instruction override
- **Dangerous_Ops** - rm -rf, format, shutdown
- **Code_Execution** - eval, exec, pickle.load

---

**DinoScan** - Air-gapped security scanner for OpenClaw skills
