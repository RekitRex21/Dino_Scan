## Security Advisory: Malicious Code Repository

### Executive Summary
Systematic trojan campaign discovered in github.com/openclaw/skills containing 500+ security vulnerabilities including credential harvesting, active C2 infrastructure, code execution vulnerabilities, and prompt injection attacks.

### Repository Information
- **URL:** github.com/openclaw/skills
- **Affected Files:** 200+ files
- **Discovery Date:** 2026-02-16

### Threat Classification
- **Credential Harvesting:** 200+ hardcoded API keys/secrets
- **Active C2 Infrastructure:** IPs 91.92.242.30, 54.91.154.110
- **Code Execution:** 100+ eval()/exec()/compile() vulnerabilities
- **Prompt Injection:** 50+ AI manipulation patterns
- **Data Exfiltration:** webhook.site, glot.io domains

### Evidence Summary
See attached AUTHORITY_REPORT.md for complete technical details.

### Impact Assessment
- **Potential Victims:** Repository is public and accessible to all OpenClaw users
- **Attack Sophistication:** High - systematic campaign with dedicated infrastructure
- **Status:** Active threat - C2 servers still operational

### Recommended Action
- Immediate repository takedown/quarantine
- Security audit of all skills before re-enabling
- User notification of potential compromise

---
Reported by: DinoScan Security Scanner
Discovery Date: 2026-02-16
