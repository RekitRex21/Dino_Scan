#!/usr/bin/env python3
"""
DinoScan v2 - Security Scanner for OpenClaw Skills
Part of Dino Dynasty OS
================================================
Family-based pattern detection with scoring and context awareness.
Supports IOC feed integration and false positive filtering.
"""

import os
import re
import json
import hashlib
import argparse
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# ============ FAMILY-BASED PATTERN DETECTION ============
# Structure: { family_name: { severity, patterns, score_bonus, context_ignore } }
PATTERN_FAMILIES = {
    # ============ CRITICAL FAMILIES ============
    "ClawHavoc_Stealer": {
        "severity": "CRITICAL",
        "score_bonus": 5,
        "patterns": [
            r"91\.92\.242\.30",           # Primary AMOS C2
            r"54\.91\.154\.110",          # Secondary C2
            r"http[s]?://91\.92\.242\.30",
            r"http[s]?://54\.91\.154\.110:\d+",
            r"openclaw-agent\.exe",       # Windows dropper
            r"x5ki60w1ih838sp7",          # macOS payload path
            r"Atomic\s*Stealer|AMOS",
        ],
        "context_ignore": [],
    },
    "Prompt_Poisoner": {
        "severity": "HIGH",
        "score_bonus": 3,
        "patterns": [
            r"(?i)ignore\s+(previous|all\s+previous|prior)",
            r"(?i)forget\s+(all\s+)?(previous|instructions)",
            r"(?i)new\s+instructions",
            r"(?i)act\s+as|you\s+are\s+now",
            r"(?i)developer\s+mode|jailbreak",
            r"(?i)override\s+(system|your)",
            r"(?i)DAN\s+mode|permanent\s+prompt",
            r"SOUL\.md|MEMORY\.md|AGENTS\.md",  # OpenClaw memory files
            r"(?i)always\s+send.*to.*http",
            r"(?i)install.*dependency.*setup\.sh",
        ],
        "context_ignore": ["tokenizer", "model training", "fine-tuning"],
    },
    "Cred_Harvester": {
        "severity": "CRITICAL",
        "score_bonus": 4,
        "patterns": [
            r"(?i)(api_key|secret|token|password|private_key)\s*=\s*['\"][a-zA-Z0-9_\-]{20,}",
            r"(?i)(binance|coinbase|bybit|solana|wallet).*=\s*['\"][a-zA-Z0-9_\-]{20,}",
            r"\.env|\.secrets|keyring",
            r"browser.*cookies|chrome.*Login\s+Data",
            r"sqlite.*cookies",
            r"(?i)Authorization.*:\s*[A-Za-z0-9\-_]{20,}",
        ],
        "context_ignore": [],
    },
    "RCE_Injector": {
        "severity": "CRITICAL",
        "score_bonus": 4,
        "patterns": [
            r"eval\s*\(|exec\s*\(|compile\s*\(",
            r"pickle\.load|marshal\.load|yaml\.load",
            r"child_process\.exec|child_process\.spawn",
            r"os\.system\(|os\.popen\(",
            r"__import__\(|import\s*\(\s*['\"]os",
            r"subprocess.*shell\s*=\s*True",
        ],
        "context_ignore": [],
    },
    # ============ HIGH SEVERITY FAMILIES ============
    "Social_Eng_Loader": {
        "severity": "HIGH",
        "score_bonus": 3,
        "patterns": [
            r"base64\s+-d\s*\|\s*bash",
            r"base64\s+-d\s*\|\s*sh",
            r"curl\s+.*?\s*\|\s*(bash|sh|python)",
            r"wget\s+.*?-O\s*-",
            r"paste\s+this.*terminal",
            r"run\s+this\s+command",
            r"fix\s+env|helper\s+agent",
            r"click\s+to\s+fix|install\s+prerequisite",
        ],
        "context_ignore": ["testing", "test_"],
    },
    "Destructive_Shell": {
        "severity": "HIGH",
        "score_bonus": 3,
        "patterns": [
            r"rm\s+-rf",
            r"rmdir\s+/",
            r"del\s+/[sq]",
            r"format\s+.*disk",
            r"wipe\s+disk|shred\s+file",
            r"shutdown|reboot|halt|poweroff",
            r"kill\s+-\d+",
        ],
        "context_ignore": [],
    },
    "Exfil_Domains": {
        "severity": "HIGH",
        "score_bonus": 3,
        "patterns": [
            r"webhook\.site|glot\.io",
            r"ngrok\.io|pipedream\.net",
            r"clawdbot\.getintwopc\.site",
            r"clawhub\.openclaw\.ai",
            r"molt\.bot",
            r"attacker\.com",
            r"darkgptprivate\.com",
            r"socifiapp\.com",
            r"pastebin\.com.*raw",
            r"transfer\.sh|file\.io",
        ],
        "context_ignore": [],
    },
    "Bare_IP_Fetch": {
        "severity": "HIGH",
        "score_bonus": 2,
        "patterns": [
            r"http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/|:)",
        ],
        "context_ignore": [r"127\.0\.0\.1", "localhost", r"0\.0\.0\.0"],
    },
    "Suspicious_Storage": {
        "severity": "HIGH",
        "score_bonus": 2,
        "patterns": [
            r"localStorage|sessionStorage",
            r"IndexedDB",
            r"chrome\.storage",
            r"electron\.store",
            r"electron\.ipcRenderer",
        ],
        "context_ignore": [],
    },
    # ============ MEDIUM SEVERITY FAMILIES ============
    "Obfuscation": {
        "severity": "MEDIUM",
        "score_bonus": 1,
        "patterns": [
            r"[A-Za-z0-9+/]{100,}={1,2}",  # Long base64
            r"\\x[0-9a-f]{2,}",              # Hex encoding
            r"eval\s*\(\s*atob\s*\(",
            r"String\.fromCharCode",
            r"rot13|rot47",
        ],
        "context_ignore": [],
    },
    "DNS_Tunneling": {
        "severity": "MEDIUM",
        "score_bonus": 2,
        "patterns": [
            r"\.attacker\.com",
            r"\.exfil\.net",
            r"dns\.resolve",
            r"socket\.gethostbyname",
        ],
        "context_ignore": [],
    },
    "Telegram_Exfil": {
        "severity": "MEDIUM",
        "score_bonus": 2,
        "patterns": [
            r"api\.telegram\.org/bot",
            r"https://api\.telegram\.org",
        ],
        "context_ignore": [],
    },
    "LotL_Attack": {
        "severity": "HIGH",
        "score_bonus": 2,
        "patterns": [
            r"subprocess\.run.*curl",
            r"subprocess\.run.*wget",
            r"subprocess\.run.*certutil",
            r"subprocess\.run.*powershell",
            r"os\.system.*curl",
            r"os\.system.*wget",
            r"pty\.spawn.*bash",
        ],
        "context_ignore": [],
    },
    "Steganography": {
        "severity": "MEDIUM",
        "score_bonus": 1,
        "patterns": [
            r"PIL\.Image\.open.*\.png",
            r"base64.*image",
            r"embed.*image",
        ],
        "context_ignore": [],
    },
}

# Keep old patterns for backwards compatibility
SUSPICIOUS_PATTERNS = PATTERN_FAMILIES  # Use family-based patterns
DEFAULT_IOCS = {
    "ips": [
        "91.92.242.30",
        "54.91.154.110",
    ],
    "domains": [
        "webhook.site",
        "glot.io",
        "ngrok.io",
        "pastebin.com",
    ],
}

# ============ FALSE POSITIVE FILTER ============
SAFE_PATTERNS = [
    r"api\.openai\.com",
    r"api\.anthropic\.com", 
    r"api\.google\.com",
    r"api\.minimax\.io",
    r"subprocess\.run\s*\(\s*\[\s*['\"]echo",
    r"subprocess\.run\s*\(\s*\[\s*['\"]ls",
    r"subprocess\.check_output",
    r"Authorization.*Bearer",
    r"process\.env\.NODE_ENV",
    r"//.*#\s*ignore",
]

# Additional safe patterns (comments, tests)
ADDITIONAL_SAFE = [
    r'SKILL\.md',
    r'healthcheck',
    r'```python',
    r'```',
    r'# .*eval\(',
    r'# .*exec\(',
    r'def test_',
    r'def malicious_',
]

# ============ RISK CONFIG ============
SEVERITY_COLORS = {
    'CRITICAL': '[!]',
    'HIGH': '[+]',
    'MEDIUM': '[~]',
    'INFO': '[i]'
}

RISK_WEIGHTS = {
    'prompt_injection': 10,
    'dangerous_ops': 10,
    'code_execution': 9,
    'data_exfil': 8,
    'shell_dynamic': 6,
    'obfuscation': 4,
    'ClawHavoc_C2': 10,
    'AuthTool_C2': 10,
    'Exfil_Domain': 9,
    'Credential_Theft': 9,
    'Memory_Poison': 8,
    'MacOS_Payload': 10,
    'Shell_Injection': 9,
}


def is_safe(content: str, start: int, end: int) -> bool:
    """Check if detection is in a safe context."""
    context_start = max(0, start - 200)
    context_end = min(len(content), end + 50)
    context = content[context_start:context_end]
    
    for safe_pattern in SAFE_PATTERNS:
        if re.search(safe_pattern, context):
            return True
    return False


def get_file_hash(path: str) -> str:
    """Calculate SHA-256 hash."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "ERROR_HASHING"


def scan_content(content: str, filename: str = "unknown") -> tuple:
    """Scan content for all patterns."""
    findings = []
    total_score = 0
    
    # Check multi-patterns
    for category, patterns in SUSPICIOUS_PATTERNS.items():
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if is_safe(content, match.start(), match.end()):
                    continue
                
                line_num = content[:match.start()].count('\n') + 1
                
                if category in ['prompt_injection', 'dangerous_ops']:
                    severity = 'CRITICAL'
                elif category in ['code_execution', 'data_exfil']:
                    severity = 'HIGH'
                else:
                    severity = 'MEDIUM'
                
                findings.append({
                    'type': category,
                    'severity': severity,
                    'line': line_num,
                    'match': match.group()[:60],
                    'source': 'multi-pattern'
                })
                total_score += RISK_WEIGHTS.get(category, 1)
    
    # Note: IOC scanning now handled by family-based patterns (ClawHavoc_Stealer, Exfil_Domains, etc.)
    # Legacy IOC scanner disabled - families provide better coverage with scoring
    
    # ============ FAMILY-BASED SCANNING (v2) - PRIMARY ============
    family_hits = {}  # Track hits per family
    
    for family_name, family_config in PATTERN_FAMILIES.items():
        patterns = family_config.get('patterns', [])
        severity = family_config.get('severity', 'MEDIUM')
        score_bonus = family_config.get('score_bonus', 1)
        context_ignore = family_config.get('context_ignore', [])
        
        for pattern in patterns:
            try:
                for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                    # Get context around match
                    context_start = max(0, match.start() - 100)
                    context_end = min(len(content), match.end() + 100)
                    context = content[context_start:context_end]
                    
                    # Check if matches safe context (false positive filter)
                    if context_ignore:
                        for ignore_term in context_ignore:
                            if ignore_term.lower() in context.lower():
                                break
                    else:
                        # Check safe patterns
                        if is_safe(content, match.start(), match.end()):
                            continue
                    
                    line_num = content[:match.start()].count('\n') + 1
                    
                    findings.append({
                        'type': family_name,
                        'severity': severity,
                        'line': line_num,
                        'match': match.group()[:60],
                        'source': 'family',
                        'family': family_name
                    })
                    total_score += score_bonus
                    
                    # Track family hits for aggregation
                    if family_name not in family_hits:
                        family_hits[family_name] = 0
                    family_hits[family_name] += 1
            except re.error:
                pass  # Skip invalid regex
    
    # Family aggregation bonus - if 2+ hits in same family, boost score
    for family, hit_count in family_hits.items():
        if hit_count >= 2:
            total_score += PATTERN_FAMILIES.get(family, {}).get('score_bonus', 2)
    
    # Calculate risk
    if findings:
        severity_scores = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'INFO': 2}
        weighted = sum(severity_scores.get(f['severity'], 1) for f in findings)
        risk_score = min(10, weighted / len(findings) * 1.5)
    else:
        risk_score = 0
    
    return findings, risk_score


def get_recommendation(risk_score, findings):
    """Get recommendation based on risk score."""
    critical = len([f for f in findings if f['severity'] == 'CRITICAL'])
    high = len([f for f in findings if f['severity'] == 'HIGH'])
    
    if risk_score == 0:
        return '[SAFE]', 'No security issues detected'
    elif critical > 0:
        return '[DANGER]', f'{critical} critical issues found'
    elif high > 0:
        return '[HIGH RISK]', f'{high} high-risk issues'
    elif risk_score < 4:
        return '[LOW RISK]', 'Minor issues - likely safe'
    else:
        return '[MODERATE]', 'Some issues to review'


def scan_file(filepath: str, return_findings: bool = False):
    """Scan a single file."""
    print(f"\n{'='*60}")
    print(f"SCANNING: {os.path.basename(filepath)}")
    print('='*60)
    
    if not os.path.exists(filepath):
        print(f"[ERROR] File not found")
        return None, 0
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    findings, score = scan_content(content, os.path.basename(filepath))
    risk_score = calculate_risk_score(findings)
    recommendation, msg = get_recommendation(risk_score, findings)
    
    print(f"\nRisk Score: {risk_score:.1f}/10")
    print(f"Recommendation: {recommendation}")
    print(f"{msg}")
    
    if findings:
        print(f"\nFINDINGS ({len(findings)}):")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM']:
            severity_findings = [f for f in findings if f['severity'] == severity]
            if severity_findings:
                print(f"\n{SEVERITY_COLORS[severity]} {severity} ({len(severity_findings)}):")
                for f in severity_findings[:5]:
                    print(f"  Line {f['line']}: {f['match'][:50]}")
                if len(severity_findings) > 5:
                    print(f"  ... and {len(severity_findings) - 5} more")
    
    print()
    
    # Add hash for evidence
    result = {
        "file": os.path.basename(filepath),
        "path": filepath,
        "hash": get_file_hash(filepath),
        "score": risk_score,
        "recommendation": recommendation,
        "findings": findings,
        "scanned_at": datetime.now().isoformat()
    }
    
    if return_findings:
        return result, risk_score
    return None, 0


def calculate_risk_score(findings):
    """Calculate risk score (0-10)."""
    if not findings:
        return 0
    severity_scores = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'INFO': 2}
    weighted = sum(severity_scores.get(f['severity'], 1) for f in findings)
    return min(10, weighted / len(findings) * 1.5)


def scan_directory(dirpath: str) -> list:
    """Scan a directory."""
    print(f"\n{'='*60}")
    print(f"SCANNING DIRECTORY: {dirpath}")
    print('='*60)
    
    results = []
    skills_scanned = 0
    
    for root, dirs, files in os.walk(dirpath):
        for f in files:
            if f.endswith(('.py', '.md', '.txt', '.json', '.js', '.sh')):
                filepath = os.path.join(root, f)
                skills_scanned += 1
                
                result, _ = scan_file(filepath, return_findings=True)
                if result:
                    results.append(result)
    
    # Summary
    danger = sum(1 for r in results if r['recommendation'] == '[DANGER]')
    high = sum(1 for r in results if r['recommendation'] == '[HIGH RISK]')
    safe = sum(1 for r in results if r['recommendation'] == '[SAFE]')
    
    print(f"\n{'='*60}")
    print(f"SCAN SUMMARY")
    print('='*60)
    print(f"Files scanned: {skills_scanned}")
    print(f"  DANGER: {danger}")
    print(f"  HIGH: {high}")
    print(f"  SAFE: {safe}")
    
    return results


def fetch_url(url: str) -> tuple:
    """Fetch content from URL."""
    headers = {'User-Agent': 'OpenClaw-Scanner/1.0'}
    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=30) as response:
            content = response.read().decode('utf-8', errors='ignore')
            filename = url.split('/')[-1].split('?')[0]
            return content, filename
    except Exception as e:
        return None, str(e)


def scan_url(url: str, return_findings: bool = False):
    """Scan content from URL."""
    print(f"\n{'='*60}")
    print(f"SCANNING URL: {url}")
    print('='*60)
    
    content, filename = fetch_url(url)
    
    if content is None:
        print(f"[ERROR] Failed to fetch: {filename}")
        return None, 0
    
    print(f"Fetched: {filename} ({len(content)} bytes)")
    
    findings, score = scan_content(content, filename)
    risk_score = calculate_risk_score(findings)
    recommendation, msg = get_recommendation(risk_score, findings)
    
    print(f"\nRisk Score: {risk_score:.1f}/10")
    print(f"Recommendation: {recommendation}")
    print(f"{msg}")
    
    result = {
        "file": filename,
        "source_url": url,
        "hash": hashlib.sha256(content.encode()).hexdigest(),
        "score": risk_score,
        "recommendation": recommendation,
        "findings": findings,
        "scanned_at": datetime.now().isoformat()
    }
    
    if return_findings:
        return result, risk_score
    return None, 0


def generate_markdown_report(results: list, output_file: str = "audit_report.md", repo_url: str = None):
    """Generate Markdown evidence report."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    danger = [r for r in results if r.get('recommendation') == '[DANGER]']
    high = [r for r in results if r.get('recommendation') == '[HIGH RISK]']
    safe = [r for r in results if r.get('recommendation') == '[SAFE]']
    
    repo_line = f"**Repository:** {repo_url}\n" if repo_url else ""
    
    report = f"""# OpenClaw Security Audit Report

**Generated:** {timestamp}
{repo_line}**Total Files Scanned:** {len(results)}

---

## Summary

| Status | Count |
| :--- | :--- |
| 🔴 DANGER | {len(danger)} |
| 🟠 HIGH | {len(high)} |
| 🟢 SAFE | {len(safe)} |

"""
    
    if danger:
        report += "## 🔴 DANGER - Critical Issues\n\n"
        for entry in danger:
            findings = ", ".join([f["type"] for f in entry.get("findings", [])])
            report += f"- **{entry['file']}** ({entry['score']:.1f}/10): {findings}\n"
        report += "\n"
    
    if high:
        report += "## 🟠 HIGH Risk\n\n"
        for entry in high:
            findings = ", ".join([f["type"] for f in entry.get("findings", [])])
            report += f"- **{entry['file']}** ({entry['score']:.1f}/10): {findings}\n"
        report += "\n"
    
    if safe:
        report += "## 🟢 Safe Files\n\n"
        for entry in safe[:20]:
            report += f"- {entry['file']}\n"
        if len(safe) > 20:
            report += f"- ... and {len(safe) - 20} more\n"
    
    report += "\n---\n*Generated by DinoScan v1*\n"
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"[+] Report saved: {output_file}")


def generate_kill_list(results: list, output_file: str = "kill_list.md"):
    """Generate a kill list of dangerous files for community sharing."""
    danger = [r for r in results if r.get('recommendation') == '[DANGER]']
    
    if not danger:
        print("[*] No danger files to add to kill list")
        return
    
    kill_list = f"""# Shield + Dino Kill List 🔴

**Generated:** {datetime.now().isoformat()}
**Total Dangerous Files:** {len(danger)}

> ⚠️ **WARNING**: These files contain malicious patterns. Do NOT install!

## Indicators

| File | SHA-256 | Issues |
| :--- | :--- | :--- |
"""
    
    for entry in danger:
        issues = ", ".join([f["type"] for f in entry.get("findings", [])])
        kill_list += f"| {entry['file']} | `{entry['hash'][:16]}...` | {issues} |\n"
    
    kill_list += """
## How to Use

1. **Check Before Install**: Cross-reference skills against this list
2. **Report to OpenClaw**: Submit issues for community awareness
3. **Block in Scanner**: Add hashes to your blocklist

---
*Generated by Shield + Dino v1 - Share responsibly*
"""
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(kill_list)
    
    print(f"[+] Kill list saved: {output_file}")
    return kill_list


def main():
    parser = argparse.ArgumentParser(
        description='DinoScan v1 - Security Scanner'
    )
    parser.add_argument('--file', '-f', help='Scan single file')
    parser.add_argument('--dir', '-d', help='Scan directory')
    parser.add_argument('--url', '-u', action='append', help='Scan URL(s) - can use multiple times')
    parser.add_argument('--urls', '--url-list', dest='url_list', help='Scan multiple URLs from file (one per line)')
    parser.add_argument('--json', '-j', action='store_true', help='JSON output')
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--report', '-r', action='store_true', help='Generate Markdown report')
    parser.add_argument('--kill-list', '-k', action='store_true', help='Generate kill list for community')
    parser.add_argument('--repo-url', help='GitHub repo URL (e.g., https://github.com/user/repo)')
    parser.add_argument('--dashboard', action='store_true', help='Rich CLI dashboard output')
    parser.add_argument('--quiet', '-q', action='store_true', help='Minimal output')
    
    args = parser.parse_args()
    
    # Import dashboard
    if args.dashboard:
        try:
            from dashboard import print_dashboard_header, create_results_table, print_summary, dashboard_print
            print_dashboard_header()
            if not args.quiet:
                dashboard_print("Scanning...", "cyan")
        except ImportError:
            print("Warning: rich not installed. Installing...")
            import subprocess
            subprocess.run(['pip', 'install', 'rich'])
            from dashboard import print_dashboard_header, create_results_table, print_summary, dashboard_print
            print_dashboard_header()
    else:
        print(f"\n{'='*60}")
        print(f"SHIELD + DINO v1 - Security Scanner")
        print(f"{'='*60}")
    
    results = []
    
    # Collect URLs
    urls_to_scan = []
    if args.url:
        urls_to_scan.extend(args.url)
    if args.url_list:
        with open(args.url_list, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    urls_to_scan.append(line)
    
    if args.file:
        result, _ = scan_file(args.file, return_findings=True)
        if result:
            results.append(result)
    elif args.dir:
        results = scan_directory(args.dir)
    elif urls_to_scan:
        for url in urls_to_scan:
            result, _ = scan_url(url, return_findings=True)
            if result:
                results.append(result)
    else:
        print("\nUsage:")
        print("  python skill_scanner.py --file skill.py")
        print("  python skill_scanner.py --dir /path/to/skills/")
        print("  python skill_scanner.py --url https://raw.github.com/.../skill.py")
        print("  python skill_scanner.py --url url1 --url url2 --url url3")
        print("  python skill_scanner.py --urls urls.txt")
        print("  python skill_scanner.py --dir . --json --output results.json --report")
        return
    
    # Output
    if args.json and results:
        # Wrap results with metadata
        output_data = {
            "repo_url": args.repo_url,
            "scanned_at": datetime.now().isoformat(),
            "total_files": len(results),
            "results": results
        }
        output = json.dumps(output_data, indent=2)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"\nJSON saved: {args.output}")
        else:
            print(output)
    
    # Report
    if args.report and results:
        generate_markdown_report(results, args.output or "audit_report.md", args.repo_url)
    
    # Kill List
    if args.kill_list and results:
        generate_kill_list(results, "kill_list.md")
    
    # Dashboard output
    if args.dashboard and results:
        try:
            from dashboard import create_results_table, print_summary
            
            # Calculate stats
            stats = {'total': len(results), 'DANGER': 0, 'HIGH': 0, 'MEDIUM': 0, 'SAFE': 0}
            findings_list = []
            
            for r in results:
                severity = r.get('severity', 'SAFE')
                stats[severity] = stats.get(severity, 0) + 1
                if severity in ['CRITICAL', 'HIGH', 'MEDIUM']:
                    findings_list.append(r)
            
            stats['risk_score'] = calculate_risk_score(findings_list)
            
            # Print results
            if findings_list:
                table = create_results_table(findings_list)
                if table:
                    console.print(table)
            
            print_summary(stats)
            
        except ImportError:
            print("Install rich for dashboard: pip install rich")


if __name__ == "__main__":
    main()
