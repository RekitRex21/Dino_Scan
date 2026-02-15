#!/usr/bin/env python3
"""
DinoScan v1 - Security Scanner for OpenClaw Skills
Part of Dino Dynasty OS
"""

import os
import re
import json
import hashlib
import argparse
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# ============ MULTI-PATTERN DETECTION ============
SUSPICIOUS_PATTERNS = {
    # Prompt injection - CRITICAL
    'prompt_injection': [
        r'(?i)(ignore.*previous|forget.*instructions|disregard.*all)',
        r'(?i)(you.*are.*now.*instead|act.*as.*if.*you.*were)',
        r'(?i)(developer.*mode|jailbreak|bypass.*restriction)',
    ],
    # Dangerous operations - CRITICAL
    'dangerous_ops': [
        r'(?i)(rm\s+-rf|rmdir\s+/|del\s+/|format\s+.*disk)',
        r'(?i)(wipe.*disk|shred.*file)',
        r'(?i)(shutdown|reboot|kill\s+-\d)',
    ],
    # Code execution - HIGH
    'code_execution': [
        r'(?i)(eval\(|exec\(|compile\(|__import__\()',
        r'(?i)(pickle\.load|marshal\.load|yaml\.load)',
    ],
    # Data exfiltration - HIGH
    'data_exfil': [
        r'(?i)(requests\.post\([^"]*(?!api\.(openai|anthropic|google))[^"]*https?://)',
        r'(?i)(urllib\.request\.urlopen)',
        r'(?i)(socket\.(connect|send)\()',
    ],
    # Shell injection - MEDIUM
    'shell_dynamic': [
        r'(?i)(os\.system\()',
        r'(?i)(popen\()',
    ],
    # Obfuscation - MEDIUM
    'obfuscation': [
        r'[A-Za-z0-9+/]{100,}=',  # Long base64
        r'\\x[0-9a-f]{2,}',        # Hex encoding
    ],
    # Living off the Land (LotL) - CRITICAL
    'lotl_attack': [
        r'subprocess\.run.*curl',
        r'subprocess\.run.*wget',
        r'subprocess\.run.*certutil',
        r'subprocess\.run.*powershell',
        r'os\.system.*curl',
        r'os\.system.*wget',
        r'pty\.spawn.*bash',
    ],
    # DNS Tunneling - HIGH
    'dns_tunneling': [
        r'\.attacker\.com',
        r'\.exfil\.net',
        r'dns\.resolve',
        r'socket\.gethostbyname',
    ],
    # Telegram Exfil - HIGH  
    'telegram_exfil': [
        r'api\.telegram\.org/bot',
        r'https://api\.telegram\.org',
    ],
    # Steganography - HIGH
    'steganography': [
        r'PIL\.Image\.open.*\.png',
        r'base64.*image',
        r'embed.*image',
    ],
}

# ============ IOCs (Feb 2026) ============
IOCS = {
    "ClawHavoc_C2": r"91\.92\.242\.30",
    "AuthTool_C2": r"54\.91\.154\.110",
    "Exfil_Domain": r"glot\.io|webhook\.site",
    "Credential_Theft": r"\.env|creds\.json",
    "Memory_Poison": r"MEMORY\.md|SOUL\.md",
    "MacOS_Payload": r"base64\s+-D\s+\|\s+bash",
    "Shell_Injection": r"os\.system\(.*curl.*sh\)",
}

# ============ FALSE POSITIVE FILTER ============
SAFE_PATTERNS = [
    r'api\.openai\.com',
    r'api\.anthropic\.com',
    r'api\.google\.com',
    r'subprocess\.run',
    r'subprocess\.check_output',
    r'Authorization.*Bearer',
    r':root\b',
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
    
    # Check IOCs
    for ioc_name, pattern in IOCS.items():
        for match in re.finditer(pattern, content, re.IGNORECASE):
            if is_safe(content, match.start(), match.end()):
                continue
            
            line_num = content[:match.start()].count('\n') + 1
            findings.append({
                'type': ioc_name,
                'severity': 'CRITICAL',
                'line': line_num,
                'match': match.group()[:60],
                'source': 'ioc'
            })
            total_score += RISK_WEIGHTS.get(ioc_name, 10)
    
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
    
    kill_list = f"""# DinoScan Kill List 🔴

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
*Generated by DinoScan v1 - Share responsibly*
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
        print(f"DINOSCAN v1 - Security Scanner")
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
