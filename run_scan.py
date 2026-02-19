import os
import json
import sys
sys.path.insert(0, r'C:\Users\rexdu\.openclaw\workspace\dino-scan')
from skill_scanner import scan_directory

print("Starting scan...")
results = scan_directory(r'C:\Users\rexdu\.openclaw\workspace\dino-scan\temp_skills\skills')
print(f'Total files scanned: {len(results)}')

# Aggregate findings
findings = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
critical_issues = []
high_issues = []

for r in results:
    sev = r.get('severity', 'INFO')
    findings[sev] = findings.get(sev, 0) + 1
    if sev == 'CRITICAL':
        critical_issues.append(r)
    elif sev == 'HIGH':
        high_issues.append(r)

print(json.dumps(findings, indent=2))
print(f'\n=== CRITICAL ISSUES ({len(critical_issues)}) ===')
for i, c in enumerate(critical_issues[:30]):
    print(f'{i+1}. {c.get("file", "?")} - {c.get("pattern", "?")}')

print(f'\n=== HIGH ISSUES ({len(high_issues)}) - Sample 20 ===')
for i, c in enumerate(high_issues[:20]):
    print(f'{i+1}. {c.get("file", "?")} - {c.get("pattern", "?")}')

# Save full results
output = {
    'summary': findings,
    'total_files': len(results),
    'critical': critical_issues[:50],
    'high': high_issues[:50]
}
with open(r'C:\Users\rexdu\.openclaw\workspace\dino-scan\reports\clawhub_full.json', 'w') as f:
    json.dump(output, f, indent=2)
print('\nSaved to reports/clawhub_full.json')
