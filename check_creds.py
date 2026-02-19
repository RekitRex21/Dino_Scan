import re
import os

scan_dir = r"C:\Users\rexdu\.openclaw\workspace\dino-scan"
suspicious = []

for root, dirs, files in os.walk(scan_dir):
    # Skip __pycache__
    dirs[:] = [d for d in dirs if d != '__pycache__']
    
    for f in files:
        if f.endswith('.py'):
            path = os.path.join(root, f)
            content = open(path, 'r', encoding='utf-8', errors='ignore').read()
            
            # Check for suspicious patterns (not in comments/regex defs)
            # Look for actual credential-like strings
            creds = re.findall(r'sk-[a-zA-Z0-9]{20,}', content)
            if creds:
                suspicious.append(f"{f}: OpenAI-like key found")
            
            creds = re.findall(r'pk_[a-zA-Z0-9]{20,}', content)
            if creds:
                suspicious.append(f"{f}: Stripe-like key found")
            
            # Check for IP addresses (except our documented IOCs)
            ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content)
            for ip in ips:
                if ip not in ['91.92.242.30', '54.91.154.110', '127.0.0.1', '0.0.0.0']:
                    suspicious.append(f"{f}: Unknown IP: {ip}")

if suspicious:
    print("SUSPICIOUS FINDINGS:")
    for s in suspicious:
        print(f"  ! {s}")
else:
    print("No suspicious credentials found!")
    
# Also check for .env files
env_files = []
for root, dirs, files in os.walk(scan_dir):
    for f in files:
        if '.env' in f.lower() or f.endswith('.key') or 'credentials' in f.lower():
            env_files.append(os.path.join(root, f))

if env_files:
    print("\n.env/credential files found:")
    for f in env_files:
        print(f"  ! {f}")
else:
    print("\nNo .env or credential files found.")
