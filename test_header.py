import sys
import os
sys.path.append(os.getcwd())
try:
    import dashboard
    dashboard.print_dashboard_header()
except Exception as e:
    print(f"Error: {e}")
