# Sample Safe Skill for Testing
# This skill should pass the security scan

import os
import json
from datetime import datetime

def get_status():
    """Get current status"""
    return {
        'time': datetime.now().isoformat(),
        'status': 'active'
    }

def format_message(text):
    """Format a message"""
    return f"[STATUS] {text}"
