#!/usr/bin/env python3
"""
DinoScan Dashboard - Rich CLI interface
Part of Dino Dynasty OS
"""

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

import sys
import os

# Console will be created when needed
_console = None

def get_console():
    global _console
    if _console is None:
        _console = Console()
    return _console

def print_dashboard_header():
    """Print ASCII art header"""
    if RICH_AVAILABLE:
        try:
            console = get_console()
            # Use ASCII-safe header for Windows
            if sys.platform == "win32":
                header = Text("""
DINO SCAN v1 - Security Scanner
=================================
    _                     _           
   / \  _   _ _ __  _ __ (_)_ __ ___ 
  / _ \| | | | '_ \| '__| | '_ ` _ \
 / ___ \ |_| | |_) | |  | | | | | | |
/_/   \_\__,_| .__/|_|  |_|_| |_| |_|
              |_|                      
""", style="bold green")
            else:
                header = Text("""
🦖 DINOSCAN v1 - Security Scanner 🛡️
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    _                     _           
   / \  _   _ _ __  _ __ (_)_ __ ___ 
  / _ \| | | | '_ \| '__| | '_ ` _ \
 / ___ \ |_| | |_) | |  | | | | | | |
/_/   \_\__,_| .__/|_|  |_|_| |_| |_|
              |_|                      
""", style="bold green")
            console.print(Panel(header, border_style="green"))
        except Exception:
            print("DINO SCAN v1 - Security Scanner")
            print("=" * 50)
    else:
        print("DINO SCAN v1 - Security Scanner")
        print("=" * 50)

def create_results_table(results):
    """Create formatted results table"""
    if not RICH_AVAILABLE:
        return None
    
    table = Table(title="📊 Scan Results", box=box.ROUNDED)
    
    table.add_column("Severity", style="bold", width=10)
    table.add_column("File", style="cyan")
    table.add_column("Line", justify="right", width=6)
    table.add_column("Pattern", style="magenta")
    
    for result in results:
        severity = result.get('severity', 'UNKNOWN')
        style = get_severity_style(severity)
        
        table.add_row(
            f"[{style}]{severity}[/{style}]",
            result.get('file', 'unknown'),
            str(result.get('line', '-')),
            result.get('pattern', 'unknown')[:40]
        )
    
    return table

def get_severity_style(severity):
    """Get color for severity level"""
    mapping = {
        'CRITICAL': 'red bold',
        'HIGH': 'orange1',
        'MEDIUM': 'yellow',
        'INFO': 'blue',
        'SAFE': 'green',
    }
    return mapping.get(severity.upper(), 'white')

def print_summary(stats):
    """Print scan summary"""
    if not RICH_AVAILABLE:
        danger = stats.get('DANGER', 0)
        high = stats.get('HIGH', 0)
        safe = stats.get('SAFE', 0)
        total = stats.get('total', 0)
        print(f"\nSummary: {total} files, {danger} DANGER, {high} HIGH, {safe} SAFE")
        return
    
    danger = stats.get('DANGER', 0)
    high = stats.get('HIGH', 0)
    medium = stats.get('MEDIUM', 0)
    safe = stats.get('SAFE', 0)
    total = stats.get('total', 0)
    risk_score = stats.get('risk_score', 0)
    
    summary = f"""
[bold]Total Files Scanned:[/bold] {total}
[bold red]🔴 CRITICAL:[/bold red] {danger}
[bold orange1]🟠 HIGH:[/bold orange1] {high}
[bold yellow]🟡 MEDIUM:[/bold yellow] {medium}
[bold green]🟢 SAFE:[/bold green] {safe}

[bold]Risk Score:[/bold] {risk_score}/10
    """
    
    console.print(Panel(summary, title="📈 Summary", border_style="cyan"))

def print_progress_bar():
    """Return a progress bar context manager"""
    if RICH_AVAILABLE:
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
        )
    return None

def print_finding(finding, style="yellow"):
    """Print a single finding with color"""
    if RICH_AVAILABLE:
        console.print(f"[{style}]{finding}[/{style}]")
    else:
        print(finding)

def dashboard_print(message, style=None):
    """Print message to dashboard"""
    if RICH_AVAILABLE:
        if style:
            console.print(f"[{style}]{message}[/{style}]")
        else:
            console.print(message)
    else:
        print(message)
