# DinoScan CLI Dashboard - SPEC.md

## Project Objective
Add a rich CLI dashboard to DinoScan for beautiful terminal-based security reports with tables, progress, and color.

## Features
- [x] Rich CLI dashboard using `rich` library
- [x] ASCII art header with DinoScan logo
- [ ] Real-time scan progress bar
- [x] Table output for findings (severity, file, line, pattern)
- [x] Summary statistics (total files, danger count, safe count)
- [x] Color-coded severity levels (red=CRITICAL, orange=HIGH, yellow=MEDIUM, green=SAFE)
- [ ] Interactive mode (optional)
- [x] Export to HTML still supported

## Technical
- Library: `rich` (pip install rich)
- Falls back to plain text if rich not available
- Same scan logic, just prettier output
- `--dashboard` flag to enable

## Acceptance Criteria
1. Dashboard shows animated progress during scan
2. Results display in formatted table
3. Summary shows risk score with emoji indicators
4. Works without rich (graceful fallback)
5. Matches existing JSON/Markdown output
