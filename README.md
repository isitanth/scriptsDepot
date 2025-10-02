# scriptsDepot

A curated collection of small but useful scripts for various contexts:
- macOS system helpers
- Mach-O binary inspection (pre-triage, structured analysis, IDA heuristics)
- Markdown utilities
- Build automation

All scripts are MIT licensed and designed to be simple, auditable, and easily adaptable.

---

## Repository structure

- **build.sh**  
  C-based build cockpit script for quick compilation workflows.

- **macos_preinspect.sh**  
  Shell pre-inspection tool for Mach-O binaries.  
  Collects headers, linked dylibs, entitlements, symbols, and interesting strings.

- **python_macho_inspect.py**  
  Python (LIEF-based) structured Mach-O analyzer.  
  Produces JSON output with segments, imports, symbols, and heuristic string detection.

- **ida_analyze_macho.py**  
  IDAPython script that marks interesting strings, ObjC selectors, and comments functions likely bridging ObjC runtime.  
  Run inside IDA (`File → Script file...`).

- **macos_hotspot_safe.sh**  
  Utility script to configure safe Wi-Fi hotspot setup on macOS.

- **md_heading_sentence_case.sh**  
  Markdown helper: normalize headings to sentence case.

---

## Usage examples

### Mach-O inspection
```bash
# Quick shell inspection
./macos_preinspect.sh /path/to/binary

# Structured JSON export
python3 python_macho_inspect.py /path/to/binary report.json

# In IDA
# File -> Script file -> ida_analyze_macho.py
