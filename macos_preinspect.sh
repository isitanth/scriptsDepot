#!/usr/bin/env bash
# macos_preinspect.sh
# -------------------------------------------------------------------------
# Author : Anthony Chambet — Solution Architect
# Date   : 2025-10-01
# Purpose: Quick macOS Mach-O pre-inspection: headers, linked dylibs, strings,
#          entitlements and simple heuristics for reverse pre-triage.
# Usage  : ./macos_preinspect.sh /path/to/binary
# License: MIT (or "Internal use only")
# -------------------------------------------------------------------------

set -euo pipefail

BIN="$1"
OUTDIR="./inspect_$(basename "$BIN")_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

echo "[*] Inspecting: $BIN"
echo "[*] Output -> $OUTDIR"

# basic file type
file "$BIN" > "$OUTDIR/00_file.txt"

# lipo info (fat/universal)
lipo -info "$BIN" > "$OUTDIR/01_lipo.txt" 2>/dev/null || true

# mach headers + load commands
echo "[*] otool -l (load commands)"
otool -l "$BIN" > "$OUTDIR/02_otool_l.txt"

# linked dylibs
echo "[*] otool -L (linked dylibs)"
otool -L "$BIN" > "$OUTDIR/03_otool_L.txt"

# symbol table (nm); try both architectures if fat
echo "[*] nm (undefined/external symbols may indicate APIs used)"
nm -m "$BIN" > "$OUTDIR/04_nm_m.txt" 2>/dev/null || nm -gU "$BIN" > "$OUTDIR/04_nm.txt" 2>/dev/null || true

# dyld info (rebase/bind/weak-bind/exports)
echo "[*] dyld info (if available)"
dyldinfo "$BIN" > "$OUTDIR/05_dyldinfo.txt" 2>/dev/null || true

# codesign & entitlements (if signed)
echo "[*] codesign -dvvvv and entitlements"
codesign -dvvvv "$BIN" > "$OUTDIR/06_codesign.txt" 2>/dev/null || true
security cms -D -i "$BIN" > /dev/null 2>/dev/null || true

# Try to dump embedded provisioning / plist / entitlements if present
if /usr/bin/plutil -p "$BIN" >/dev/null 2>&1; then
  echo "[*] plutil: likely embedded plist (dumping maybe)"
  /usr/bin/plutil -p "$BIN" > "$OUTDIR/07_plutil.txt" 2>/dev/null || true
fi

# strings (with offset)
echo "[*] strings (filtered)"
strings -a -t x "$BIN" | egrep -i "password|api|token|key|secret|http|https|passwd|Authorization|UUID|S3|AWS|AWS_SECRET|id_rsa|BEGIN RSA" > "$OUTDIR/08_strings_interesting.txt" || true
strings -a -t x "$BIN" > "$OUTDIR/08_strings_all.txt"

# Heuristics: Objective-C runtime / classes (class names visible as strings)
echo "[*] Searching for ObjC classes / selectors"
egrep -a --only-matching "'?[_A-Za-z0-9$@]+" "$OUTDIR/08_strings_all.txt" > /dev/null 2>&1 || true
# quick grep for objc selectors / -[ or _OBJC_CLASS_
strings -a "$BIN" | egrep -i "objc|NS|CF|UIApplication|UIView|alloc|init|selector|objc_msgSend" > "$OUTDIR/09_objc_candidates.txt" || true

# extract entitlements via codesign (if IPAs or signed Mach-O)
codesign -d --entitlements :- "$BIN" > "$OUTDIR/10_entitlements.plist" 2>/dev/null || true

# attempt to list exported symbols (for dylibs)
echo "[*] exports (if any)"
nm -gU "$BIN" > "$OUTDIR/11_exports.txt" 2>/dev/null || true

# packer/UPX detection: simple heuristics
echo "[*] Packer heuristics: checking for known packer strings"
egrep -i "upx|mpress|pez|aspack|themida|vmprotect|enigma" "$OUTDIR/08_strings_all.txt" | sort -u > "$OUTDIR/12_packer_candidates.txt" || true

# file summary
echo "Binary: $BIN" > "$OUTDIR/99_summary.txt"
echo "Created: $(date -u)" >> "$OUTDIR/99_summary.txt"
echo "file output: $(realpath "$OUTDIR")" >> "$OUTDIR/99_summary.txt"
echo "[*] Done. Inspect files in $OUTDIR"