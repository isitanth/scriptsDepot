# ida_analyze_macho.py
# -----------------------------------------------------------------------------
# Author : Anthony Chambet — Solution Architect
# Date   : 2025-10-02
# Purpose: Lightweight IDAPython heuristics: mark interesting strings, detect
#          ObjC selectors and add function comments for quick triage.
# Notes  : Run inside IDA (File -> Script file...). Does not patch the binary.
# -----------------------------------------------------------------------------

import idaapi
import idautils
import idc

def banner(msg):
	print("[IDA ANALYZE] " + msg)

banner("Starting analysis heuristics...")

# collect strings with address
strings = [(s.ea, str(s), s.length) for s in idautils.Strings()]

# mark likely interesting strings
keywords = ["password","token","secret","api","http://","https://","Authorization","BEGIN RSA","objc_msgSend","_OBJC_CLASS_"]
for ea, s, ln in strings:
	lower = s.lower()
	if any(k.lower() in lower for k in keywords):
		# add a code xref comment for easy find
		idc.set_cmt(ea, "INTERESTING_STRING: {}".format(s), 0)
		print("Interesting string at 0x{:X}: {}".format(ea, s))

# find imported functions (DLL imports)
banner("Listing imports:")
for imp in idautils.ImportEntries():
	print("Import: {} -> {} @ 0x{:X}".format(imp.name, imp.module, imp.ea))

# try to find objc class names (objc runtime uses __objc_classname etc.)
banner("Searching for ObjC classes/selectors...")
for ea, s, ln in strings:
	if 'objc' in s.lower() or s.startswith('-[') or s.startswith('+[') or s.endswith(':'):
		idc.set_cmt(ea, "OBJC_CANDIDATE: {}".format(s), 0)

# heuristics to mark functions that call objc_msgSend or have many objc-like strings nearby
for func_ea in idautils.Functions():
	func = idaapi.get_func(func_ea)
	if not func: continue
	calls_objc = False
	for head in idautils.FuncItems(func_ea):
		mnem = idc.print_insn_mnem(head)
		opnds = idc.generate_disasm_line(head, 0)
		if 'objc_msgSend' in opnds or 'objc' in opnds.lower():
			calls_objc = True
			break
	if calls_objc:
		idc.set_func_cmt(func_ea, "LIKELY_OBJC_BRIDGE", 1)
		print("Function 0x{:X} likely ObjC bridge".format(func_ea))

banner("Finished. Use 'Strings window', and the 'Search' for comments 'INTERESTING_STRING' or 'OBJC_CANDIDATE'.")