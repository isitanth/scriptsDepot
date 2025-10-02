#!/usr/bin/env python3
"""
python_macho_inspect.py
-----------------------------------------------------------------------------
Author : Anthony Chambet — Solution Architect
Date   : 2025-10-02
Purpose: Structural Mach-O analyser using LIEF. Produces JSON with segments,
         imports, symbols and a short list of "interesting" strings.
Usage  : python3 python_macho_inspect.py /path/to/bin out.json
License: MIT
-----------------------------------------------------------------------------
"""

import sys
import json
from pathlib import Path

try:
	import lief
except Exception as e:
	print("LIEF import failed:", e)
	print("Install with: pip install lief")
	sys.exit(2)

def analyze(path):
	m = lief.parse(str(path))
	out = {}
	out['file'] = str(path)
	out['format'] = 'MACHO' if isinstance(m, lief.MachO.Binary) else type(m).__name__
	# architectures (fat / slices)
	try:
		out['is_fat'] = m.is_fat
	except AttributeError:
		out['is_fat'] = False

	out['header'] = {
		'entrypoint': hex(m.entrypoint),
		'arch': str(m.header.cpu_type).split('.')[-1] if hasattr(m, 'header') else None,
		'ncommands': getattr(m.header, "numberof_commands", None)
	}

	# segments and sections
	out['segments'] = []
	for seg in m.segments:
		s = {'name': seg.name, 'vmaddr': hex(seg.virtual_address), 'vmsize': seg.virtual_size, 'sections': []}
		for sec in seg.sections:
			s['sections'].append({'name': sec.name, 'size': sec.size, 'offset': sec.offset})
		out['segments'].append(s)

	# imports (dylibs)
	out['dylibs'] = [{'name': d.name, 'version': getattr(d, 'version', None)} for d in getattr(m, 'imports', [])] \
		if hasattr(m, 'imports') else [ {'name': d.name} for d in m.libraries ]

	# symbols
	out['symbols'] = []
	for sym in m.symbols:
		out['symbols'].append({'name': sym.name, 'value': hex(sym.value) if sym.value else None, 'type': str(sym.type)})

	# exported symbols
	try:
		out['exports'] = [e.name for e in m.exported_functions]
	except Exception:
		out['exports'] = []

	# heuristics: objc runtime / selectors heuristics via strings
	try:
		strings = set(x.string for x in m.strings)
	except Exception:
		# fallback: scan whole binary
		with open(path, 'rb') as f:
			data = f.read()
		import re
		strings = set([s.decode('latin1') for s in re.findall(rb'[\x20-\x7E]{4,}', data)])

	# quick interesting strings
	keywords = ['password','passwd','api','token','secret','http','https','aws','s3','BEGIN RSA','objc_msgSend','_OBJC_CLASS_']
	out['interesting_strings'] = [s for s in strings if any(k.lower() in s.lower() for k in keywords)]
	out['objc_candidates'] = [s for s in strings if 'objc' in s.lower() or 'objc_msgSend' in s or '_OBJC_CLASS_' in s]

	return out

def main():
	if len(sys.argv) < 3:
		print("Usage: python3 python_macho_inspect.py /path/to/binary out.json")
		sys.exit(1)
	path = Path(sys.argv[1])
	outpath = Path(sys.argv[2])
	res = analyze(path)
	outpath.write_text(json.dumps(res, indent=2))
	print("Wrote", outpath)

if __name__ == "__main__":
	main()