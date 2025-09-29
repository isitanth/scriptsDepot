#!/usr/bin/env bash
# md_heading_sentence_case.sh
# make markdown headings sentence-style:
# keep casing of the first meaningful word; lowercase the rest,
# while preserving acronyms and numbering. skips code fences.

set -euo pipefail

usage() {
  cat <<EOF
usage: $0 [-i] [FILE...]
  without -i: reads files (or stdin) and writes to stdout
  with    -i: edits files in place (creates .bak backups)
examples:
  $0 README.md
  $0 -i README.md docs/*.md
  cat README.md | $0
EOF
}

inplace=0
if [[ "${1:-}" == "-i" ]]; then
  inplace=1
  shift
fi

process() {
  awk '
  function is_code_fence(line) { return line ~ /^(```|~~~)/ }
  function is_heading(line)    { return line ~ /^[[:space:]]*#{1,6}[[:space:]]+/ }

  # token helpers (POSIX awk compatible)
  function strip_trailing_punct(t,    u) {
	# remove trailing punctuation commonly found in titles, keep / and - in place
	u = t
	sub(/[[:punct:]]+$/, "", u)
	return u
  }
  function is_number_token(t) {
	# matches: 4, 4., 4), IV, IV), 2025.
	return t ~ /^([0-9]+|[IVXLCDM]+)([.)])?$/
  }
  function is_acronym(t,    core) {
	# allow separators - or / inside, but no lowercase letters
	core = t
	# drop trailing punctuation for the test
	sub(/[[:punct:]]+$/, "", core)
	# at least one upper/digit; allow grouped segments joined by - or /
	# BSD awk-safe: put - at start to avoid range
	return core ~ /^[[:upper:][:digit:]]+([-\/][[:upper:][:digit:]]+)*$/ && core !~ /[[:lower:]]/
  }

  BEGIN { in_code=0 }
  {
	line = $0

	if (is_code_fence(line)) { in_code = !in_code; print line; next }
	if (in_code) { print line; next }

	if (!is_heading(line)) { print line; next }

	# split prefix (hashes + spaces) and text
	match(line, /^[[:space:]]*(#{1,6}[[:space:]]+)/)
	prefix = substr(line, 1, RLENGTH)
	text   = substr(line, RLENGTH+1)

	# split on spaces; keep simple spacing
	n = split(text, tok, /[ ]+/)
	out = ""
	first_kept = 0

	for (i = 1; i <= n; i++) {
	  t = tok[i]
	  if (t == "") { continue }

	  if (!first_kept) {
		if (is_number_token(t)) {
		  out = (out ? out " " : "") t
		  continue
		} else {
		  # first meaningful token: keep as-is
		  out = (out ? out " " : "") t
		  first_kept = 1
		  continue
		}
	  } else {
		# after the first word: keep acronyms as-is, lowercase everything else
		if (is_acronym(t)) {
		  out = out " " t
		} else {
		  # preserve any trailing punctuation by lowercasing core then reattaching
		  core = t
		  trail = ""
		  if (core ~ /[[:punct:]]+$/) {
			# capture trailing punctuation
			match(core, /[[:punct:]]+$/)
			trail = substr(core, RSTART, RLENGTH)
			core = substr(core, 1, RSTART-1)
		  }
		  out = out " " tolower(core) trail
		}
	  }
	}

	print prefix out
  }'
}

if (( inplace == 1 )); then
  if (( $# == 0 )); then usage >&2; exit 1; fi
  for f in "$@"; do
	[[ -f "$f" ]] || { echo "not a file: $f" >&2; continue; }
	cp -f -- "$f" "$f.bak"
	process <"$f.bak" >"$f"
  done
else
  if (( $# == 0 )); then
	process
  else
	for f in "$@"; do process <"$f"; done
  fi
fi