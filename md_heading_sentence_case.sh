#!/usr/bin/env bash


# md_heading_sentence_case.sh
# 2025/09/26 Anthony Chambet
# 2025/10/28 Updated hyphen and slash combos and better regex parsing
# make markdown headings sentence-style:
# keep casing of the first meaningful word; lowercase the rest,
# while preserving acronyms and numbering. skips code fences.

set -euo pipefail

# Usage:
#   ./md_heading_sentence_case.sh input.md > output.md
#   cat input.md | ./md_heading_sentence_case.sh > output.md
#
# Behavior:
#   - Removes emojis and common pictographs from all text
#   - Normalizes Markdown heading whitespace
#   - Converts Markdown headings (#..######) to sentence case
#   - Converts list items whose first content is a bold span to sentence case
#     while preserving acronyms (2+ uppercase letters) like GPU, API, FFT, EU, EUI
#   - Skips fenced code blocks (```)
#   - Leaves other lines unchanged (aside from emoji stripping)
#
# Controls:
#   - Set PRESERVE_ALL_CAPS=1 to preserve any ALLCAPS tokens (2+ caps) fully.
#
# Exit codes:
#   0 on success, non-zero on usage or IO errors.

process_markdown() {
  perl -CSD -pe '
    use strict;
    use warnings;
    our $in_code = 0;

    # Toggle code fence state; leave line unchanged
    if (/^\s*```/) { $in_code = !$in_code; }

    # Helper sub: sentence-case with acronym preservation
    sub sentence_case_preserve_acronyms {
      my ($s) = @_;

      # Remove emojis inside target
      $s =~ s/[\x{200D}\x{FE0F}]//g;
      $s =~ s/[\x{1F1E6}-\x{1F1FF}]//g;
      $s =~ s/[\x{1F3FB}-\x{1F3FF}]//g;
      $s =~ s/[\x{2600}-\x{26FF}\x{2700}-\x{27BF}\x{1F300}-\x{1FAFF}]//g;

      # Trim and collapse spaces
      $s =~ s/^\s+|\s+$//g;
      $s =~ s/\s{2,}/ /g;

      my $preserve_all = $ENV{PRESERVE_ALL_CAPS} // q{};

      # Tokenize into alnum vs non-alnum, preserve punctuation current workaround but may not work for all contexts
      my @toks = ($s =~ /([A-Za-z0-9]+|[^A-Za-z0-9]+)/g);
      for (my $i = 0; $i <= $#toks; $i++) {
        my $t = $toks[$i];
        if ($t =~ /^[A-Za-z0-9]+$/) {
          my $uc = () = ($t =~ /[A-Z]/g);
          if ($uc >= 2) {
            unless ($preserve_all) {
              # Basically I decided to check each tokens with ALLCAPS and longer than 5 should like not be an acronym (to be investigated for a better logic)
              if ($t =~ /^[A-Z]{6,}$/) {
                $t = lc($t);
              }
            }
          } else {
            $t = lc($t);
          }
          $toks[$i] = $t;
        }
      }

      # Reassemble
      $s = join("", @toks);

      # Capitalize first letter (Unicode-ish)
      $s =~ s/^([A-Za-z])/uc($1)/e;

      return $s;
    }

    if (!$in_code) {
      # 1) Headings
      if (/^(\#{1,6})[ \t]*(.*)$/) {
        my ($h, $text) = ($1, $2);
        my $sc = sentence_case_preserve_acronyms($text);
        $_ = "$h $sc\n";
        next;
      }

      # 2) List items where the FIRST content is a bold span
      if (/^(\s*(?:\d+[\.\)]|[-+*]))\s+(\*\*)([^*]+)(\*\*)(.*)$/) {
        my ($lead, $o, $inner, $c, $rest) = ($1, $2, $3, $4, $5);
        my $sc = sentence_case_preserve_acronyms($inner);
        $_ = "$lead $o$sc$c$rest\n";
        next;
      }
    }

    # 3) Global emoji stripping for any remaining content (outside code)
    s/[\x{200D}\x{FE0F}]//g;
    s/[\x{1F1E6}-\x{1F1FF}]//g;
    s/[\x{1F3FB}-\x{1F3FF}]//g;
    s/[\x{2600}-\x{26FF}\x{2700}-\x{27BF}\x{1F300}-\x{1FAFF}]//g;
  ' "$@"
}

main() {
  if [[ $# -gt 1 ]]; then
    echo "Usage: $0 [file.md]" >&2
    exit 2
  fi

  if [[ $# -eq 1 ]]; then
    if [[ ! -f "$1" ]]; then
      echo "Error: file not found: $1" >&2
      exit 3
    fi
    process_markdown "$1"
  else
    process_markdown
  fi
}

main "$@"
