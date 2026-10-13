#!/bin/sh
# Shared helpers for the git hooks in this directory.

# modules_for_files: print the directory of the nearest go.mod for each path
# read from stdin, de-duplicated. "." is the root module.
modules_for_files() {
	while IFS= read -r f; do
		[ -z "$f" ] && continue
		d=$(dirname "$f")
		while [ "$d" != "." ] && [ "$d" != "/" ] && [ ! -f "$d/go.mod" ]; do
			d=$(dirname "$d")
		done
		[ -f "$d/go.mod" ] && echo "$d"
	done | sort -u
}

fail() {
	printf 'hook: %s\n' "$1" >&2
	exit 1
}

warn() {
	printf 'hook: warning: %s\n' "$1" >&2
}

# has_dash: succeed when stdin contains an em dash (U+2014) or en dash
# (U+2013). Byte match with LC_ALL=C so it works with BSD and GNU grep.
has_dash() {
	LC_ALL=C grep -q -e "$(printf '\342\200\224')" -e "$(printf '\342\200\223')"
}
