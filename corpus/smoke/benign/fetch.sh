#!/bin/sh
# Downloads the release notes. Benign: one URL, no shell tricks.
set -eu
URL="http://example.invalid/releases/notes.txt"
echo "fetching $URL"
