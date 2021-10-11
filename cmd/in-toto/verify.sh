#!/usr/bin/env bash

set -e

# Verify that generated Markdown docs are up-to-date.
tmpdir=$(mktemp -d)
go run ./cmd/in-toto gendoc --dir "$tmpdir"
echo "###########################################"
echo "If diffs are found, run: go run ./cmd/in-toto gendoc"
echo "###########################################"
diff -Naur "$tmpdir" doc/
