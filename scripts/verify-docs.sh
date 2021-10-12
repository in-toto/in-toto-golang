#!/usr/bin/env bash

set -e

# Verify that generated Markdown docs are up-to-date.
tmpdir=$(mktemp -d)
go run main.go gendoc --dir "$tmpdir"
echo "###########################################"
echo "If diffs are found, run: go run ./cmd gendoc"
echo "###########################################"
diff -Naur "$tmpdir" doc/
