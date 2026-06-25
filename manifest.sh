#!/bin/bash
set -e

cd "$(dirname "$0")"

# 1. Restore Manifest (thin-manifests)
echo "# thin-manifests repo" > net-analyzer/suritop-web/Manifest

# 2. Rebuild tar.gz (exclude readme.html)
tar czf suritop-web-overlay.tar.gz \
    --transform='s,^,suritop-web-gentoo/,' \
    --exclude='readme.html' \
    net-analyzer/ metadata/ profiles/ README.md

echo "=== Manifest + tar.gz rebuilt ==="
git status -sb
