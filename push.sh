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

# 3. Stage everything
git add -A

# 4. Check if there are changes
if git diff --cached --quiet; then
    echo "No changes to commit."
    exit 0
fi

# 5. Show what will be committed
echo "=== Changes ==="
git diff --cached --stat
echo ""

# 6. Commit
read -p "Commit message: " MSG
git commit -m "$MSG"

# 7. Push
git push origin main
echo "=== Done ==="
