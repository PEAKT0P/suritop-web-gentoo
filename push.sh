#!/bin/bash
set -e

cd "$(dirname "$0")"

git add -A

if git diff --cached --quiet; then
    echo "No changes to commit."
    exit 0
fi

echo "=== Changes ==="
git diff --cached --stat
echo ""

read -p "Commit message: " MSG
git commit -m "$MSG"

TOKEN=$(cat ~/tok.txt 2>/dev/null)
if [ -n "$TOKEN" ]; then
    git remote set-url origin "https://PEAKT0P:${TOKEN}@github.com/PEAKT0P/suritop-web-gentoo.git"
fi
git push origin main
git remote set-url origin https://github.com/PEAKT0P/suritop-web-gentoo.git
echo "=== Done ==="
