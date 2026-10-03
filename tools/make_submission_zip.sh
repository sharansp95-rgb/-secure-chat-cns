#!/bin/bash
# Build a clean submission archive from TRACKED files only:
#
#     tools/make_submission_zip.sh          ->  dist/Team15_SecureChat_submission.zip
#
# It uses `git archive HEAD`, so anything untracked or ignored can never be included:
# .venv/, .git/, data/ (user store + private keys), certs/*.key and *.crt, logs/, exports/,
# CnsProj/, _to_delete/, the review .pptx, __MACOSX and .DS_Store. Commit your changes first:
# uncommitted edits are not in HEAD, and the script refuses to run with any.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "Uncommitted changes to tracked files: commit them first (git archive packs HEAD)." >&2
    git status --short --untracked-files=no >&2
    exit 1
fi

OUT_DIR=dist
ZIP="$OUT_DIR/Team15_SecureChat_submission.zip"
mkdir -p "$OUT_DIR"
rm -f "$ZIP"
git archive --format=zip --prefix=Team15_SecureChat/ -o "$ZIP" HEAD

# Safety net: refuse to hand out an archive containing anything sensitive or bulky.
BAD="$(unzip -Z1 "$ZIP" | grep -E '(^|/)(\.venv|\.git|data|logs|exports|CnsProj|_to_delete|__MACOSX|dist)/|\.(key|crt|pem|pptx)$|\.DS_Store$' || true)"
if [ -n "$BAD" ]; then
    echo "REFUSING: the archive contains files that must not be submitted:" >&2
    echo "$BAD" >&2
    rm -f "$ZIP"
    exit 1
fi
echo "Built $ZIP ($(unzip -Z1 "$ZIP" | grep -vc '/$') files, $(du -h "$ZIP" | cut -f1))"
echo "Contains no keys, certificates, user data, logs, exports, CnsProj, .pptx or virtualenv."
