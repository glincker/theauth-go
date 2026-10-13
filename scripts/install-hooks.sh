#!/bin/sh
# Points git at the tracked hooks in .githooks. Run once per clone.
set -e
cd "$(git rev-parse --show-toplevel)"
git config core.hooksPath .githooks
echo "git hooks installed from .githooks (pre-commit, commit-msg, pre-push)"
echo "bypass in an emergency: THEAUTH_SKIP_HOOKS=1 git push"
