#!/bin/bash
# Install Git Hooks

set -e

HOOKS_DIR=".git/hooks"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -d .git ]; then
    echo "Error: Not a Git repository"
    exit 1
fi

echo "Installing pre-commit hook..."
cp "$SCRIPT_DIR/pre-commit" "$HOOKS_DIR/pre-commit"
chmod +x "$HOOKS_DIR/pre-commit"

echo "✓ Hooks installed successfully"
echo ""
echo "To skip hooks: git commit --no-verify"
