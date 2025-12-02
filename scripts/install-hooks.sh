#!/bin/bash
# Install Git Hooks for Moon-Gazing-Tower

set -e

HOOKS_DIR=".git/hooks"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -d .git ]; then
    echo "Error: Not a Git repository"
    exit 1
fi

echo "Installing pre-push hook..."
cat > "$HOOKS_DIR/pre-push" << 'EOF'
#!/bin/bash
# Pre-push hook - Prevent pushing broken code

set -e

echo "Running pre-push validation..."
make pre-push

exit 0
EOF

chmod +x "$HOOKS_DIR/pre-push"

echo "✓ Git hooks installed successfully"
echo ""
echo "To skip hooks: git push --no-verify"
