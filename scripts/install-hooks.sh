#!/bin/sh
# Install git hooks for cachekit-core development

HOOK_DIR="$(git rev-parse --git-dir)/hooks"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

cat > "$HOOK_DIR/pre-commit" << 'EOF'
#!/bin/sh
# Pre-commit hook: runs cargo fmt check

echo "Running cargo fmt --check..."
cargo fmt --check
if [ $? -ne 0 ]; then
    echo ""
    echo "ERROR: Code is not formatted. Run 'cargo fmt' and try again."
    exit 1
fi

echo "Running cargo clippy..."
cargo clippy --all-features -- -D warnings 2>/dev/null
if [ $? -ne 0 ]; then
    echo ""
    echo "ERROR: Clippy warnings found. Fix them and try again."
    exit 1
fi

echo "Pre-commit checks passed."
EOF

chmod +x "$HOOK_DIR/pre-commit"
echo "Pre-commit hook installed."
