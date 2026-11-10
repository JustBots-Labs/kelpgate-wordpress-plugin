#!/usr/bin/env bash
# Builds the zip users install in WordPress admin: Plugins > Add New > Upload Plugin.
#
#   ./package.sh [output-dir]      default output directory: ./dist
#
# Output: <output-dir>/kelpgate-wordpress-plugin-<version>.zip (+ .sha256)
#
# The zip contains exactly ONE top-level folder, `kelpgate-wordpress-plugin/`, with the main plugin file
# directly inside it. That is the layout WordPress requires; a repository download (nested or renamed
# folder, dev files) is not installable the same way. Only an explicit allowlist of files is packaged,
# and the result is checked before the script succeeds.
set -euo pipefail

SLUG="kelpgate-wordpress-plugin"
MAIN="$SLUG.php"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-$SCRIPT_DIR/dist}"
INCLUDE=("$MAIN" uninstall.php includes assets LICENSE README.md readme.txt)

fail() { echo "package.sh: $*" >&2; exit 1; }

# The version in the plugin header (what WordPress shows) must match the constant the code uses.
HEADER_VERSION="$(sed -n 's/^ \* Version: *//p' "$SCRIPT_DIR/$MAIN" | head -1 | tr -d '[:space:]')"
CONST_VERSION="$(sed -n "s/^define('KELPGATE_VERSION', '\([^']*\)');.*/\1/p" "$SCRIPT_DIR/$MAIN" | head -1)"
[ -n "$HEADER_VERSION" ] || fail "no Version header found in $MAIN"
[ "$HEADER_VERSION" = "$CONST_VERSION" ] || fail "header version ($HEADER_VERSION) differs from KELPGATE_VERSION ($CONST_VERSION)"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
mkdir -p "$TMP_DIR/$SLUG" "$OUTPUT_DIR"
for item in "${INCLUDE[@]}"; do
  [ -e "$SCRIPT_DIR/$item" ] || fail "missing $item"
  cp -R "$SCRIPT_DIR/$item" "$TMP_DIR/$SLUG/"
done
find "$TMP_DIR" \( -name '.DS_Store' -o -name '*.log' \) -delete

ZIP="$(cd "$OUTPUT_DIR" && pwd)/$SLUG-$HEADER_VERSION.zip"
rm -f "$ZIP" "$ZIP.sha256"
(cd "$TMP_DIR" && zip -qr -X "$ZIP" "$SLUG")

# --- verify what will actually be uploaded ---
LISTING="$(unzip -Z1 "$ZIP")"
TOPS="$(printf '%s\n' "$LISTING" | cut -d/ -f1 | sort -u)"
[ "$TOPS" = "$SLUG" ] || fail "zip must have one top-level folder named $SLUG, found: $TOPS"
printf '%s\n' "$LISTING" | grep -qx "$SLUG/$MAIN" || fail "$SLUG/$MAIN is not at the top of the plugin folder"
unzip -p "$ZIP" "$SLUG/$MAIN" | grep -q "^ \* Plugin Name:" || fail "plugin header missing from $MAIN"
if printf '%s\n' "$LISTING" | grep -E "(^|/)(package\.sh|composer\.json|\.git[^/]*|\.github|dist)(/|$)" >/dev/null; then
  fail "development files ended up in the zip"
fi

if command -v sha256sum >/dev/null 2>&1; then SUM="$(sha256sum "$ZIP" | cut -d' ' -f1)"; else SUM="$(shasum -a 256 "$ZIP" | cut -d' ' -f1)"; fi
echo "$SUM  $(basename "$ZIP")" > "$ZIP.sha256"

echo "Built $ZIP"
echo "  version $HEADER_VERSION, $(printf '%s\n' "$LISTING" | grep -vc '/$') files, sha256 $SUM"
