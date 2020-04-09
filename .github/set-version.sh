#!/usr/bin/env bash

SCRIPT_BASE="$(cd "$( dirname "$0")" && pwd )"
ROOT=${SCRIPT_BASE}/..

# Exit immediatly if any command exits with a non-zero status
set -e

# Usage
print_usage() {
    echo "Set the app/add-on version"
    echo ""
    echo "Usage:"
    echo "  set-version.sh <new-version>"
    echo ""
}

# if less than one arguments supplied, display usage
if [  $# -lt 1 ]
then
    print_usage
    exit 1
fi

# check whether user had supplied -h or --help . If yes display usage
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    print_usage
    exit 0
fi

NEW_VERSION=$1

# Set version in pyproject.toml
grep -E '^version = ".+"$' "$ROOT/pyproject.toml" >/dev/null
sed -i.bak -E "s/^version = \".+\"$/version = \"$NEW_VERSION\"/" "$ROOT/pyproject.toml" && rm "$ROOT/pyproject.toml.bak"

# Set version in __init__.py
grep -E '^__version__ = ".+"$' "$ROOT/pandevice/__init__.py" >/dev/null
sed -i.bak -E "s/^__version__ = \".+\"$/__version__ = \"$NEW_VERSION\"/" "$ROOT/pandevice/__init__.py" && rm "$ROOT/pandevice/__init__.py.bak"

# Generate setup.py from pyproject.toml
make sync-deps