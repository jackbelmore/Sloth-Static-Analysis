#!/bin/bash
# Test script for PE malware analysis

cd /mnt/c/Users/Box/malware-analysis-tui
source venv/bin/activate

echo "=========================================="
echo "PE Malware Analysis Tool - Test Script"
echo "=========================================="
echo ""

# Function to convert Windows path to WSL path
convert_path() {
    local path="$1"

    # Check if it's a Windows path (contains backslash or starts with drive letter)
    if [[ "$path" =~ ^[A-Za-z]:\\ ]] || [[ "$path" =~ \\ ]]; then
        # Convert backslashes to forward slashes
        path="${path//\\//}"

        # Extract drive letter and convert to lowercase
        if [[ "$path" =~ ^([A-Za-z]): ]]; then
            local drive="${BASH_REMATCH[1],,}"  # Convert to lowercase
            path="${path#*:}"  # Remove drive letter and colon
            path="/mnt/$drive$path"
        fi

        echo "Converted Windows path to: $path" >&2
    fi

    echo "$path"
}

# Function to analyze a file
analyze_file() {
    local file="$1"
    local flags="$2"

    echo "Analyzing: $file"
    echo "Size: $(du -h "$file" | cut -f1)"
    echo ""

    if [[ "$flags" == *"--async"* ]]; then
        echo "Running FULL async analysis (pefile + capa + floss)..."
        echo "This may take a while..."
    else
        echo "Running fast analysis (pefile only)..."
    fi

    if [[ "$flags" == *"--verbose"* ]]; then
        echo "Mode: Verbose (detailed output)"
    else
        echo "Mode: Simple (risk assessment + summary)"
    fi

    echo "------------------------------------------"
    python cli.py "$file" $flags

    echo ""
    echo "Analysis complete!"
    echo "=========================================="
}

# Parse arguments
ASYNC_FLAG=""
VERBOSE_FLAG=""
TARGET_FILE=""

for arg in "$@"; do
    if [ "$arg" = "--async" ] || [ "$arg" = "-a" ]; then
        ASYNC_FLAG="--async"
    elif [ "$arg" = "--verbose" ] || [ "$arg" = "-v" ]; then
        VERBOSE_FLAG="--verbose"
    else
        TARGET_FILE="$arg"
    fi
done

FLAGS="$ASYNC_FLAG $VERBOSE_FLAG"

# Check if a specific file was provided
if [ -n "$TARGET_FILE" ]; then
    TARGET="$(convert_path "$TARGET_FILE")"
    if [ ! -f "$TARGET" ]; then
        echo "ERROR: File not found: $TARGET"
        exit 1
    fi
    analyze_file "$TARGET" "$FLAGS"
else
    # Default: analyze notepad.exe as a safe test
    echo "No file specified. Using notepad.exe as a safe test file."
    echo ""
    TARGET="/mnt/c/Windows/System32/notepad.exe"

    if [ ! -f "$TARGET" ]; then
        echo "ERROR: Test file not found: $TARGET"
        exit 1
    fi

    analyze_file "$TARGET" "$FLAGS"
fi

echo ""
echo "To analyze a specific file, run:"
echo "  ./test_pe.sh /path/to/file.exe"
echo "  ./test_pe.sh -a /path/to/file.exe              # Async analysis (capa + floss)"
echo "  ./test_pe.sh -a -v /path/to/file.exe           # Async + verbose mode"
echo "  ./test_pe.sh -a 'C:\\Windows\\System32\\calc.exe'"
echo ""
echo "Flags:"
echo "  -a, --async    Run capa + floss (slower but more complete)"
echo "  -v, --verbose  Detailed output (default: simple risk assessment)"
