#!/bin/bash
# Test script to analyze Boom3D.msi

cd /mnt/c/Users/Box/malware-analysis-tui
source venv/bin/activate

echo "=========================================="
echo "Testing Malware Analysis on Boom3D.msi"
echo "=========================================="
echo ""

TARGET="/mnt/c/Users/Box/Desktop/Boom3D.msi"

if [ ! -f "$TARGET" ]; then
    echo "ERROR: File not found: $TARGET"
    exit 1
fi

echo "File: $TARGET"
echo ""

echo "Running fast analysis (pefile only)..."
echo "=========================================="
python cli.py "$TARGET"

echo ""
echo ""
echo "=========================================="
echo "Would you like to run async analysis? (y/n)"
echo "Note: This requires capa rules to be installed"
echo "Press Ctrl+C to skip, or wait 5 seconds..."
read -t 5 -n 1 response

if [[ $response =~ ^[Yy]$ ]]; then
    echo ""
    echo "Running async analysis (capa + floss)..."
    echo "=========================================="
    python cli.py "$TARGET" --async
fi

echo ""
echo "=========================================="
echo "Analysis complete!"
echo "=========================================="
