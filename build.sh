#!/bin/bash
# Build script for AI Packet Analyzer
# Creates a standalone binary for the current platform using PyInstaller

set -e

echo "=== AI Packet Analyzer Build Script ==="
echo ""

# Check Python
python3 --version || { echo "Python 3 is required"; exit 1; }

# Install build dependencies
echo "Installing build dependencies..."
pip install -r requirements.txt
pip install pyinstaller

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$OS" in
    linux*)   PLATFORM="linux" ;;
    darwin*)  PLATFORM="macos" ;;
    mingw*|msys*|cygwin*) PLATFORM="windows" ;;
    *)        PLATFORM="unknown" ;;
esac

BINARY_NAME="ai-packet-analyzer-${PLATFORM}"
if [ "$PLATFORM" = "windows" ]; then
    BINARY_NAME="ai-packet-analyzer-windows.exe"
fi

echo "Building for: ${PLATFORM} (${ARCH})"
echo "Output: dist/${BINARY_NAME}"
echo ""

# Build
pyinstaller \
    --onefile \
    --name "${BINARY_NAME}" \
    --paths src \
    --hidden-import ai_packet_analyzer \
    --hidden-import ai_packet_analyzer.cli \
    --hidden-import ai_packet_analyzer.packet_parser \
    --hidden-import ai_packet_analyzer.ai_engine \
    --hidden-import ai_packet_analyzer.report_renderer \
    --hidden-import scapy.all \
    --hidden-import scapy.layers.inet \
    --hidden-import scapy.layers.dns \
    --hidden-import scapy.layers.l2 \
    --hidden-import rich \
    --exclude-module tkinter \
    --exclude-module matplotlib \
    --exclude-module numpy \
    --clean \
    build_entry.py

echo ""
echo "=== Build Complete ==="
echo "Binary: dist/${BINARY_NAME}"
ls -lh "dist/${BINARY_NAME}"
echo ""
echo "Test with: ./dist/${BINARY_NAME} tests/pcaps/synthetic_test.pcap --mode security"
