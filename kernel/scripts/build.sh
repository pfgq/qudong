#!/bin/bash
# TearGame Build Script
# Usage: ./build.sh [kernel_dir] [cross_compile_prefix]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Default values
KERNEL_DIR="${1:-/lib/modules/$(uname -r)/build}"
CROSS_COMPILE="${2:-}"
ARCH="arm64"
JOBS=$(nproc)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  TearGame Kernel Module Build Script  ${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check kernel directory
if [ ! -d "$KERNEL_DIR" ]; then
    echo -e "${RED}Error: Kernel directory not found: $KERNEL_DIR${NC}"
    echo "Usage: $0 [kernel_dir] [cross_compile_prefix]"
    exit 1
fi

echo -e "${YELLOW}Configuration:${NC}"
echo "  Project Dir:   $PROJECT_DIR"
echo "  Kernel Dir:    $KERNEL_DIR"
echo "  Architecture:  $ARCH"
echo "  Cross Compile: ${CROSS_COMPILE:-native}"
echo "  Parallel Jobs: $JOBS"
echo ""

# Clean previous build
echo -e "${YELLOW}Cleaning previous build...${NC}"
cd "$PROJECT_DIR"
make clean 2>/dev/null || true

# Build module
echo -e "${YELLOW}Building module...${NC}"
make -j$JOBS \
    ARCH=$ARCH \
    CROSS_COMPILE=$CROSS_COMPILE \
    KDIR=$KERNEL_DIR

# Check result
if [ -f "$PROJECT_DIR/teargame.ko" ]; then
    echo ""
    echo -e "${GREEN}Build successful!${NC}"
    echo ""
    echo "Module info:"
    file "$PROJECT_DIR/teargame.ko"
    echo ""
    ls -lh "$PROJECT_DIR/teargame.ko"
    echo ""
    echo "To load the module:"
    echo "  insmod teargame.ko"
    echo ""
    echo "To unload the module:"
    echo "  rmmod teargame"
else
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi
