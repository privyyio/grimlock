#!/bin/bash

# Grimlock Test Runner Script
# This script makes it easy to run the Grimlock test suite

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo ""
echo "🔐 Grimlock Crypto Module Test Runner"
echo "======================================"
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo -e "${RED}Error: Node.js is not installed${NC}"
    echo "Please install Node.js from https://nodejs.org/"
    exit 1
fi

echo -e "${GREEN}✓${NC} Node.js found: $(node --version)"

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo -e "${RED}Error: npm is not installed${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} npm found: $(npm --version)"

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo ""
    echo -e "${YELLOW}⚠${NC} node_modules not found. Installing dependencies..."
    npm install
    echo ""
fi

# Check if dependencies are installed
if [ ! -d "node_modules/ts-node" ]; then
    echo ""
    echo -e "${YELLOW}⚠${NC} Installing development dependencies..."
    npm install --save-dev typescript ts-node @types/node
    echo ""
fi

# Run the tests
echo ""
echo "Running tests..."
echo ""

if npm test; then
    echo ""
    echo -e "${GREEN}✓ Test suite completed successfully!${NC}"
    exit 0
else
    echo ""
    echo -e "${RED}✗ Test suite failed!${NC}"
    exit 1
fi
