#!/bin/bash

# Grimlock Cross-Compatibility Test Suite
# ========================================
# This script runs comprehensive cross-compatibility tests between
# Go and TypeScript implementations of Grimlock.

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Grimlock Cross-Compatibility Test Suite                  ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Create test-data directory if it doesn't exist
mkdir -p test-data

# Track test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to print section headers
print_section() {
    echo ""
    echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${PURPLE}  $1${NC}"
    echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# Function to run a test step
run_test() {
    local test_name="$1"
    local command="$2"
    
    echo -e "${BLUE}▶ ${test_name}${NC}"
    
    if eval "$command"; then
        echo -e "${GREEN}✓ ${test_name} passed${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        echo -e "${RED}✗ ${test_name} failed${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# ============================================================================
# Phase 1: Setup and Dependencies
# ============================================================================
print_section "Phase 1: Setup and Dependencies"

echo -e "${YELLOW}Installing dependencies...${NC}"

# Install Go dependencies
echo "  • Installing Go dependencies for generator..."
cd go-generator
go mod download 2>/dev/null || true
cd ..

echo "  • Installing Go dependencies for verifier..."
cd go-verifier
go mod download 2>/dev/null || true
cd ..

# Install and build TypeScript grimlock first (needed by generator/verifier)
echo "  • Installing TypeScript grimlock dependencies..."
cd ../typescript/grimlock
if [ ! -f "package.json" ]; then
  echo "Error: package.json not found in typescript/grimlock"
  exit 1
fi
npm install || {
  echo "Error: Failed to install grimlock dependencies"
  exit 1
}
echo "  • Building TypeScript grimlock..."
npm run build || {
  echo "Error: Failed to build grimlock"
  exit 1
}
if [ ! -d "dist" ]; then
  echo "Error: dist directory not found after build"
  exit 1
fi
cd ../../cross-compatibility-testing

# Install TypeScript dependencies (after grimlock is built)
echo "  • Installing TypeScript dependencies for generator..."
cd ts-generator
if [ ! -f "package.json" ]; then
  echo "Error: package.json not found in ts-generator"
  exit 1
fi
# Verify grimlock package is built and accessible
if [ ! -d "../../typescript/grimlock/dist" ]; then
  echo "Error: grimlock dist directory not found. Build may have failed."
  exit 1
fi
npm install || {
  echo "Error: Failed to install generator dependencies"
  echo "Attempting to show npm error details..."
  npm install --loglevel=error
  exit 1
}
cd ..

echo "  • Installing TypeScript dependencies for verifier..."
cd ts-verifier
if [ ! -f "package.json" ]; then
  echo "Error: package.json not found in ts-verifier"
  exit 1
fi
npm install || {
  echo "Error: Failed to install verifier dependencies"
  echo "Attempting to show npm error details..."
  npm install --loglevel=error
  exit 1
}
cd ..

echo -e "${GREEN}✓ All dependencies installed${NC}"

# ============================================================================
# Phase 2: Generate Test Data
# ============================================================================
print_section "Phase 2: Generate Test Data"

TOTAL_TESTS=$((TOTAL_TESTS + 2))

# Generate test data using Go
run_test "Generate test data with Go" "cd go-generator && go run main.go && cd .."

# Generate test data using TypeScript
run_test "Generate test data with TypeScript" "cd ts-generator && npm run generate && cd .."

# ============================================================================
# Phase 3: Verify Cross-Compatibility
# ============================================================================
print_section "Phase 3: Verify Cross-Compatibility"

TOTAL_TESTS=$((TOTAL_TESTS + 2))

# Verify Go-generated data with TypeScript
run_test "Verify Go data with TypeScript" "cd ts-verifier && npm run verify && cd .."

# Verify TypeScript-generated data with Go
run_test "Verify TypeScript data with Go" "cd go-verifier && go run main.go && cd .."

# ============================================================================
# Phase 4: Summary
# ============================================================================
print_section "Phase 4: Test Summary"

echo -e "Total Tests:  ${BLUE}${TOTAL_TESTS}${NC}"
echo -e "Passed:       ${GREEN}${PASSED_TESTS}${NC}"
echo -e "Failed:       ${RED}${FAILED_TESTS}${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✓ All cross-compatibility tests passed!                  ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    exit 0
else
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ✗ Some cross-compatibility tests failed!                 ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    exit 1
fi
