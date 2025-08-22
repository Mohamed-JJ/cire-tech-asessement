#!/bin/bash

# Selenium Test Runner Script
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🧪 Wazuh Deployment Test Suite${NC}"
echo "=================================="

# Check if we're in CI environment
if [[ "$CI" == "true" ]]; then
    echo -e "${YELLOW}Running in CI environment${NC}"
    export HEADLESS=true
    export DISPLAY=:99
    
    # Start Xvfb for headless testing
    if command -v Xvfb >/dev/null 2>&1; then
        echo "Starting virtual display..."
        Xvfb :99 -screen 0 1920x1080x24 &
        XVFB_PID=$!
        sleep 2
    fi
fi

# Set default test configuration
export WAZUH_HOST=${WAZUH_HOST:-"localhost"}
export WAZUH_PORT=${WAZUH_PORT:-"80"}
export WAZUH_DASHBOARD_PORT=${WAZUH_DASHBOARD_PORT:-"5601"}
export WAZUH_API_PORT=${WAZUH_API_PORT:-"55000"}
export TEST_TIMEOUT=${TEST_TIMEOUT:-"30"}

# Load environment variables if .env file exists
if [[ -f "tests/.env" ]]; then
    echo -e "${YELLOW}Loading environment from tests/.env${NC}"
    set -o allexport
    source tests/.env
    set +o allexport
fi

# Create reports directory
mkdir -p tests/reports

echo -e "${YELLOW}Test Configuration:${NC}"
echo "  Host: $WAZUH_HOST"
echo "  Port: $WAZUH_PORT"
echo "  Dashboard Port: $WAZUH_DASHBOARD_PORT"
echo "  API Port: $WAZUH_API_PORT"
echo "  Timeout: $TEST_TIMEOUT seconds"
echo ""

# Check if Python virtual environment exists
if [[ ! -d "tests/venv" ]]; then
    echo -e "${YELLOW}Creating Python virtual environment...${NC}"
    python3 -m venv tests/venv
fi

# Activate virtual environment
source tests/venv/bin/activate

# Install/upgrade dependencies
echo -e "${YELLOW}Installing test dependencies...${NC}"
pip install --upgrade pip
pip install -r tests/requirements.txt

# Install Chrome/Chromium for Selenium (if not in CI with pre-installed)
if [[ "$CI" != "true" ]]; then
    if ! command -v google-chrome >/dev/null 2>&1 && ! command -v chromium-browser >/dev/null 2>&1; then
        echo -e "${YELLOW}Chrome/Chromium not found. Please install Chrome or Chromium browser.${NC}"
        echo "Ubuntu/Debian: sudo apt-get install chromium-browser"
        echo "CentOS/RHEL: sudo yum install chromium"
        echo "macOS: brew install --cask google-chrome"
    fi
fi

# Run different test suites based on arguments
TEST_SUITE=${1:-"all"}

case "$TEST_SUITE" in
    "smoke")
        echo -e "${GREEN}Running smoke tests...${NC}"
        pytest tests/test_wazuh_deployment.py::TestWazuhDeployment::test_api_health_probe \
               tests/test_wazuh_deployment.py::TestWazuhDeployment::test_wazuh_dashboard_https_reachable \
               -v --tb=short
        ;;
    "ui")
        echo -e "${GREEN}Running UI tests...${NC}"
        pytest tests/test_wazuh_deployment.py::TestWazuhDeployment::test_wazuh_dashboard_https_reachable \
               tests/test_wazuh_deployment.py::TestWazuhDeployment::test_dashboard_via_nginx_proxy \
               tests/test_wazuh_deployment.py::TestWazuhDeployment::test_page_title_and_login_elements \
               tests/test_wazuh_deployment.py::TestWazuhDeployment::test_programmatic_login_and_landing_page \
               -v --tb=short -m ui
        ;;
    "api")
        echo -e "${GREEN}Running API tests...${NC}"
        pytest tests/test_wazuh_deployment.py::TestWazuhDeployment::test_api_health_probe \
               tests/test_wazuh_deployment.py::TestWazuhDeployment::test_nginx_proxy_health \
               -v --tb=short -m api
        ;;
    "integration"|"all")
        echo -e "${GREEN}Running full test suite...${NC}"
        pytest tests/test_wazuh_deployment.py -v --tb=short
        ;;
    *)
        echo -e "${RED}Unknown test suite: $TEST_SUITE${NC}"
        echo "Available options: smoke, ui, api, integration, all"
        exit 1
        ;;
esac

TEST_EXIT_CODE=$?

# Cleanup
if [[ "$CI" == "true" ]] && [[ -n "$XVFB_PID" ]]; then
    echo "Stopping virtual display..."
    kill $XVFB_PID 2>/dev/null || true
fi

# Generate test report summary
if [[ -f "tests/reports/test_report.html" ]]; then
    echo -e "${GREEN}Test report generated: tests/reports/test_report.html${NC}"
fi

# Exit with test result
if [[ $TEST_EXIT_CODE -eq 0 ]]; then
    echo -e "${GREEN}✅ All tests passed!${NC}"
else
    echo -e "${RED}❌ Some tests failed!${NC}"
fi

exit $TEST_EXIT_CODE
