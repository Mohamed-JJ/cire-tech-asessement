# Testing Documentation

This document provides comprehensive testing guidelines for the Wazuh SOC deployment project, including test suites, execution strategies, and best practices.

## 🧪 Testing Overview

The project includes multiple test categories designed to validate different aspects of the Wazuh SOC deployment:

- **Smoke Tests**: Basic service availability and connectivity
- **API Tests**: Backend service health and API endpoint validation
- **UI Tests**: Web dashboard functionality and user interface testing
- **Integration Tests**: End-to-end workflow validation
- **Security Tests**: Authentication and authorization validation

## 📋 Test Structure

### Test Directory Structure

```
tests/
├── pytest.ini                     # Pytest configuration
├── requirements.txt               # Test dependencies
├── run_tests.sh                   # Test execution script
├── test_wazuh_deployment.py       # Main test suite
├── .env.example                   # Environment configuration template
├── .env                          # Local environment variables (create from .env.example)
├── reports/                      # Generated test reports
│   ├── test_report.html         # HTML test report
│   ├── junit.xml               # JUnit XML report
│   └── coverage.xml            # Coverage report
└── __pycache__/                 # Python cache files
```

### Test Categories

#### 🔥 Smoke Tests
Quick validation of basic service availability:

```python
# Services reachable
- test_wazuh_dashboard_https_reachable
- test_dashboard_via_nginx_proxy
- test_api_health_probe
- test_nginx_proxy_health
```

#### 🌐 API Tests
Backend service validation:

```python
# API endpoint health
- test_api_health_probe
- test_wazuh_manager_api_status
- test_indexer_cluster_health
- test_api_authentication
```

#### 🖥️ UI Tests
Web dashboard functionality:

```python
# Dashboard interface
- test_page_title_and_login_elements
- test_programmatic_login_and_landing_page
- test_dashboard_navigation
- test_dashboard_responsiveness
```

#### 🔒 Security Tests
Authentication and security validation:

```python
# Security validations
- test_ssl_certificate_validity
- test_authentication_required
- test_unauthorized_access_blocked
- test_password_policy_enforcement
```

## ⚙️ Test Configuration

### Environment Variables

Create `tests/.env` from `tests/.env.example`:

```bash
# Wazuh Service Configuration
WAZUH_HOST=localhost
WAZUH_PORT=80
WAZUH_DASHBOARD_PORT=5601
WAZUH_API_PORT=55000
WAZUH_INDEXER_PORT=9200

# Authentication
WAZUH_TEST_USERNAME=kibanaserver
WAZUH_TEST_PASSWORD=MyS3cr3tP450r.-*
WAZUH_ADMIN_USERNAME=admin
WAZUH_ADMIN_PASSWORD=SecretPassword

# Test Configuration
TEST_TIMEOUT=30
HEADLESS=true
CI=false
WAZUH_USE_HTTPS=true

# Browser Configuration (Selenium)
SELENIUM_DRIVER=chrome
BROWSER_WINDOW_SIZE=1920x1080
BROWSER_HEADLESS=true
```

### Pytest Configuration

The `pytest.ini` file contains test execution settings:

```ini
[tool:pytest]
testpaths = .
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = 
    -v
    --tb=short
    --strict-markers
    --html=reports/test_report.html
    --self-contained-html
    --junit-xml=reports/junit.xml
markers =
    smoke: Basic smoke tests for service availability
    api: API endpoint and backend service tests
    ui: User interface and browser-based tests
    integration: End-to-end integration tests
    security: Security and authentication tests
    slow: Tests that take longer to execute
```

## 🚀 Running Tests

### Test Execution Script

Use the provided `run_tests.sh` script for easy test execution:

```bash
# Run all tests
./tests/run_tests.sh

# Run specific test categories
./tests/run_tests.sh smoke    # Quick smoke tests
./tests/run_tests.sh api      # API tests only
./tests/run_tests.sh ui       # UI tests only
./tests/run_tests.sh security # Security tests only

# Run with specific options
./tests/run_tests.sh --verbose
./tests/run_tests.sh --parallel
./tests/run_tests.sh --report-only
```

### Manual Pytest Execution

```bash
# Install test dependencies
pip install -r tests/requirements.txt

# Run all tests
pytest tests/ -v

# Run specific test markers
pytest tests/ -m "smoke" -v
pytest tests/ -m "api" -v  
pytest tests/ -m "ui" -v

# Run specific test files
pytest tests/test_wazuh_deployment.py -v

# Run specific test methods
pytest tests/test_wazuh_deployment.py::TestWazuhDeployment::test_api_health_probe -v

# Generate HTML report
pytest tests/ --html=reports/test_report.html --self-contained-html

# Run with coverage
pytest tests/ --cov=. --cov-report=html --cov-report=xml
```

### Parallel Test Execution

```bash
# Install pytest-xdist for parallel execution
pip install pytest-xdist

# Run tests in parallel
pytest tests/ -n auto                    # Auto-detect CPU cores
pytest tests/ -n 4                      # Use 4 workers
pytest tests/ -n auto --dist worksteal  # Work stealing distribution
```

## 🔧 Test Development

### Writing New Tests

#### Test Class Structure

```python
import pytest
from selenium import webdriver
import requests

class TestNewFeature:
    """Test suite for new feature validation"""
    
    @pytest.fixture(scope="class")
    def test_config(self):
        """Load test configuration"""
        return {
            'host': os.getenv('WAZUH_HOST', 'localhost'),
            'timeout': int(os.getenv('TEST_TIMEOUT', '30'))
        }
    
    @pytest.mark.smoke
    def test_basic_functionality(self, test_config):
        """Test basic functionality"""
        # Test implementation
        pass
    
    @pytest.mark.api
    def test_api_endpoint(self, test_config):
        """Test API endpoint"""
        response = requests.get(f"http://{test_config['host']}/api/endpoint")
        assert response.status_code == 200
    
    @pytest.mark.ui
    def test_ui_element(self, selenium_driver, test_config):
        """Test UI element"""
        selenium_driver.get(f"http://{test_config['host']}")
        # UI test implementation
        pass
```

#### Test Markers

Use pytest markers to categorize tests:

```python
@pytest.mark.smoke        # Quick smoke tests
@pytest.mark.api          # API tests
@pytest.mark.ui           # UI tests
@pytest.mark.integration  # Integration tests
@pytest.mark.security     # Security tests
@pytest.mark.slow         # Long-running tests
@pytest.mark.skip         # Skip test
@pytest.mark.skipif       # Conditional skip
@pytest.mark.parametrize  # Parameterized tests
```

### Fixtures and Utilities

#### Common Fixtures

```python
@pytest.fixture(scope="session")
def selenium_driver():
    """Setup Chrome WebDriver"""
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    driver = webdriver.Chrome(options=options)
    yield driver
    driver.quit()

@pytest.fixture(scope="session")
def api_client():
    """Setup API client with authentication"""
    return APIClient(
        base_url=os.getenv('WAZUH_HOST'),
        username=os.getenv('WAZUH_ADMIN_USERNAME'),
        password=os.getenv('WAZUH_ADMIN_PASSWORD')
    )
```

#### Utility Functions

```python
def wait_for_service(url, timeout=30):
    """Wait for service to be available"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return True
        except:
            time.sleep(1)
    return False

def take_screenshot(driver, name):
    """Take screenshot for debugging"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/screenshots/{name}_{timestamp}.png"
    driver.save_screenshot(filename)
    return filename
```

## 🎯 Test Strategies

### Smoke Testing Strategy

**Objective**: Quick validation that services are running and accessible

**Execution Time**: < 2 minutes

**Test Scenarios**:
1. Service connectivity tests
2. Basic HTTP response validation
3. Critical endpoint availability
4. Essential configuration verification

```bash
# Run smoke tests before deployment
./tests/run_tests.sh smoke

# Expected output
✓ Dashboard is reachable
✓ API endpoints respond
✓ Nginx proxy functional
✓ SSL certificates valid
```

### API Testing Strategy

**Objective**: Validate backend service functionality and API contracts

**Execution Time**: < 5 minutes

**Test Scenarios**:
1. REST API endpoint validation
2. Authentication and authorization
3. Response format verification
4. Error handling validation
5. Performance benchmarks

```bash
# API-focused testing
./tests/run_tests.sh api

# Test different API endpoints
pytest tests/ -k "api" --verbose
```

### UI Testing Strategy

**Objective**: Validate user interface functionality and user workflows

**Execution Time**: 5-10 minutes

**Test Scenarios**:
1. Page loading and rendering
2. Form submission and validation
3. Navigation and user flows
4. Responsive design validation
5. Accessibility compliance

```bash
# UI testing with browser automation
./tests/run_tests.sh ui

# Run specific UI test suites
pytest tests/ -m "ui" --html=reports/ui_report.html
```

### Integration Testing Strategy

**Objective**: Validate end-to-end workflows and component integration

**Execution Time**: 10-15 minutes

**Test Scenarios**:
1. Complete user workflows
2. Data flow validation
3. Service communication
4. Configuration integration
5. Performance under load

```bash
# Full integration test suite
./tests/run_tests.sh integration

# Run with detailed reporting
pytest tests/ -m "integration" --verbose --tb=long
```

## 📊 Test Reporting

### HTML Reports

Generate comprehensive HTML test reports:

```bash
pytest tests/ --html=reports/detailed_report.html --self-contained-html
```

**Report Features**:
- Test execution summary
- Individual test results
- Failure details and stack traces
- Screenshots for UI test failures
- Performance metrics
- Environment information

### JUnit XML Reports

For CI/CD integration:

```bash
pytest tests/ --junit-xml=reports/junit.xml
```

### Coverage Reports

Track test coverage:

```bash
pip install pytest-cov
pytest tests/ --cov=. --cov-report=html --cov-report=xml
```

### Custom Report Templates

Create custom report templates in `tests/templates/`:

```html
<!-- tests/templates/custom_report.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Wazuh SOC Test Report</title>
    <style>
        /* Custom styling */
    </style>
</head>
<body>
    <!-- Custom report content -->
</body>
</html>
```

## 🔄 Continuous Integration

### GitHub Actions Integration

The project includes automated testing via GitHub Actions:

```yaml
# .github/workflows/ci-cd.yml
- name: Run smoke tests
  run: ./tests/run_tests.sh smoke

- name: Run API tests  
  run: ./tests/run_tests.sh api

- name: Run UI tests
  run: ./tests/run_tests.sh ui
```

### Test Artifacts

CI/CD pipelines generate test artifacts:
- HTML test reports
- JUnit XML results  
- Screenshot captures
- Log files
- Coverage reports

## 📈 Performance Testing

### Load Testing

```bash
# Install load testing tools
pip install locust

# Run load tests
locust -f tests/load_test.py --host http://localhost:5601
```

### Stress Testing

```bash
# Stress test API endpoints
ab -n 1000 -c 10 http://localhost:55000/

# Monitor resource usage during tests
htop
docker stats
```

### Test Writing Guidelines

1. **Test Isolation**: Each test should be independent
2. **Clear Naming**: Use descriptive test method names
3. **Documentation**: Add docstrings explaining test purpose
4. **Assertions**: Use specific assertions with meaningful messages
5. **Cleanup**: Ensure proper test cleanup and teardown

### Test Execution Guidelines

1. **Environment Consistency**: Use containerized test environments
2. **Data Management**: Use test-specific data sets
3. **Parallel Execution**: Run tests in parallel when possible
4. **Retry Logic**: Implement retry mechanisms for flaky tests
5. **Reporting**: Generate comprehensive test reports

### Maintenance Guidelines

1. **Regular Updates**: Keep test dependencies updated
2. **Test Review**: Regular code review of test implementations
3. **Coverage Monitoring**: Monitor and improve test coverage
4. **Performance**: Optimize test execution time
5. **Documentation**: Keep test documentation current

---

For additional testing support, see:
- [CI/CD Documentation](cicd.md)
- [Troubleshooting Guide](troubleshooting.md)
- [Development Guide](development.md)
