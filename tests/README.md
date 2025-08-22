# Wazuh Docker Swarm SOC - Testing Framework

This directory contains comprehensive test automation for validating the Wazuh Security Operations Center deployment.

## 🧪 Test Structure

### Test Categories

- **Smoke Tests** (`-m smoke`): Quick health checks and basic connectivity
- **UI Tests** (`-m ui`): Dashboard interface and user interaction testing  
- **API Tests** (`-m api`): Backend service validation and health probes
- **Integration Tests**: End-to-end workflow validation

### Test Files

- `test_wazuh_deployment.py`: Main test suite with comprehensive coverage
- `requirements.txt`: Python dependencies for test execution
- `pytest.ini`: Test configuration and settings
- `.env.example`: Template for test environment configuration
- `run_tests.sh`: Test runner script with multiple execution modes

## 🚀 Quick Start

### 1. Set Up Test Environment

```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env
```

### 2. Install Dependencies

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run Tests

```bash
# Make runner executable
chmod +x run_tests.sh

# Run all tests
./run_tests.sh

# Run specific test suites
./run_tests.sh smoke    # Quick validation
./run_tests.sh ui       # Dashboard tests
./run_tests.sh api      # Backend tests
```

## 📋 Test Coverage

### Smoke Tests
- ✅ Wazuh Dashboard HTTPS accessibility
- ✅ Nginx proxy health check
- ✅ API endpoint availability
- ✅ Basic service connectivity

### UI Tests
- ✅ Page title and branding validation
- ✅ Login form elements presence
- ✅ Navigation structure verification
- ✅ Dashboard component loading
- ✅ Programmatic login workflow
- ✅ Post-login landing page validation

### API Tests
- ✅ Wazuh Manager API health probe
- ✅ JSON response schema validation
- ✅ Authentication endpoint testing
- ✅ Service status verification
- ✅ Error handling validation

### Security Tests
- ✅ HTTPS enforcement
- ✅ SSL certificate validation
- ✅ Security header presence
- ✅ Authentication requirements

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `WAZUH_HOST` | Target server hostname | `localhost` |
| `WAZUH_PORT` | HTTP port (Nginx) | `80` |
| `WAZUH_DASHBOARD_PORT` | Dashboard port | `5601` |
| `WAZUH_API_PORT` | API port | `55000` |
| `TEST_TIMEOUT` | Request timeout | `30` |
| `HEADLESS` | Browser headless mode | `true` |
| `WAZUH_TEST_USER` | Test username | `test-user` |
| `WAZUH_TEST_PASSWORD` | Test password | `SecurePass123!` |

### Browser Configuration

Tests support multiple browsers:
- **Chrome/Chromium** (default): Best performance and compatibility
- **Firefox**: Alternative browser testing
- **Edge**: Windows compatibility testing

WebDriver management is handled automatically via `webdriver-manager`.

## 🔍 Test Execution Modes

### Local Development
```bash
# Interactive mode with browser visible
HEADLESS=false ./run_tests.sh ui

# Debug mode with detailed output
pytest tests/ -v -s --tb=long
```

### CI/CD Integration
```bash
# Headless mode for CI
export CI=true
export HEADLESS=true
./run_tests.sh all
```

### Custom Test Selection
```bash
# Run tests matching pattern
pytest tests/ -k "login"

# Run specific test class
pytest tests/test_wazuh_deployment.py::TestWazuhDeployment

# Run with markers
pytest tests/ -m "not slow"
```

## 📊 Test Reports

### HTML Reports
```bash
# Generate HTML report
pytest tests/ --html=reports/test_report.html --self-contained-html
```

### JUnit XML (CI Integration)
```bash
# Generate JUnit XML for CI
pytest tests/ --junit-xml=reports/junit.xml
```

### Coverage Reports
```bash
# Install coverage plugin
pip install pytest-cov

# Run with coverage
pytest tests/ --cov=tests --cov-report=html
```

## 🛠️ Development

### Adding New Tests

1. **Create test method**:
```python
def test_new_feature(self):
    """Test description"""
    # Test implementation
    assert condition
```

2. **Add markers**:
```python
@pytest.mark.ui
@pytest.mark.slow
def test_new_ui_feature(self):
    # Test implementation
```

3. **Update configuration**:
Add new markers to `pytest.ini` if needed.

### Test Utilities

Common utilities available:
- `wait_for_element()`: Wait for DOM elements
- `take_screenshot()`: Capture screenshots on failure
- `validate_json_schema()`: API response validation
- `check_security_headers()`: Security header validation

## 🐛 Troubleshooting

### Common Issues

**ChromeDriver not found?**
```bash
# Reinstall webdriver-manager
pip install --upgrade webdriver-manager
```

**Timeout errors?**
```bash
# Increase timeout
export TEST_TIMEOUT=60
./run_tests.sh
```

**SSL certificate errors?**
```bash
# Skip SSL verification for testing
export PYTHONHTTPSVERIFY=0
```

### Debug Mode
```bash
# Run with debug output
pytest tests/ -v -s --capture=no

# Keep browser open on failure
pytest tests/ --pdb
```

### Log Analysis
```bash
# View test logs
tail -f tests/logs/test_execution.log

# View browser logs
grep "browser" tests/logs/test_execution.log
```

## 🔄 CI/CD Integration

### GitHub Actions
Tests are integrated with GitHub Actions workflow:
- Automated on push/PR
- Multiple environment testing
- Test report artifacts
- Security scanning integration

### Test Pipeline
1. **Lint**: Code quality checks
2. **Deploy**: Infrastructure setup
3. **Test**: Comprehensive validation
4. **Report**: Results and artifacts
5. **Cleanup**: Resource cleanup

## 📈 Performance Testing

### Load Testing Setup
```bash
# Install additional dependencies
pip install locust

# Run load tests
locust -f tests/performance/load_test.py
```

### Metrics Collection
- Response time tracking
- Error rate monitoring  
- Resource usage analysis
- Concurrent user simulation

## 🔐 Security Testing

### Vulnerability Scanning
- SSL/TLS configuration validation
- Security header verification
- Authentication bypass testing
- Input validation testing

### Compliance Testing
- OWASP Top 10 validation
- Security best practices
- Access control verification
- Data protection testing

## 📚 Resources

- [Selenium Documentation](https://selenium-python.readthedocs.io/)
- [pytest Documentation](https://docs.pytest.org/)
- [WebDriver Manager](https://github.com/SergeyPirogov/webdriver_manager)
- [Wazuh API Reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)
