# Development Guide

This guide provides comprehensive information for developers working on the Wazuh SOC deployment project, including setup, development workflows, and contribution guidelines.

## 🏗️ Development Environment Setup

### Prerequisites

Before starting development, ensure you have:

```bash
# System requirements
- Ubuntu 20.04+ / macOS 10.15+ / Windows 10 WSL2
- Docker 20.10+
- Docker Compose 2.0+
- Python 3.8+
- Ansible 2.9+
- Git 2.20+

# Development tools
- VS Code or preferred IDE
- Chrome/Chromium browser
- SSH client
- Text editor with YAML support
```

### Local Development Setup

#### 1. Repository Setup

```bash
# Clone the repository
git clone https://github.com/your-org/cire-soc-challenge.git
cd cire-soc-challenge

# Create development branch
git checkout -b feature/your-feature-name

# Set up Git hooks (optional but recommended)
cp scripts/pre-commit .git/hooks/
chmod +x .git/hooks/pre-commit
```

#### 2. Python Environment

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements.txt
pip install -r tests/requirements.txt

# Install development tools
pip install black flake8 isort mypy pre-commit
```

#### 3. Development Configuration

```bash
# Copy environment templates
cp .env.example .env
cp tests/.env.example tests/.env

# Configure for local development
cat >> .env << EOF
ENVIRONMENT=development
DEBUG=true
LOG_LEVEL=debug
EOF

# Configure test environment
cat >> tests/.env << EOF
WAZUH_HOST=localhost
WAZUH_PORT=5601
HEADLESS=false
CI=false
EOF
```

### Development Tools Configuration

#### VS Code Setup

```json
// .vscode/settings.json
{
    "python.defaultInterpreterPath": "./venv/bin/python",
    "python.linting.enabled": true,
    "python.linting.flake8Enabled": true,
    "python.linting.mypyEnabled": true,
    "python.formatting.provider": "black",
    "python.sortImports.args": ["--profile", "black"],
    "files.associations": {
        "*.yml": "yaml",
        "*.yaml": "yaml"
    },
    "yaml.schemas": {
        "https://json.schemastore.org/docker-compose.json": "docker-compose*.yml",
        "https://json.schemastore.org/ansible-playbook.json": "playbooks/*.yml"
    }
}
```

#### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files

  - repo: https://github.com/psf/black
    rev: 22.10.0
    hooks:
      - id: black
        language_version: python3

  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8

  - repo: https://github.com/pycqa/isort
    rev: 5.11.4
    hooks:
      - id: isort
        args: ["--profile", "black"]
```

## 🛠️ Development Workflows

### Local Development Workflow

#### 1. Start Development Services

```bash
# Start Wazuh services for development
cd wazuh-docker/single-node

# Generate certificates first
docker-compose -f generate-indexer-certs.yml run --rm generator

# Start services in development mode
docker-compose up -d

# Monitor service startup
docker-compose logs -f

# Verify services are ready
curl -I http://localhost:5601
curl -I http://localhost:55000
curl -I -k https://localhost:9200
```

#### 2. Development Testing

```bash
# Run tests during development
./tests/run_tests.sh smoke        # Quick validation
./tests/run_tests.sh api          # API testing
./tests/run_tests.sh ui           # UI testing (with browser)

# Run specific tests
pytest tests/test_wazuh_deployment.py::TestWazuhDeployment::test_api_health_probe -v

# Run tests with debugging
pytest tests/ -v --tb=long --capture=no
```

#### 3. Code Quality Checks

```bash
# Format code
black . --line-length 88
isort . --profile black

# Lint code
flake8 . --max-line-length 88 --extend-ignore E203,W503
mypy . --ignore-missing-imports

# Check YAML files
yamllint ansible/ tests/ wazuh-docker/
```

### Feature Development Process

#### 1. Planning Phase

Before starting development:

1. **Issue Creation**: Create GitHub issue describing the feature
2. **Design Review**: Discuss approach with team
3. **Requirements**: Define acceptance criteria
4. **Testing Strategy**: Plan test scenarios

#### 2. Implementation Phase

```bash
# Create feature branch
git checkout -b feature/new-monitoring-dashboard

# Make incremental commits
git add .
git commit -m "feat: add monitoring dashboard component"

# Push changes regularly
git push origin feature/new-monitoring-dashboard
```

#### 3. Testing Phase

```bash
# Test locally
./tests/run_tests.sh

# Test with different configurations
export WAZUH_HOST=test-server.example.com
./tests/run_tests.sh

# Performance testing
./scripts/performance_test.sh
```

#### 4. Review Phase

1. **Self Review**: Review your own code
2. **Testing**: Ensure all tests pass
3. **Documentation**: Update relevant documentation
4. **Pull Request**: Create PR with detailed description

## 📝 Coding Standards

### Python Code Standards

#### Style Guidelines

```python
# Follow PEP 8 with Black formatting
# Use type hints
def process_wazuh_data(data: Dict[str, Any]) -> List[Alert]:
    """Process Wazuh alert data and return formatted alerts.
    
    Args:
        data: Raw alert data from Wazuh API
        
    Returns:
        List of formatted Alert objects
        
    Raises:
        ValidationError: If data format is invalid
    """
    alerts = []
    
    for item in data.get('items', []):
        alert = Alert(
            id=item['id'],
            timestamp=item['timestamp'],
            severity=item.get('rule', {}).get('level', 0)
        )
        alerts.append(alert)
    
    return alerts
```

#### Error Handling

```python
# Use specific exception types
try:
    response = requests.get(url, timeout=30)
    response.raise_for_status()
except requests.exceptions.Timeout:
    logger.error("Request timed out")
    raise WazuhConnectionError("API request timed out")
except requests.exceptions.HTTPError as e:
    logger.error(f"HTTP error: {e}")
    raise WazuhAPIError(f"API returned error: {e}")
```

#### Logging Standards

```python
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Use appropriate log levels
logger.debug("Detailed debug information")
logger.info("General information")
logger.warning("Warning about potential issue")
logger.error("Error that was handled")
logger.critical("Critical error that may cause shutdown")
```

### Ansible Standards

#### Playbook Structure

```yaml
---
# Playbook: deploy-wazuh-stack.yml
# Description: Deploy Wazuh SOC stack with high availability
# Author: Your Name
# Date: 2024-01-01

- name: Deploy Wazuh SOC Stack
  hosts: wazuh_servers
  become: true
  gather_facts: true
  
  vars:
    wazuh_version: "4.7.2"
    deployment_environment: "{{ env | default('staging') }}"
  
  pre_tasks:
    - name: Verify system requirements
      assert:
        that:
          - ansible_memtotal_mb >= 4096
          - ansible_processor_vcpus >= 2
        fail_msg: "Insufficient system resources"
  
  tasks:
    - name: Include Docker setup role
      include_role:
        name: docker_setup
      tags: [docker, setup]
  
  post_tasks:
    - name: Verify deployment success
      uri:
        url: "http://{{ ansible_default_ipv4.address }}:5601"
        status_code: 200
      tags: [verify]
```

#### Task Naming and Structure

```yaml
- name: Install Docker packages
  package:
    name: "{{ item }}"
    state: present
  loop:
    - docker.io
    - docker-compose
  notify: restart docker
  tags: [docker, packages]

- name: Configure Docker daemon
  template:
    src: daemon.json.j2
    dest: /etc/docker/daemon.json
    backup: yes
  notify: restart docker
  tags: [docker, config]

- name: Ensure Docker service is running
  systemd:
    name: docker
    state: started
    enabled: yes
  tags: [docker, service]
```

### Docker Standards

#### Dockerfile Best Practices

```dockerfile
# Multi-stage build for optimization
FROM node:16-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:16-alpine
# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# Set working directory
WORKDIR /app

# Copy application
COPY --from=builder --chown=nextjs:nodejs /app/node_modules ./node_modules
COPY --chown=nextjs:nodejs . .

# Security: Run as non-root
USER nextjs

EXPOSE 3000

CMD ["npm", "start"]
```

#### Docker Compose Standards

```yaml
version: '3.8'

services:
  wazuh-manager:
    image: wazuh/wazuh-manager:4.7.2
    container_name: wazuh.manager
    hostname: wazuh.manager
    restart: unless-stopped
    
    environment:
      - INDEXER_URL=https://wazuh1.indexer:9200
      - INDEXER_USERNAME=${INDEXER_USERNAME:-admin}
      - INDEXER_PASSWORD=${INDEXER_PASSWORD:-SecretPassword}
      - FILEBEAT_SSL_VERIFICATION_MODE=${FILEBEAT_SSL_VERIFICATION_MODE:-full}
    
    volumes:
      - wazuh_api_configuration:/var/ossec/api/configuration
      - wazuh_etc:/var/ossec/etc
      - wazuh_logs:/var/ossec/logs
      - wazuh_queue:/var/ossec/queue
      - wazuh_var_multigroups:/var/ossec/var/multigroups
      - wazuh_integrations:/var/ossec/integrations
      - wazuh_active_response:/var/ossec/active-response/bin
      - wazuh_agentless:/var/ossec/agentless
      - wazuh_wodles:/var/ossec/wodles
      - filebeat_etc:/etc/filebeat
      - filebeat_var:/var/lib/filebeat
    
    ports:
      - "1514:1514"
      - "1515:1515"
      - "514:514/udp"
      - "55000:55000"
    
    networks:
      - wazuh
    
    depends_on:
      - wazuh1.indexer
    
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:55000 || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s

networks:
  wazuh:
    driver: bridge

volumes:
  wazuh_api_configuration:
  wazuh_etc:
  wazuh_logs:
  wazuh_queue:
  wazuh_var_multigroups:
  wazuh_integrations:
  wazuh_active_response:
  wazuh_agentless:
  wazuh_wodles:
  filebeat_etc:
  filebeat_var:
```

## 🧪 Testing Development

### Writing Tests

#### Unit Tests

```python
import unittest
from unittest.mock import Mock, patch
import requests
from wazuh_client import WazuhAPI

class TestWazuhAPI(unittest.TestCase):
    def setUp(self):
        self.api = WazuhAPI('http://localhost:55000', 'admin', 'password')
    
    def test_get_agents_success(self):
        """Test successful agent retrieval"""
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                'data': {'affected_items': [{'id': '001', 'name': 'agent1'}]}
            }
            mock_get.return_value = mock_response
            
            agents = self.api.get_agents()
            
            self.assertEqual(len(agents), 1)
            self.assertEqual(agents[0]['name'], 'agent1')
    
    def test_get_agents_authentication_error(self):
        """Test authentication error handling"""
        with patch('requests.get') as mock_get:
            mock_get.side_effect = requests.exceptions.HTTPError("401 Unauthorized")
            
            with self.assertRaises(AuthenticationError):
                self.api.get_agents()
```

#### Integration Tests

```python
import pytest
import docker
import time

@pytest.fixture(scope="session")
def wazuh_stack():
    """Start Wazuh stack for integration testing"""
    client = docker.from_env()
    
    # Start services
    client.compose.up(detach=True)
    
    # Wait for services to be ready
    time.sleep(120)
    
    yield
    
    # Cleanup
    client.compose.down(volumes=True)

def test_end_to_end_workflow(wazuh_stack):
    """Test complete workflow from agent registration to alert generation"""
    # Register agent
    agent_id = register_test_agent()
    
    # Generate test event
    generate_security_event(agent_id)
    
    # Wait for processing
    time.sleep(30)
    
    # Verify alert in dashboard
    alerts = search_alerts(agent_id)
    assert len(alerts) > 0
    assert alerts[0]['agent']['id'] == agent_id
```

### Test Data Management

#### Test Fixtures

```python
# tests/fixtures.py
import pytest

@pytest.fixture
def sample_alert():
    return {
        "id": "1234567890",
        "timestamp": "2024-01-01T12:00:00.000Z",
        "agent": {
            "id": "001",
            "name": "test-agent",
            "ip": "192.168.1.100"
        },
        "rule": {
            "id": 5503,
            "level": 5,
            "description": "User login failed"
        }
    }

@pytest.fixture
def test_user():
    return {
        "username": "testuser",
        "password": "TestPassword123!",
        "roles": ["readonly"]
    }
```

#### Mock Services

```python
# tests/mocks.py
from unittest.mock import Mock

class MockWazuhAPI:
    def __init__(self):
        self.agents = []
        self.alerts = []
    
    def get_agents(self):
        return self.agents
    
    def add_agent(self, agent_data):
        self.agents.append(agent_data)
        return {"id": len(self.agents)}
    
    def get_alerts(self, query=None):
        if query:
            return [alert for alert in self.alerts if self._match_query(alert, query)]
        return self.alerts
```

## 🔧 Configuration Management

### Environment Configuration

#### Development Environment

```bash
# .env.development
ENVIRONMENT=development
DEBUG=true
LOG_LEVEL=debug

# Service Configuration
WAZUH_MANAGER_HOST=localhost
WAZUH_MANAGER_PORT=55000
WAZUH_DASHBOARD_HOST=localhost
WAZUH_DASHBOARD_PORT=5601
WAZUH_INDEXER_HOST=localhost
WAZUH_INDEXER_PORT=9200

# Authentication
WAZUH_ADMIN_USER=admin
WAZUH_ADMIN_PASSWORD=DevPassword123!
WAZUH_API_USER=wazuh
WAZUH_API_PASSWORD=DevAPIPassword123!

# Development Features
ENABLE_DEBUG_TOOLBAR=true
MOCK_EXTERNAL_SERVICES=true
SKIP_SSL_VERIFICATION=true
```

#### Testing Environment

```bash
# .env.testing
ENVIRONMENT=testing
DEBUG=false
LOG_LEVEL=info

# Test Configuration
USE_TEST_DATABASE=true
RESET_DATA_ON_START=true
HEADLESS_BROWSER=true
PARALLEL_TESTS=true

# Mock Services
MOCK_WAZUH_API=true
MOCK_ELASTICSEARCH=true
USE_FAKE_DATA=true
```

### Configuration Validation

```python
# config/validator.py
import os
from typing import Dict, Any
from pydantic import BaseSettings, validator

class WazuhConfig(BaseSettings):
    """Wazuh configuration with validation"""
    
    # Service Configuration
    wazuh_host: str = "localhost"
    wazuh_port: int = 55000
    wazuh_username: str
    wazuh_password: str
    
    # Optional Configuration
    timeout: int = 30
    ssl_verify: bool = True
    debug: bool = False
    
    @validator('wazuh_port')
    def validate_port(cls, v):
        if not 1 <= v <= 65535:
            raise ValueError('Port must be between 1 and 65535')
        return v
    
    @validator('timeout')
    def validate_timeout(cls, v):
        if v < 1:
            raise ValueError('Timeout must be positive')
        return v
    
    class Config:
        env_prefix = 'WAZUH_'
        case_sensitive = False
```

## 📊 Monitoring and Debugging

### Local Debugging Setup

#### Debug Configuration

```python
# debug/config.py
import logging
import sys

def setup_debug_logging():
    """Configure detailed logging for debugging"""
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('debug.log')
        ]
    )
    
    # Enable HTTP request logging
    import http.client
    http.client.HTTPConnection.debuglevel = 1
    
    # Enable urllib3 logging
    import urllib3
    urllib3.disable_warnings()
    logging.getLogger("urllib3").setLevel(logging.DEBUG)
```

#### Performance Profiling

```python
# debug/profiler.py
import cProfile
import pstats
import io
from functools import wraps

def profile_function(func):
    """Decorator to profile function performance"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        profiler = cProfile.Profile()
        profiler.enable()
        
        result = func(*args, **kwargs)
        
        profiler.disable()
        
        # Print results
        s = io.StringIO()
        ps = pstats.Stats(profiler, stream=s).sort_stats('cumulative')
        ps.print_stats()
        print(s.getvalue())
        
        return result
    return wrapper

@profile_function
def process_large_dataset(data):
    # Function implementation
    pass
```

### Development Tools

#### Custom CLI Tools

```python
#!/usr/bin/env python3
# tools/dev_cli.py
import click
import docker
import subprocess

@click.group()
def cli():
    """Development CLI tools for Wazuh SOC project"""
    pass

@cli.command()
def start():
    """Start development environment"""
    click.echo("Starting Wazuh development environment...")
    subprocess.run(['docker-compose', 'up', '-d'])

@cli.command()
def stop():
    """Stop development environment"""
    click.echo("Stopping Wazuh development environment...")
    subprocess.run(['docker-compose', 'down'])

@cli.command()
def logs():
    """Show service logs"""
    subprocess.run(['docker-compose', 'logs', '-f'])

@cli.command()
@click.option('--service', help='Specific service to test')
def test(service):
    """Run tests"""
    if service:
        subprocess.run(['pytest', f'tests/test_{service}.py', '-v'])
    else:
        subprocess.run(['./tests/run_tests.sh'])

if __name__ == '__main__':
    cli()
```

#### Development Scripts

```bash
#!/bin/bash
# scripts/dev_setup.sh

set -e

echo "=== Wazuh SOC Development Setup ==="

# Check prerequisites
command -v docker >/dev/null 2>&1 || { echo "Docker required"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "Python 3 required"; exit 1; }

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt
pip install -r tests/requirements.txt

# Install development dependencies
pip install black flake8 isort mypy pytest-cov

# Copy configuration templates
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "Created .env file - please update with your settings"
fi

if [ ! -f "tests/.env" ]; then
    cp tests/.env.example tests/.env
    echo "Created tests/.env file"
fi

# Generate SSL certificates
echo "Generating SSL certificates..."
cd wazuh-docker/single-node
docker-compose -f generate-indexer-certs.yml run --rm generator

echo "=== Setup Complete ==="
echo "To start development:"
echo "1. source venv/bin/activate"
echo "2. docker-compose up -d"
echo "3. ./tests/run_tests.sh smoke"
```

## 🤝 Contributing Guidelines

### Pull Request Process

#### 1. Pre-PR Checklist

- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] Breaking changes documented
- [ ] Security implications considered

#### 2. PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing completed

## Screenshots (if applicable)
Add screenshots to help explain your changes

## Additional Notes
Any additional information about the changes
```

### Code Review Guidelines

#### For Authors

1. **Small Changes**: Keep PRs focused and small
2. **Clear Description**: Explain what and why
3. **Test Coverage**: Include relevant tests
4. **Documentation**: Update docs as needed
5. **Self Review**: Review your own code first

#### For Reviewers

1. **Constructive Feedback**: Be helpful and specific
2. **Security Focus**: Look for security issues
3. **Performance Impact**: Consider performance implications
4. **Maintainability**: Ensure code is maintainable
5. **Testing**: Verify test coverage

### Release Process

#### Version Management

```bash
# Semantic versioning: MAJOR.MINOR.PATCH
# MAJOR: Breaking changes
# MINOR: New features (backward compatible)
# PATCH: Bug fixes (backward compatible)

# Update version
echo "4.7.3" > VERSION

# Tag release
git tag -a v4.7.3 -m "Release version 4.7.3"
git push origin v4.7.3
```

#### Changelog Maintenance

```markdown
# Changelog

All notable changes to this project will be documented in this file.

## [4.7.3] - 2024-01-15

### Added
- New monitoring dashboard
- Enhanced security scanning
- Additional test scenarios

### Changed
- Updated Docker images to latest versions
- Improved error handling in API client
- Enhanced documentation

### Fixed
- Fixed SSL certificate generation issue
- Resolved memory leak in indexer
- Corrected timezone handling

### Security
- Updated dependencies with security fixes
- Enhanced authentication validation
```

---

This development guide provides the foundation for contributing to the Wazuh SOC project. For additional information, see:
- [Testing Documentation](testing.md)
- [Architecture Guide](architecture.md)
- [Troubleshooting Guide](troubleshooting.md)
