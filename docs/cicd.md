# CI/CD Documentation

This document provides comprehensive guidelines for the Continuous Integration and Continuous Deployment (CI/CD) pipeline of the Wazuh SOC deployment project.

## 🔄 CI/CD Overview

The project uses GitHub Actions for automated CI/CD workflows that include:

- **Automated Testing**: Smoke, API, UI, and integration tests
- **Security Scanning**: Vulnerability assessment with Trivy
- **Code Quality**: Linting and static analysis
- **Deployment Automation**: Automated deployment to staging/production
- **Monitoring Integration**: Post-deployment health checks

## 📋 Workflow Structure

### Available Workflows

```
.github/workflows/
├── ci-cd.yml              # Main CI/CD pipeline
├── test-simple.yml        # Simple test workflow
└── trivy.yml             # Security vulnerability scanning
```

### Main CI/CD Pipeline (`ci-cd.yml`)

The primary workflow handles the complete CI/CD process:

```yaml
name: Wazuh Docker Compose CI/CD

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  workflow_dispatch:  # Manual triggering
```

## 🏗️ Pipeline Stages

### Stage 1: Environment Setup

```yaml
- name: Checkout code
  uses: actions/checkout@v4
  
- name: Set up Python
  uses: actions/setup-python@v4
  with:
    python-version: '3.11'
    
- name: Install system dependencies
  run: |
    sudo apt-get update
    sudo apt-get install -y \
      docker-compose \
      chromium-browser \
      xvfb \
      curl
```

**Purpose**: Prepare the CI environment with required dependencies

**Key Components**:
- Repository checkout
- Python environment setup
- System package installation
- Docker Compose installation
- Browser dependencies for UI testing

### Stage 2: System Configuration

```yaml
- name: Configure system for Wazuh
  run: |
    # Increase system limits for Wazuh
    sudo sysctl -w vm.max_map_count=262144
    echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
    
    # Show available resources
    echo "Memory: $(free -h)"
    echo "CPU: $(nproc) cores"
    echo "Disk: $(df -h /)"
```

**Purpose**: Configure system parameters required for Wazuh services

**Key Actions**:
- Set virtual memory limits
- Display system resources
- Optimize kernel parameters

### Stage 3: Certificate Generation

```yaml
- name: Generate Wazuh indexer certificates
  run: |
    cd wazuh-docker/single-node
    docker-compose -f generate-indexer-certs.yml run --rm generator
    sudo chmod -R 755 config/wazuh_indexer_ssl_certs/
    sudo chown -R $(whoami):$(whoami) config/wazuh_indexer_ssl_certs/
```

**Purpose**: Generate SSL certificates for secure communication

**Key Actions**:
- Generate indexer SSL certificates
- Set proper file permissions
- Prepare SSL configuration

### Stage 4: Service Deployment

```yaml
- name: Start Wazuh stack
  run: |
    cd wazuh-docker/single-node
    docker-compose up -d
    sleep 120  # Wait for services to initialize
    docker-compose ps
```

**Purpose**: Deploy and start all Wazuh services

**Services Started**:
- Wazuh Manager
- Wazuh Indexer (OpenSearch)
- Wazuh Dashboard
- Support services

### Stage 5: Health Verification

```yaml
- name: Wait for services to be ready
  run: |
    # Wait for Wazuh Indexer
    timeout 600 bash -c 'until curl -f -k -u admin:SecretPassword https://localhost:9200/_cluster/health 2>/dev/null; do sleep 15; done'
    
    # Wait for Wazuh Manager API
    timeout 600 bash -c 'until curl -f http://localhost:55000/ 2>/dev/null; do sleep 15; done'
    
    # Wait for Wazuh Dashboard
    timeout 600 bash -c 'until curl -f http://localhost:5601/api/status 2>/dev/null; do sleep 15; done'
```

**Purpose**: Ensure all services are healthy before testing

**Health Checks**:
- Indexer cluster health
- Manager API availability
- Dashboard API status
- Service connectivity

### Stage 6: Test Execution

```yaml
- name: Run smoke tests
  run: ./tests/run_tests.sh smoke

- name: Run API tests
  run: ./tests/run_tests.sh api

- name: Run UI tests
  run: ./tests/run_tests.sh ui
```

**Purpose**: Execute comprehensive test suites

**Test Categories**:
- **Smoke Tests**: Basic service availability
- **API Tests**: Backend functionality
- **UI Tests**: Web interface validation

### Stage 7: Security Validation

```yaml
- name: Check HTTPS functionality
  run: |
    curl -I http://localhost:5601/ 2>/dev/null || echo "Dashboard check"
    curl -I http://localhost:55000/ 2>/dev/null || echo "API check"
    curl -I -k -u admin:SecretPassword https://localhost:9200/ 2>/dev/null || echo "Indexer check"
```

**Purpose**: Validate security configurations

**Security Checks**:
- SSL/TLS connectivity
- Authentication mechanisms
- Service endpoint security

### Stage 8: Report Generation

```yaml
- name: Upload test reports
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: test-reports
    path: tests/reports/
    retention-days: 30
```

**Purpose**: Archive test results and reports

**Report Types**:
- HTML test reports
- JUnit XML reports
- Screenshots from UI tests
- Coverage reports

### Stage 9: Cleanup

```yaml
- name: Cleanup
  if: always()
  run: |
    cd wazuh-docker/single-node
    docker-compose down -v
    docker system prune -f
```

**Purpose**: Clean up resources after pipeline execution

**Cleanup Actions**:
- Stop and remove containers
- Remove volumes
- Clean Docker system

## 🔒 Security Scanning Workflow

### Trivy Security Scanner (`trivy.yml`)

```yaml
name: Security Scan with Trivy

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        format: 'sarif'
        output: 'trivy-results.sarif'
        
    - name: Upload Trivy scan results to GitHub Security tab
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'
```

**Purpose**: Automated security vulnerability scanning

**Scan Types**:
- Filesystem scanning
- Container image scanning
- Dependencies vulnerability check
- License compliance check

## ⚙️ Configuration Management

### Environment Variables

Configure workflows using GitHub repository settings:

```yaml
env:
  DOCKER_BUILDKIT: 1
  COMPOSE_DOCKER_CLI_BUILD: 1
  WAZUH_VERSION: 4.7.2
  NODE_VERSION: 18
  PYTHON_VERSION: 3.11
```

### Secrets Management

Store sensitive information in GitHub Secrets:

```yaml
secrets:
  WAZUH_ADMIN_PASSWORD: ${{ secrets.WAZUH_ADMIN_PASSWORD }}
  WAZUH_API_PASSWORD: ${{ secrets.WAZUH_API_PASSWORD }}
  DOCKER_HUB_TOKEN: ${{ secrets.DOCKER_HUB_TOKEN }}
  DEPLOY_SSH_KEY: ${{ secrets.DEPLOY_SSH_KEY }}
```

**Required Secrets**:
- `WAZUH_ADMIN_PASSWORD`: Admin user password
- `WAZUH_API_PASSWORD`: API authentication password
- `DOCKER_HUB_TOKEN`: Docker Hub access token
- `DEPLOY_SSH_KEY`: SSH key for deployment servers

### Matrix Builds

Test across multiple environments:

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, ubuntu-20.04]
    python-version: [3.8, 3.9, 3.11]
    wazuh-version: [4.6.0, 4.7.2]
```

## 🚀 Deployment Strategies

### Staging Deployment

```yaml
deploy-staging:
  if: github.ref == 'refs/heads/develop'
  needs: [test]
  runs-on: ubuntu-latest
  environment: staging
  
  steps:
  - name: Deploy to staging
    run: |
      # Deploy to staging environment
      ansible-playbook -i inventory/staging playbooks/deploy.yml
```

### Production Deployment

```yaml
deploy-production:
  if: github.ref == 'refs/heads/main'
  needs: [test, security-scan]
  runs-on: ubuntu-latest
  environment: production
  
  steps:
  - name: Deploy to production
    run: |
      # Deploy to production environment
      ansible-playbook -i inventory/prod playbooks/deploy.yml
```

### Blue-Green Deployment

```yaml
blue-green-deploy:
  steps:
  - name: Deploy to blue environment
    run: |
      ansible-playbook -i inventory/prod playbooks/deploy.yml -e target_env=blue
      
  - name: Run health checks on blue
    run: |
      ./tests/run_tests.sh smoke --target blue
      
  - name: Switch traffic to blue
    run: |
      ansible-playbook -i inventory/prod playbooks/switch-traffic.yml -e target_env=blue
      
  - name: Cleanup green environment
    run: |
      ansible-playbook -i inventory/prod playbooks/cleanup.yml -e target_env=green
```

## 📊 Monitoring and Notifications

### Workflow Notifications

Configure notifications for workflow events:

```yaml
- name: Notify on failure
  if: failure()
  uses: 8398a7/action-slack@v3
  with:
    status: failure
    channel: '#devops'
    webhook_url: ${{ secrets.SLACK_WEBHOOK }}
```

### Performance Monitoring

```yaml
- name: Performance benchmarks
  run: |
    # Run performance tests
    ./tests/run_performance_tests.sh
    
    # Upload results
    curl -X POST $MONITORING_ENDPOINT \
      -H "Content-Type: application/json" \
      -d @performance_results.json
```

### Health Check Integration

```yaml
- name: Post-deployment health check
  run: |
    # Wait for deployment
    sleep 30
    
    # Comprehensive health check
    ./scripts/health_check.sh --environment production
    
    # Notify monitoring systems
    curl -X POST $HEALTH_CHECK_ENDPOINT/success
```

## 🔧 Troubleshooting CI/CD

### Common Pipeline Issues

#### 1. Service Startup Timeouts

**Symptoms**:
```
TimeoutException: Services not ready within 600 seconds
```

**Solutions**:
```yaml
# Increase timeout periods
- name: Wait for services
  run: |
    timeout 900 bash -c 'until curl -f http://localhost:5601; do sleep 30; done'

# Add resource monitoring
- name: Monitor resources
  run: |
    free -h
    df -h
    docker stats --no-stream
```

#### 2. Resource Constraints

**Symptoms**:
```
Exit code 137: Container killed due to memory limit
```

**Solutions**:
```yaml
# Use larger runner
runs-on: ubuntu-latest-4-cores

# Optimize resource usage
- name: Configure Docker
  run: |
    echo '{"max-concurrent-downloads": 2}' | sudo tee /etc/docker/daemon.json
    sudo systemctl restart docker
```

#### 3. Authentication Failures

**Symptoms**:
```
401 Unauthorized: Docker pull rate limit exceeded
```

**Solutions**:
```yaml
# Authenticate with Docker Hub
- name: Login to Docker Hub
  uses: docker/login-action@v2
  with:
    username: ${{ secrets.DOCKER_HUB_USERNAME }}
    password: ${{ secrets.DOCKER_HUB_TOKEN }}
```

#### 4. Test Flakiness

**Symptoms**:
```
Tests pass locally but fail in CI
```

**Solutions**:
```yaml
# Add retry logic
- name: Run tests with retry
  uses: nick-invision/retry@v2
  with:
    timeout_minutes: 10
    max_attempts: 3
    command: ./tests/run_tests.sh

# Increase wait times
- name: Wait for stability
  run: sleep 60
```

### Debug Mode

Enable debug mode for troubleshooting:

```yaml
- name: Enable debug logging
  run: echo "RUNNER_DEBUG=1" >> $GITHUB_ENV

- name: Dump context
  env:
    CONTEXT: ${{ toJson(github) }}
  run: echo "$CONTEXT"
```

### Log Collection

```yaml
- name: Collect logs on failure
  if: failure()
  run: |
    # Collect container logs
    docker-compose logs > container_logs.txt
    
    # Collect system logs
    journalctl --since "1 hour ago" > system_logs.txt
    
- name: Upload logs
  if: failure()
  uses: actions/upload-artifact@v4
  with:
    name: debug-logs
    path: |
      container_logs.txt
      system_logs.txt
      tests/reports/
```

## 🎯 Best Practices

### Workflow Design

1. **Fast Feedback**: Run quick tests first
2. **Parallel Execution**: Use job parallelization
3. **Conditional Steps**: Skip unnecessary steps
4. **Resource Optimization**: Clean up resources
5. **Error Handling**: Implement proper error handling

### Security Best Practices

1. **Secrets Management**: Use GitHub Secrets
2. **Least Privilege**: Minimal required permissions
3. **Dependency Scanning**: Regular vulnerability scans
4. **Image Security**: Scan container images
5. **Audit Logging**: Enable audit logs

### Performance Optimization

1. **Caching**: Use action caching
2. **Layer Optimization**: Optimize Docker layers
3. **Resource Limits**: Set appropriate limits
4. **Cleanup**: Regular resource cleanup
5. **Monitoring**: Monitor pipeline performance

### Testing Strategy

1. **Test Pyramid**: Unit, integration, E2E tests
2. **Parallel Testing**: Run tests in parallel
3. **Test Data**: Use isolated test data
4. **Reporting**: Comprehensive test reporting
5. **Coverage**: Maintain test coverage

## 📈 Metrics and Monitoring

### Pipeline Metrics

Track important CI/CD metrics:

- **Build Success Rate**: Percentage of successful builds
- **Build Duration**: Average pipeline execution time
- **Test Coverage**: Code coverage percentage
- **Deployment Frequency**: Number of deployments per day
- **Mean Time to Recovery**: Average recovery time from failures

### Dashboards

Create monitoring dashboards:

```yaml
# GitHub Actions dashboard
- Build status overview
- Test results trends
- Performance metrics
- Resource usage
- Failure analysis
```

## 🔄 Continuous Improvement

### Pipeline Optimization

1. **Regular Reviews**: Review pipeline performance
2. **Bottleneck Analysis**: Identify and resolve bottlenecks
3. **Tool Updates**: Keep tools and actions updated
4. **Feedback Integration**: Incorporate team feedback
5. **Documentation**: Maintain up-to-date documentation

### Automation Enhancement

1. **Auto-scaling**: Implement runner auto-scaling
2. **Smart Triggering**: Optimize build triggers
3. **Dependency Updates**: Automated dependency updates
4. **Security Patches**: Automated security patching
5. **Rollback Automation**: Automated rollback procedures

---

For additional CI/CD support, see:
- [Testing Documentation](testing.md)
- [Troubleshooting Guide](troubleshooting.md)
- [Development Guide](development.md)
