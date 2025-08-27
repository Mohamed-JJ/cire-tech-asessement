# Wazuh Docker SOC Platform Documentation

Welcome to the comprehensive documentation for the Wazuh Docker SOC (Security Operations Center) platform. This documentation provides everything you need to deploy, configure, monitor, and maintain a production-ready security monitoring solution.

## 📚 Documentation Structure

### Quick Navigation

| Document | Purpose | Target Audience |
|----------|---------|----------------|
| **[Architecture Guide](architecture.md)** | System design and component overview | System Architects, Senior Developers |
| **[Deployment Guide](deployment.md)** | Installation and deployment procedures | DevOps Engineers, System Administrators |
| **[Troubleshooting Guide](troubleshooting.md)** | Problem resolution and debugging | Operations Teams, Support Engineers |
| **[CI/CD Guide](cicd.md)** | Automated deployment and workflows | DevOps Engineers, Release Managers |
| **[Testing Guide](testing.md)** | Comprehensive testing procedures | QA Engineers, Developers |

### Role-Based Access

#### 🏗️ For System Administrators
- Start with: [Deployment Guide](deployment.md) → [Troubleshooting Guide](troubleshooting.md)
- **Quick Start**: Single-node deployment in under 10 minutes
- **Production Setup**: Multi-node cluster configuration
- **Maintenance**: Backup, monitoring, and health checks

#### 👨‍💻 For Developers  
- Start with: [Architecture Guide](architecture.md) → [Testing Guide](testing.md) → [CI/CD Guide](cicd.md)
- **Code Structure**: Component relationships and data flows
- **Development Workflow**: Testing strategies and validation
- **Integration**: API endpoints and customization

#### 🛡️ For Security Analysts
- Start with: [Deployment Guide](deployment.md#agent-deployment) → [Troubleshooting Guide](troubleshooting.md#security-incidents)
- **Agent Management**: Deploy and configure Wazuh agents
- **Custom Rules**: Create detection rules and decoders
- **Incident Response**: Security event analysis and response

#### 🚀 For DevOps Engineers
- Start with: [CI/CD Guide](cicd.md) → [Deployment Guide](deployment.md#production-deployment)
- **Automation**: Automated deployment pipelines
- **Monitoring**: Infrastructure and application monitoring
- **Scaling**: Multi-environment and cluster management

## 🚀 Quick Start

### Prerequisites
- **System**: Ubuntu 20.04+ or CentOS 8+ (8GB RAM, 50GB storage minimum)
- **Software**: Docker 20.10+, Docker Compose 2.0+
- **Network**: Ports 80, 443, 5601, 55000 available

### 5-Minute Deployment
```bash
# Clone the repository
git clone <repository-url>
cd cire-soc-challenge

# Deploy single-node setup
cd wazuh-docker/single-node
docker-compose -f generate-indexer-certs.yml run --rm generator
docker-compose up -d

# Wait for services (2-5 minutes)
sleep 120

# Access dashboard
open https://localhost:5601
# Default credentials: admin / SecretPassword
```

### Verify Installation
```bash
# Check service health
curl -k https://localhost:55000/     # Wazuh API
curl -k https://localhost:9200/     # OpenSearch
curl -k https://localhost:5601/     # Dashboard

# View logs
docker-compose logs -f
```

## 🏗️ Platform Overview

### Core Components

| Component | Version | Purpose | Default Port |
|-----------|---------|---------|-------------|
| **Wazuh Manager** | 4.7.2 | Security analysis engine | 55000, 1514, 1515 |
| **OpenSearch** | 2.10.0 | Data storage and search | 9200, 9300 |
| **Wazuh Dashboard** | 4.7.2 | Web interface | 5601 |
| **Nginx** | Latest | Reverse proxy | 80, 443 |

### Key Features

- **🔍 Real-time Monitoring**: Continuous security event analysis
- **📊 SIEM Capabilities**: Log correlation and threat detection  
- **🛡️ Compliance**: PCI DSS, GDPR, HIPAA, SOX compliance
- **🤖 Automated Response**: Active response and threat mitigation
- **📈 Scalability**: Single-node to multi-cluster deployment
- **🔐 Security**: End-to-end encryption and authentication

## 🛠️ Technology Stack

### Container Orchestration
- **Docker**: Containerization platform
- **Docker Compose**: Multi-container orchestration
- **Volumes**: Persistent data storage
- **Networks**: Internal service communication

### Security Stack
- **Wazuh**: Open-source security platform
- **OpenSearch**: Search and analytics engine
- **SSL/TLS**: Certificate-based encryption
- **RBAC**: Role-based access control

### Automation & CI/CD
- **GitHub Actions**: Automated testing and deployment
- **Ansible**: Infrastructure automation
- **Shell Scripts**: Custom automation tasks
- **Monitoring**: Health checks and alerting

## 📖 Getting Started Workflows

### New to Wazuh?
1. **Learn the Basics**: Read [Architecture Guide](architecture.md) sections 1-3
2. **Deploy Locally**: Follow [Deployment Guide](deployment.md) quick start
3. **Explore Interface**: Access dashboard and explore features
4. **Add Agents**: Deploy your first monitoring agents

### Setting Up Production?
1. **Plan Architecture**: Review [Architecture Guide](architecture.md) scaling section
2. **Prepare Infrastructure**: Follow [Deployment Guide](deployment.md) prerequisites
3. **Deploy Multi-Node**: Implement production cluster setup
4. **Configure Monitoring**: Set up [Troubleshooting Guide](troubleshooting.md) health checks
5. **Implement CI/CD**: Deploy [CI/CD Guide](cicd.md) automation

### Troubleshooting Issues?
1. **Quick Fixes**: Check [Troubleshooting Guide](troubleshooting.md) common issues
2. **Service Problems**: Use diagnostic scripts and health checks
3. **Performance Issues**: Review resource optimization guides
4. **Security Concerns**: Follow security incident procedures

### Developing & Testing?
1. **Development Setup**: Use [Testing Guide](testing.md) for local development
2. **Run Tests**: Execute comprehensive test suites
3. **CI Integration**: Implement automated testing pipelines
4. **Code Quality**: Follow testing best practices

## 🎯 Common Use Cases

### Security Operations Center (SOC)
- **Centralized Monitoring**: Aggregate logs from multiple sources
- **Threat Detection**: Real-time analysis of security events
- **Incident Response**: Automated alerting and response workflows
- **Compliance Reporting**: Generate compliance reports and audits

### Infrastructure Monitoring
- **Server Monitoring**: System health and performance tracking
- **Application Monitoring**: Custom application log analysis
- **Network Security**: Network traffic and intrusion detection
- **File Integrity**: Monitor critical file changes

### Development & DevOps
- **CI/CD Integration**: Automated security testing in pipelines
- **Container Security**: Docker and Kubernetes monitoring
- **Configuration Management**: Infrastructure as code validation
- **Performance Testing**: Load testing and optimization

## 🔗 Quick Reference Links

### Essential URLs (Default Single-Node)
- **Wazuh Dashboard**: https://localhost:5601
- **Wazuh API**: https://localhost:55000
- **OpenSearch API**: https://localhost:9200
- **API Documentation**: https://localhost:55000/api-docs

### Default Credentials
- **Dashboard**: `admin` / `SecretPassword`
- **API**: `wazuh-wui` / `wazuh-wui`
- **OpenSearch**: `admin` / `SecretPassword`

### Important Commands
```bash
# Service management
docker-compose up -d          # Start services
docker-compose down -v        # Stop and remove services
docker-compose logs -f        # View logs

# Health checks
curl -k https://localhost:55000/
docker-compose ps
docker stats

# Certificate management
docker-compose -f generate-indexer-certs.yml run --rm generator
```

### Configuration Files
- **Docker Compose**: `wazuh-docker/single-node/docker-compose.yml`
- **SSL Certificates**: `config/wazuh_indexer_ssl_certs/`
- **Wazuh Config**: `config/wazuh_cluster/wazuh_manager.conf`
- **Dashboard Config**: `config/wazuh_dashboard/wazuh.yml`

## 📞 Support & Community

### Documentation
- **Official Wazuh Docs**: https://documentation.wazuh.com/
- **OpenSearch Docs**: https://opensearch.org/docs/
- **Docker Docs**: https://docs.docker.com/

### Community Resources
- **Wazuh Community**: https://groups.google.com/forum/\#\!forum/wazuh
- **GitHub Issues**: Report bugs and feature requests
- **Stack Overflow**: Technical questions and answers

### Contributing
1. **Fork Repository**: Create your own fork
2. **Create Branch**: Feature or bug-fix branches
3. **Submit PR**: Pull request with detailed description
4. **Follow Guidelines**: Code style and testing requirements
