# Wazuh Docker Swarm Security Operations Center

A comprehensive Security Operations Center (SOC) deployment using Wazuh, automated with Ansible, deployed on Docker Swarm, and validated with Selenium tests.

## 🏗️ Architecture

- **Wazuh Manager**: Central security management and log analysis
- **Wazuh Indexer**: OpenSearch-based data indexing and storage  
- **Wazuh Dashboard**: Web interface for security monitoring
- **Nginx**: Reverse proxy with SSL termination and load balancing
- **Docker Swarm**: Container orchestration and high availability
- **Let's Encrypt**: Automated SSL certificate management

## 🚀 Quick Start

### Prerequisites

- Ubuntu 20.04+ or Amazon Linux 2
- Python 3.8+
- Ansible 2.9+
- Domain name pointing to your server (for SSL certificates)

### 1. Configure Inventory

Edit `ansible/inventory/prod/host`:

```ini
[swarm_managers]
your-server.com ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/your-key.pem

[swarm_managers:vars]
stack_name=wazuh-soc
domain_name=your-domain.com
email_address=admin@your-domain.com
```

### 2. Set Secrets

Create `ansible/group_vars/vault.yaml`:

```yaml
# Encrypt with: ansible-vault encrypt group_vars/vault.yaml
wazuh_admin_password: "SecurePassword123!"
wazuh_api_password: "APIPassword123!"
indexer_admin_password: "IndexerPassword123!"
```

### 3. Deploy Stack

```bash
cd ansible
ansible-playbook -i inventory/prod/host playbooks/deploy.yml --ask-vault-pass
```

### 4. Run Tests

```bash
# Set up test environment
cp tests/.env.example tests/.env
# Edit tests/.env with your configuration

# Run all tests
./tests/run_tests.sh

# Run specific test suites
./tests/run_tests.sh smoke    # Quick health checks
./tests/run_tests.sh ui       # Web interface tests
./tests/run_tests.sh api      # API endpoint tests
```

## 📋 Features

### ✅ Infrastructure Automation
- **Docker Swarm Setup**: Automated cluster initialization
- **SSL Certificates**: Let's Encrypt with automatic renewal
- **Overlay Networks**: Secure container communication
- **Secrets Management**: Encrypted password handling
- **Configuration Management**: Templated service configs

### ✅ Security Monitoring
- **Log Analysis**: Real-time security event processing
- **Threat Detection**: Rule-based intrusion detection
- **Vulnerability Assessment**: System security scanning
- **Compliance Monitoring**: Regulatory compliance checks
- **File Integrity**: Critical file change monitoring

### ✅ High Availability
- **Docker Swarm**: Multi-node container orchestration
- **Load Balancing**: Nginx reverse proxy with SSL
- **Health Checks**: Automated service monitoring
- **Rolling Updates**: Zero-downtime deployments
- **Backup Integration**: Automated data backup

### ✅ Testing & Validation
- **Selenium Tests**: Automated UI validation
- **API Health Probes**: Backend service verification
- **CI/CD Pipeline**: GitHub Actions integration
- **Security Scanning**: Vulnerability assessment
- **Performance Testing**: Load and stress testing

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WAZUH_HOST` | Wazuh server hostname | `localhost` |
| `WAZUH_PORT` | HTTP port for Nginx | `80` |
| `WAZUH_DASHBOARD_PORT` | Dashboard port | `5601` |
| `WAZUH_API_PORT` | API port | `55000` |
| `TEST_TIMEOUT` | Test timeout in seconds | `30` |

### Resource Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 2 cores | 4+ cores |
| **RAM** | 4GB | 8GB+ |
| **Storage** | 20GB | 50GB+ |
| **Network** | 1Gbps | 10Gbps |

## 🧪 Testing

### Test Suites

1. **Smoke Tests**: Basic service availability
2. **UI Tests**: Dashboard functionality and login
3. **API Tests**: Backend service health and responses
4. **Integration Tests**: End-to-end workflow validation

### Running Tests

```bash
# Install test dependencies
pip install -r tests/requirements.txt

# Run specific test categories
pytest tests/ -m "smoke"        # Quick smoke tests
pytest tests/ -m "ui"           # UI tests
pytest tests/ -m "api"          # API tests
pytest tests/ -k "login"        # Tests matching pattern

# Generate HTML reports
pytest tests/ --html=reports/test_report.html
```

### CI/CD Integration

The project includes GitHub Actions workflows for:
- Ansible playbook linting
- Automated deployment testing
- Security vulnerability scanning
- Test report generation

## 🛡️ Security

### SSL/TLS Configuration
- Let's Encrypt certificates with automatic renewal
- Strong cipher suites and TLS 1.2+ only
- HSTS headers for enhanced security
- Perfect Forward Secrecy (PFS)

### Access Control
- Role-based authentication
- API key management
- Network segmentation
- Encrypted inter-service communication

### Monitoring
- Failed login attempt detection
- Unusual activity alerting
- System integrity monitoring
- Real-time threat detection

## 📊 Monitoring & Alerting

### Available Dashboards
- **Security Events**: Real-time security incident tracking
- **System Health**: Infrastructure monitoring
- **Compliance**: Regulatory compliance status
- **Threat Intelligence**: IOC and threat feeds

### Alert Channels
- Email notifications
- Slack integration
- Webhook endpoints
- SIEM integration

## 🔄 Maintenance

### Regular Tasks
- Certificate renewal (automated)
- Log rotation and cleanup
- Security rule updates
- System patches and updates

### Backup & Recovery
- Database snapshots
- Configuration backups
- Disaster recovery procedures
- Data retention policies

## 🐛 Troubleshooting

### Common Issues

**Services not starting?**
```bash
# Check service status
docker service ls
docker service logs wazuh-soc_wazuh-manager

# Check resource usage
docker stats
```

**SSL certificate issues?**
```bash
# Check certificate status
sudo certbot certificates
sudo certbot renew --dry-run
```

**Dashboard not accessible?**
```bash
# Check nginx configuration
docker config inspect wazuh-soc_nginx.conf
docker service logs wazuh-soc_nginx
```

### Log Locations
- **Wazuh Manager**: `/var/ossec/logs/`
- **Nginx**: Container logs via `docker service logs`
- **SSL Certificates**: `/etc/letsencrypt/live/`

## 📖 Documentation

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Docker Swarm Guide](https://docs.docker.com/engine/swarm/)
- [Ansible Best Practices](https://docs.ansible.com/ansible/latest/user_guide/playbooks_best_practices.html)
- [Let's Encrypt Guide](https://letsencrypt.org/getting-started/)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `./tests/run_tests.sh`
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚖️ Legal & Compliance

- SOC 2 Type II compatible
- GDPR compliance features
- HIPAA security controls
- PCI DSS monitoring capabilities

## 🆘 Support

- **Issues**: GitHub Issues tracker
- **Documentation**: Wiki pages
- **Community**: Discussions tab
- **Security**: security@your-domain.com
