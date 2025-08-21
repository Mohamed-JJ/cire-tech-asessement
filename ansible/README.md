# Wazuh Docker Swarm Deployment with Ansible

This Ansible automation deploys the Wazuh security platform on a Docker Swarm cluster with advanced features like high availability, automated rollback, and comprehensive monitoring.

## Architecture

- **Docker Swarm**: Orchestrates containers across multiple nodes
- **Wazuh Manager**: Security event processing and management
- **Wazuh Indexer**: Data storage and search (based on OpenSearch)
- **Wazuh Dashboard**: Web interface for visualization and management

## Prerequisites

### System Requirements
- **Operating System**: CentOS/RHEL 7+ or Amazon Linux 2
- **Memory**: Minimum 8GB RAM per node (16GB recommended)
- **CPU**: Minimum 4 cores per node
- **Disk**: 100GB+ available space
- **Network**: Open ports 2377, 7946, 4789 for Swarm communication

### Software Requirements
- Ansible 2.9+
- Python 3.6+
- SSH access to all nodes
- Sudo privileges on target hosts

## Quick Start

1. **Configure Inventory**
   ```bash
   # Edit inventory file
   vim ansible/inventory/prod/host
   ```

2. **Set Variables**
   ```bash
   # Edit group variables
   vim ansible/group_vars/prod.yml
   vim ansible/group_vars/vault.yaml
   ```

3. **Deploy Stack**
   ```bash
   cd ansible
   ansible-playbook -i inventory/prod/host playbooks/deploy.yml --ask-vault-pass
   ```

## Configuration Files

### Inventory Structure
```
inventory/
├── prod/
│   └── host              # Production hosts
└── staging/
    └── host              # Staging hosts (optional)
```

### Group Variables
- `group_vars/all.yml` - Global configuration
- `group_vars/prod.yml` - Production-specific settings
- `group_vars/vault.yaml` - Non-encrypted sensitive data
- `vault.yml` - Encrypted sensitive data

### Key Configuration Options

```yaml
# Stack Configuration
stack_name: "wazuh"
primary_manager: "host1"

# Service Replicas
wazuh_services:
  manager:
    replicas: 1
    placement_constraints:
      - "node.hostname == host1"
  indexer:
    replicas: 1
  dashboard:
    replicas: 1

# Resource Limits
resource_limits:
  manager:
    memory: "2G"
    cpus: "1.0"
  indexer:
    memory: "4G" 
    cpus: "2.0"
  dashboard:
    memory: "1G"
    cpus: "0.5"
```

## Deployment Process

### 1. Docker Installation
- Installs Docker CE and required dependencies
- Configures Docker daemon with optimal settings
- Sets up logging and storage drivers

### 2. Swarm Initialization
- Creates Docker Swarm cluster (idempotent)
- Configures manager and worker nodes
- Sets up overlay networks for service communication

### 3. SSL Certificate Management  
- Creates Docker configs for SSL certificates
- Manages certificate distribution securely
- Configures TLS for all service communications

### 4. Stack Deployment
- Generates Docker Compose file for Swarm mode
- Deploys services with health checks
- Configures resource limits and placement constraints

### 5. Verification & Monitoring
- Verifies service health and availability
- Checks resource utilization
- Validates network connectivity

## High Availability Features

### Automatic Rollback
```yaml
# Rollback Configuration
rollback_enabled: true
rollback_on_failure: true
update_failure_action: "rollback"
rollback_max_failure_ratio: 0
```

### Health Checks
- Service-level health monitoring
- Automatic container restart on failure
- Load balancer integration ready

### Resource Management
- CPU and memory limits/reservations
- Anti-affinity rules for service distribution
- Storage persistence across node failures

## Operations

### Deploy Stack
```bash
ansible-playbook -i inventory/prod/host playbooks/deploy.yml --ask-vault-pass
```

### Update Stack
```bash
ansible-playbook -i inventory/prod/host playbooks/deploy.yml --ask-vault-pass --tags=stack
```

### Rollback Deployment
```bash
ansible-playbook -i inventory/prod/host playbooks/rollback.yml --ask-vault-pass
```

### Complete Teardown
```bash
ansible-playbook -i inventory/prod/host playbooks/teardown.yml --ask-vault-pass
```

### Verify Deployment
```bash
ansible-playbook -i inventory/prod/host playbooks/deploy.yml --ask-vault-pass --tags=verify
```

## Service Access

After deployment, access services at:

- **Load Balancer (Nginx)**: `http://<manager-ip>:80`
- **Wazuh Dashboard**: `https://<manager-ip>:443` or `http://<manager-ip>:80/dashboard/`
- **Wazuh API**: `https://<manager-ip>:55000` or `http://<manager-ip>:80/api/`
- **Indexer API**: `https://<manager-ip>:9200` or `http://<manager-ip>:80/indexer/`

### Health Check Endpoints

The Nginx load balancer provides comprehensive health check endpoints:

- **Main Health Check**: `http://<manager-ip>:80/health`
  - Returns detailed JSON with service status and metadata
  - Example response:
  ```json
  {
    "status": "success",
    "message": "Wazuh Stack is healthy and operational",
    "timestamp": "2025-08-21T10:30:00Z",
    "data": {
      "services": {
        "nginx": {"status": "running", "role": "load_balancer"},
        "wazuh-manager": {"status": "proxied", "endpoint": "/api/"},
        "wazuh-dashboard": {"status": "proxied", "endpoint": "/dashboard/"},
        "wazuh-indexer": {"status": "proxied", "endpoint": "/indexer/"}
      },
      "environment": "production",
      "version": "1.0.0"
    }
  }
  ```

- **Simple Health Check**: `http://<manager-ip>:80/health/simple`
  - Returns minimal JSON: `{"status":"success","message":"OK"}`

- **Service-Specific Health Checks**:
  - Manager: `http://<manager-ip>:80/health/manager`
  - Dashboard: `http://<manager-ip>:80/health/dashboard`  
  - Indexer: `http://<manager-ip>:80/health/indexer`

- **Status Endpoint**: `http://<manager-ip>:80/status`
  - Returns plain text "OK" for basic monitoring tools

### Load Balancer Features

- **Rate Limiting**: API calls limited to 10/sec, health checks to 100/sec
- **Upstream Health Monitoring**: Automatic failover for unhealthy backends
- **Request Routing**: Intelligent routing based on URL paths
- **Access Logs**: Comprehensive logging with response times

### Default Credentials
- **Dashboard**: kibanaserver / kibanaserver
- **API**: wazuh-wui / MyS3cr37P450r.*-
- **Indexer**: admin / SecretPassword

## Troubleshooting

### Common Issues

1. **Swarm Join Failures**
   ```bash
   # Check firewall ports
   sudo firewall-cmd --list-ports
   
   # Verify Docker service
   sudo systemctl status docker
   ```

2. **Service Startup Failures**
   ```bash
   # Check service logs
   docker service logs <service-name>
   
   # Check service status
   docker service ps <service-name>
   ```

3. **SSL Certificate Issues**
   ```bash
   # Verify configs
   docker config ls
   
   # Check config content
   docker config inspect <config-name>
   ```

### Monitoring Commands

```bash
# View stack status
docker stack ls
docker stack services wazuh

# Monitor service health
docker service ls
docker node ls

# Check resource usage
docker stats
docker system df
```

### Log Locations

- **Ansible logs**: `/tmp/ansible.log`
- **Docker service logs**: `docker service logs <service>`
- **System logs**: `/var/log/messages`

## Security Considerations

### Network Security
- All inter-service communication uses TLS
- Overlay networks provide isolation
- Firewall rules should restrict external access

### Secret Management
- Sensitive data stored in Docker secrets
- Ansible Vault for configuration encryption
- Regular password rotation recommended

### Updates
- Rolling updates with zero downtime
- Automatic rollback on failures
- Backup before major updates

## Backup and Recovery

### Manual Backup
```bash
# Create volume backup
docker run --rm -v wazuh-indexer-data:/data -v /backup:/backup alpine tar czf /backup/indexer-data-$(date +%Y%m%d).tar.gz -C /data .

# Backup configurations
tar czf /backup/wazuh-config-$(date +%Y%m%d).tar.gz /opt/docker-stacks/wazuh/
```

### Recovery
```bash
# Restore volume data
docker run --rm -v wazuh-indexer-data:/data -v /backup:/backup alpine tar xzf /backup/indexer-data-YYYYMMDD.tar.gz -C /data

# Redeploy stack
ansible-playbook -i inventory/prod/host playbooks/deploy.yml --ask-vault-pass
```

## Performance Tuning

### Indexer Optimization
```yaml
# Increase JVM heap size
OPENSEARCH_JAVA_OPTS: "-Xms4g -Xmx4g"

# Adjust resource limits
resource_limits:
  indexer:
    memory: "8G"
    cpus: "4.0"
```

### Manager Tuning
```bash
# Increase file descriptors
ulimit -n 65536

# Optimize log retention
echo "logcollector.remote_commands=1" >> /var/ossec/etc/local_internal_options.conf
```

## Contributing

1. Fork the repository
2. Create feature branch
3. Test changes in staging environment
4. Submit pull request with documentation updates

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

- **Documentation**: [Wazuh Documentation](https://documentation.wazuh.com/)
- **Community**: [Wazuh Community](https://wazuh.com/community/)
- **Issues**: Create GitHub issue for bugs or feature requests
