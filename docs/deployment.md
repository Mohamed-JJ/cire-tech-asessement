# Deployment Guide

This comprehensive guide covers deployment strategies, environment setup, and operational procedures for the Wazuh SOC deployment project.

## 🚀 Deployment Overview

The project supports multiple deployment strategies:

- **Single-node Development**: Local development and testing
- **Multi-node Production**: High availability production deployment
- **Cloud Deployment**: AWS, Azure, GCP deployment options
- **Kubernetes Deployment**: Container orchestration with Kubernetes
- **Ansible Automation**: Infrastructure as Code deployment

## 🏗️ Infrastructure Requirements

### Minimum Requirements

| Component | CPU | Memory | Storage | Network |
|-----------|-----|---------|---------|---------|
| **Small Deployment** | 2 cores | 4GB RAM | 50GB SSD | 1Gbps |
| **Medium Deployment** | 4 cores | 8GB RAM | 100GB SSD | 1Gbps |
| **Large Deployment** | 8 cores | 16GB RAM | 500GB SSD | 10Gbps |
| **Enterprise** | 16+ cores | 32GB+ RAM | 1TB+ SSD | 10Gbps+ |

### System Requirements

```bash
# Operating System Support
- Ubuntu 20.04+ LTS
- Amazon Linux 2
- CentOS 8+
- Red Hat Enterprise Linux 8+

# Software Dependencies
- Docker 20.10+
- Docker Compose 2.0+
- Python 3.8+
- Ansible 2.9+

# Network Requirements
- Ports 80, 443 (HTTP/HTTPS)
- Port 5601 (Wazuh Dashboard)
- Port 55000 (Wazuh Manager API)
- Port 9200 (OpenSearch API)
- Port 1514, 1515 (Agent communication)
```

### Resource Planning

#### Storage Requirements

```bash
# Data Volume Sizing
/var/ossec/logs/         # 10GB-100GB (retention dependent)
/var/lib/wazuh-indexer/  # 100GB-1TB+ (data retention)
/etc/ssl/               # 100MB (certificates)
/var/log/               # 5GB-20GB (system logs)

# Backup Storage
# Plan for 150% of data volume for backups
```

#### Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Internet / External Users                │
└─────────────────────┬───────────────────────────────────────┘
                      │
    ┌─────────────────────────────────────────────────────────┐
    │                Load Balancer                            │
    │            (HAProxy / ALB / F5)                         │
    └─────────────────┬───────────────────────────────────────┘
                      │
    ┌─────────────────────────────────────────────────────────┐
    │                DMZ Network                              │
    │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
    │  │   Nginx     │  │   Nginx     │  │   Nginx     │    │
    │  │  (Node 1)   │  │  (Node 2)   │  │  (Node 3)   │    │
    │  └─────────────┘  └─────────────┘  └─────────────┘    │
    └─────────────────┬───────────────────────────────────────┘
                      │
    ┌─────────────────────────────────────────────────────────┐
    │              Internal Network                           │
    │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
    │  │   Wazuh     │  │   Wazuh     │  │   Wazuh     │    │
    │  │ Manager 1   │  │ Manager 2   │  │ Manager 3   │    │
    │  └─────────────┘  └─────────────┘  └─────────────┘    │
    │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
    │  │ OpenSearch  │  │ OpenSearch  │  │ OpenSearch  │    │
    │  │  Node 1     │  │  Node 2     │  │  Node 3     │    │
    │  └─────────────┘  └─────────────┘  └─────────────┘    │
    └─────────────────────────────────────────────────────────┘
```

## 🐳 Docker Deployment

### Single-Node Deployment

Perfect for development, testing, and small production environments.

#### Quick Start

```bash
# Clone repository
git clone https://github.com/your-org/cire-soc-challenge.git
cd cire-soc-challenge

# Generate certificates
cd wazuh-docker/single-node
docker-compose -f generate-indexer-certs.yml run --rm generator

# Start services
docker-compose up -d

# Verify deployment
curl -I http://localhost:5601  # Dashboard
curl -I http://localhost:55000  # Manager API
curl -I -k https://localhost:9200  # Indexer
```

#### Configuration Customization

```yaml
# docker-compose.override.yml
version: '3.8'

services:
  wazuh.manager:
    environment:
      - CUSTOM_SETTING=value
    volumes:
      - ./custom-config:/custom-config:ro
    ports:
      - "55000:55000"
      - "1514:1514"
      - "1515:1515"
    
  wazuh1.indexer:
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms2g -Xmx2g"  # Increase heap
    volumes:
      - indexer_data:/usr/share/wazuh-indexer/data
      - ./backup:/backup
    
  wazuh.dashboard:
    environment:
      - SERVER_HOST=0.0.0.0
      - OPENSEARCH_HOSTS=["https://wazuh1.indexer:9200"]
```

### Multi-Node Deployment

For production environments requiring high availability.

#### Configuration

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  # Wazuh Manager Cluster
  wazuh.manager.master:
    image: wazuh/wazuh-manager:4.7.2
    hostname: wazuh-master
    environment:
      - WAZUH_CLUSTER_NODE_TYPE=master
      - WAZUH_CLUSTER_NODE_NAME=master
      - WAZUH_CLUSTER_KEY=c98b62a9b6169ac5f67dae55ae4a9088
    networks:
      - wazuh_cluster
  
  wazuh.manager.worker1:
    image: wazuh/wazuh-manager:4.7.2
    hostname: wazuh-worker1
    environment:
      - WAZUH_CLUSTER_NODE_TYPE=worker
      - WAZUH_CLUSTER_NODE_NAME=worker1
      - WAZUH_CLUSTER_NODE_MASTER=wazuh-master
    networks:
      - wazuh_cluster
  
  # OpenSearch Cluster
  opensearch1:
    image: opensearchproject/opensearch:2.10.0
    hostname: opensearch1
    environment:
      - cluster.name=wazuh-cluster
      - node.name=opensearch1
      - discovery.seed_hosts=opensearch1,opensearch2,opensearch3
      - cluster.initial_cluster_manager_nodes=opensearch1,opensearch2,opensearch3
    networks:
      - opensearch_cluster
  
  opensearch2:
    image: opensearchproject/opensearch:2.10.0
    hostname: opensearch2
    environment:
      - cluster.name=wazuh-cluster
      - node.name=opensearch2
    networks:
      - opensearch_cluster

networks:
  wazuh_cluster:
    driver: overlay
    attachable: true
  opensearch_cluster:
    driver: overlay
    attachable: true
```

## 🎯 Ansible Deployment

### Inventory Setup

#### Production Inventory

```ini
# inventory/prod/hosts
[wazuh_managers]
wazuh-master.example.com ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/prod-key.pem
wazuh-worker1.example.com ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/prod-key.pem
wazuh-worker2.example.com ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/prod-key.pem

[opensearch_cluster]
opensearch1.example.com ansible_user=ubuntu
opensearch2.example.com ansible_user=ubuntu
opensearch3.example.com ansible_user=ubuntu

[load_balancers]
lb1.example.com ansible_user=ubuntu
lb2.example.com ansible_user=ubuntu

[all:vars]
ansible_ssh_common_args='-o StrictHostKeyChecking=no'
domain_name=wazuh.example.com
email_address=admin@example.com
```

### Variable Configuration

#### Group Variables

```yaml
# group_vars/all.yml
---
# Global Configuration
wazuh_version: "4.7.2"
opensearch_version: "2.10.0"
environment: "production"
deployment_name: "wazuh-soc-prod"

# Network Configuration
internal_network: "10.0.0.0/16"
cluster_network: "10.0.1.0/24"
mgmt_network: "10.0.2.0/24"

# Security Configuration
ssl_enabled: true
ssl_cert_validity_days: 365
enable_firewall: true
fail2ban_enabled: true

# Monitoring
enable_monitoring: true
log_level: "info"
retention_days: 90

# Backup Configuration
backup_enabled: true
backup_schedule: "0 2 * * *"  # Daily at 2 AM
backup_retention_days: 30
```

#### Host-Specific Variables

```yaml
# host_vars/wazuh-master.example.com.yml
---
wazuh_cluster_node_type: "master"
wazuh_cluster_node_name: "master"
wazuh_cluster_key: "{{ vault_wazuh_cluster_key }}"

# Resource allocation
docker_memory_limit: "8g"
opensearch_heap_size: "4g"

# Network configuration
private_ip: "10.0.1.10"
public_ip: "203.0.113.10"
```

### Deployment Playbooks

#### Main Deployment Playbook

```yaml
# playbooks/deploy.yml
---
- name: Wazuh SOC Production Deployment
  hosts: all
  become: true
  gather_facts: true
  
  vars_files:
    - ../group_vars/vault.yml
  
  pre_tasks:
    - name: Validate prerequisites
      include_tasks: tasks/validate_prerequisites.yml
      tags: [validation]
    
    - name: Update system packages
      package:
        name: "*"
        state: latest
      when: update_packages | default(true)
      tags: [system]
  
  roles:
    - role: common
      tags: [common]
    
    - role: docker_setup
      tags: [docker]
    
    - role: ssl_setup
      tags: [ssl]
      when: ssl_enabled
    
    - role: wazuh_cluster
      tags: [wazuh]
      when: inventory_hostname in groups['wazuh_managers']
    
    - role: opensearch_cluster
      tags: [opensearch]
      when: inventory_hostname in groups['opensearch_cluster']
    
    - role: load_balancer
      tags: [lb]
      when: inventory_hostname in groups['load_balancers']
    
    - role: monitoring
      tags: [monitoring]
      when: enable_monitoring
  
  post_tasks:
    - name: Verify deployment
      include_tasks: tasks/verify_deployment.yml
      tags: [verify]
    
    - name: Configure backups
      include_tasks: tasks/configure_backups.yml
      tags: [backup]
      when: backup_enabled
```

### Role Development

#### Wazuh Manager Role

```yaml
# roles/wazuh_manager/tasks/main.yml
---
- name: Create Wazuh directories
  file:
    path: "{{ item }}"
    state: directory
    owner: root
    group: root
    mode: '0755'
  loop:
    - /opt/wazuh-manager
    - /opt/wazuh-manager/config
    - /opt/wazuh-manager/logs

- name: Generate Wazuh configuration
  template:
    src: wazuh-manager.conf.j2
    dest: /opt/wazuh-manager/config/wazuh-manager.conf
    owner: root
    group: root
    mode: '0644'
  notify: restart wazuh-manager

- name: Deploy Wazuh Manager container
  docker_container:
    name: wazuh-manager
    image: "wazuh/wazuh-manager:{{ wazuh_version }}"
    state: started
    restart_policy: unless-stopped
    ports:
      - "55000:55000"
      - "1514:1514"
      - "1515:1515"
    volumes:
      - "/opt/wazuh-manager/config:/var/ossec/etc"
      - "/opt/wazuh-manager/logs:/var/ossec/logs"
    environment:
      WAZUH_CLUSTER_NODE_TYPE: "{{ wazuh_cluster_node_type }}"
      WAZUH_CLUSTER_NODE_NAME: "{{ wazuh_cluster_node_name }}"
      WAZUH_CLUSTER_KEY: "{{ wazuh_cluster_key }}"
    networks:
      - name: wazuh_cluster
```

#### SSL Setup Role

```yaml
# roles/ssl_setup/tasks/main.yml
---
- name: Install SSL dependencies
  package:
    name:
      - openssl
      - ca-certificates
    state: present

- name: Create SSL directory
  file:
    path: /opt/ssl
    state: directory
    mode: '0755'

- name: Generate SSL certificates
  include_tasks: generate_certificates.yml
  when: generate_self_signed_certs | default(true)

- name: Configure Let's Encrypt
  include_tasks: letsencrypt.yml
  when: use_letsencrypt | default(false)

- name: Deploy certificates to services
  include_tasks: deploy_certificates.yml
```

### Deployment Commands

#### Production Deployment

```bash
# Full production deployment
ansible-playbook -i inventory/prod/hosts playbooks/deploy.yml --ask-vault-pass

# Deploy specific components
ansible-playbook -i inventory/prod/hosts playbooks/deploy.yml --tags "wazuh" --ask-vault-pass

# Deploy to specific hosts
ansible-playbook -i inventory/prod/hosts playbooks/deploy.yml --limit "wazuh_managers" --ask-vault-pass

# Dry run deployment
ansible-playbook -i inventory/prod/hosts playbooks/deploy.yml --check --diff --ask-vault-pass
```

#### Rolling Updates

```bash
# Rolling update script
#!/bin/bash

INVENTORY="inventory/prod/hosts"
PLAYBOOK="playbooks/rolling_update.yml"

echo "Starting rolling update of Wazuh cluster..."

# Update workers first
ansible-playbook -i $INVENTORY $PLAYBOOK --limit "wazuh_workers" --ask-vault-pass

# Update master last
ansible-playbook -i $INVENTORY $PLAYBOOK --limit "wazuh_master" --ask-vault-pass

echo "Rolling update complete"
```


## 🔧 Post-Deployment Configuration

### Initial Setup

#### Admin User Creation

```bash
# Create admin user script
#!/bin/bash

WAZUH_API_URL="http://localhost:55000"
ADMIN_USER="admin"
ADMIN_PASS="NewSecurePassword123!"

# Wait for API to be ready
until curl -f $WAZUH_API_URL 2>/dev/null; do
  echo "Waiting for Wazuh API..."
  sleep 10
done

# Create admin user
curl -u admin:SecretPassword -X POST "$WAZUH_API_URL/security/users" \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"$ADMIN_USER\",
    \"password\": \"$ADMIN_PASS\",
    \"roles\": [\"administrator\"]
  }"

echo "Admin user created successfully"
```

#### SSL Certificate Configuration

```bash
# SSL setup script
#!/bin/bash

DOMAIN="wazuh.example.com"
EMAIL="admin@example.com"

# Install certbot
apt-get update
apt-get install -y certbot python3-certbot-nginx

# Generate Let's Encrypt certificate
certbot --nginx -d $DOMAIN --email $EMAIL --agree-tos --non-interactive

# Setup auto-renewal
echo "0 12 * * * /usr/bin/certbot renew --quiet" | crontab -
```


## 🔒 Security Hardening

### System Security

#### Firewall Configuration

```bash
# UFW firewall setup
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Allow SSH
ufw allow 22/tcp

# Allow HTTP/HTTPS
ufw allow 80/tcp
ufw allow 443/tcp

# Allow Wazuh services
ufw allow 55000/tcp
ufw allow 1514/tcp
ufw allow 1515/tcp

# Enable firewall
ufw --force enable
```

### Application Security

#### Wazuh Configuration

```xml
<!-- /var/ossec/etc/ossec.conf -->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>yes</email_notification>
    <smtp_server>smtp.example.com</smtp_server>
    <email_from>wazuh@example.com</email_from>
    <email_to>admin@example.com</email_to>
  </global>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
  </remote>

  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>yes</use_source_ip>
    <force_insert>yes</force_insert>
    <force_time>0</force_time>
    <purge>yes</purge>
    <use_password>yes</use_password>
    <ssl_agent_ca>/var/ossec/etc/sslmanager.cert</ssl_agent_ca>
    <ssl_verify_host>yes</ssl_verify_host>
    <ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>
</ossec_config>
```

## 🚀 Scaling Strategies

### Horizontal Scaling

#### Auto-scaling Configuration

```yaml
# kubernetes/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: wazuh-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: wazuh-manager
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

### Vertical Scaling

#### Resource Optimization

```yaml
# Resource limits for different workloads
resources:
  small_deployment:
    limits:
      cpu: 1000m
      memory: 2Gi
    requests:
      cpu: 500m
      memory: 1Gi
      
  medium_deployment:
    limits:
      cpu: 2000m
      memory: 4Gi
    requests:
      cpu: 1000m
      memory: 2Gi
      
  large_deployment:
    limits:
      cpu: 4000m
      memory: 8Gi
    requests:
      cpu: 2000m
      memory: 4Gi
```

---

This deployment guide provides comprehensive coverage of deployment strategies and operational procedures. For additional information, see:
- [Architecture Guide](architecture.md)
- [Troubleshooting Guide](troubleshooting.md)
- [Testing Documentation](testing.md)
