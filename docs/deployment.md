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

## ☁️ Cloud Deployment

### AWS Deployment

#### Infrastructure as Code (Terraform)

```hcl
# aws/main.tf
provider "aws" {
  region = var.aws_region
}

# VPC Configuration
resource "aws_vpc" "wazuh_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name = "wazuh-vpc"
    Project = "wazuh-soc"
  }
}

# Security Groups
resource "aws_security_group" "wazuh_sg" {
  name_prefix = "wazuh-sg"
  vpc_id      = aws_vpc.wazuh_vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 5601
    to_port     = 5601
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Launch Template
resource "aws_launch_template" "wazuh_template" {
  name_prefix   = "wazuh-"
  image_id      = data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  
  vpc_security_group_ids = [aws_security_group.wazuh_sg.id]
  
  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    wazuh_version = var.wazuh_version
  }))

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "wazuh-instance"
      Project = "wazuh-soc"
    }
  }
}

# Auto Scaling Group
resource "aws_autoscaling_group" "wazuh_asg" {
  name                = "wazuh-asg"
  vpc_zone_identifier = aws_subnet.private_subnets[*].id
  target_group_arns   = [aws_lb_target_group.wazuh_tg.arn]
  health_check_type   = "ELB"
  
  min_size         = 2
  max_size         = 6
  desired_capacity = 3
  
  launch_template {
    id      = aws_launch_template.wazuh_template.id
    version = "$Latest"
  }
}
```

#### User Data Script

```bash
#!/bin/bash
# user_data.sh

set -e

# Update system
apt-get update
apt-get upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
systemctl enable docker
systemctl start docker

# Install Docker Compose
curl -L "https://github.com/docker/compose/releases/download/v2.17.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Clone Wazuh repository
cd /opt
git clone https://github.com/your-org/cire-soc-challenge.git
cd cire-soc-challenge

# Configure environment
cp .env.example .env
sed -i "s/localhost/$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)/" .env

# Generate certificates
cd wazuh-docker/single-node
docker-compose -f generate-indexer-certs.yml run --rm generator

# Start services
docker-compose up -d

# Configure log rotation
cat > /etc/logrotate.d/wazuh << EOF
/opt/cire-soc-challenge/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF

# Setup monitoring
curl -L -o /usr/local/bin/cloudwatch-agent.deb https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
dpkg -i /usr/local/bin/cloudwatch-agent.deb

# Signal completion
/opt/aws/bin/cfn-signal -e $? --stack ${AWS::StackName} --resource AutoScalingGroup --region ${AWS::Region}
```

### Azure Deployment

#### ARM Template

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "vmSize": {
      "type": "string",
      "defaultValue": "Standard_D4s_v3",
      "metadata": {
        "description": "VM size for Wazuh instances"
      }
    },
    "instanceCount": {
      "type": "int",
      "defaultValue": 3,
      "metadata": {
        "description": "Number of Wazuh instances"
      }
    }
  },
  "resources": [
    {
      "type": "Microsoft.Network/virtualNetworks",
      "apiVersion": "2021-02-01",
      "name": "wazuh-vnet",
      "location": "[resourceGroup().location]",
      "properties": {
        "addressSpace": {
          "addressPrefixes": ["10.0.0.0/16"]
        },
        "subnets": [
          {
            "name": "wazuh-subnet",
            "properties": {
              "addressPrefix": "10.0.1.0/24"
            }
          }
        ]
      }
    }
  ]
}
```

### Google Cloud Platform

#### Deployment Manager

```yaml
# gcp/wazuh-deployment.yaml
imports:
  - path: templates/vm-template.jinja
  - path: templates/network-template.jinja

resources:
  - name: wazuh-network
    type: templates/network-template.jinja
    properties:
      region: us-central1
      
  - name: wazuh-cluster
    type: templates/vm-template.jinja
    properties:
      zone: us-central1-a
      machineType: n1-standard-4
      instanceCount: 3
      sourceImage: https://www.googleapis.com/compute/v1/projects/ubuntu-os-cloud/global/images/ubuntu-2004-focal-v20231213
```

## 🎛️ Kubernetes Deployment

### Helm Chart

#### Chart Configuration

```yaml
# helm/wazuh/Chart.yaml
apiVersion: v2
name: wazuh
description: A Helm chart for Wazuh SOC deployment
type: application
version: 0.1.0
appVersion: "4.7.2"

dependencies:
  - name: opensearch
    version: "2.x.x"
    repository: "https://opensearch-project.github.io/helm-charts/"
    condition: opensearch.enabled
```

#### Values Configuration

```yaml
# helm/wazuh/values.yaml
replicaCount: 3

image:
  repository: wazuh/wazuh-manager
  tag: "4.7.2"
  pullPolicy: IfNotPresent

service:
  type: LoadBalancer
  ports:
    - name: api
      port: 55000
      targetPort: 55000
    - name: agents
      port: 1514
      targetPort: 1514

resources:
  limits:
    cpu: 2000m
    memory: 4Gi
  requests:
    cpu: 1000m
    memory: 2Gi

persistence:
  enabled: true
  storageClass: fast-ssd
  size: 100Gi

opensearch:
  enabled: true
  replicas: 3
  resources:
    limits:
      cpu: 2000m
      memory: 4Gi

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: wazuh.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: wazuh-tls
      hosts:
        - wazuh.example.com
```

#### Deployment Templates

```yaml
# helm/wazuh/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "wazuh.fullname" . }}
  labels:
    {{- include "wazuh.labels" . | nindent 4 }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      {{- include "wazuh.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "wazuh.selectorLabels" . | nindent 8 }}
    spec:
      containers:
      - name: {{ .Chart.Name }}
        image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
        imagePullPolicy: {{ .Values.image.pullPolicy }}
        ports:
        - name: api
          containerPort: 55000
          protocol: TCP
        - name: agents
          containerPort: 1514
          protocol: TCP
        livenessProbe:
          httpGet:
            path: /
            port: api
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /
            port: api
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          {{- toYaml .Values.resources | nindent 10 }}
        volumeMounts:
        - name: wazuh-data
          mountPath: /var/ossec
      volumes:
      - name: wazuh-data
        persistentVolumeClaim:
          claimName: {{ include "wazuh.fullname" . }}-data
```

### Kubernetes Commands

```bash
# Deploy with Helm
helm repo add wazuh ./helm/wazuh
helm install wazuh-soc wazuh/wazuh -f values-prod.yaml

# Update deployment
helm upgrade wazuh-soc wazuh/wazuh -f values-prod.yaml

# Scale deployment
kubectl scale deployment wazuh-manager --replicas=5

# Check status
kubectl get pods -l app=wazuh
kubectl get services
kubectl describe ingress wazuh-ingress
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

### Monitoring Setup

#### Prometheus Configuration

```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'wazuh-manager'
    static_configs:
      - targets: ['wazuh-manager:55000']
    metrics_path: /api/stats
    basic_auth:
      username: monitoring
      password: monitoring_password

  - job_name: 'opensearch'
    static_configs:
      - targets: ['opensearch:9200']
    metrics_path: /_prometheus/metrics
```

#### Grafana Dashboards

```json
{
  "dashboard": {
    "title": "Wazuh SOC Overview",
    "panels": [
      {
        "title": "Active Agents",
        "type": "stat",
        "targets": [
          {
            "expr": "wazuh_agents_active_total",
            "legendFormat": "Active Agents"
          }
        ]
      },
      {
        "title": "Alert Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(wazuh_alerts_total[5m])",
            "legendFormat": "Alerts/sec"
          }
        ]
      }
    ]
  }
}
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

#### Fail2ban Configuration

```ini
# /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[ssh]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[wazuh-api]
enabled = true
port = 55000
filter = wazuh-api
logpath = /var/log/wazuh/api.log
maxretry = 3
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

## 📊 Monitoring & Maintenance

### Health Checks

#### Service Health Monitoring

```bash
#!/bin/bash
# health_check.sh

SERVICES=("wazuh-manager" "wazuh-indexer" "wazuh-dashboard")
FAILED_SERVICES=()

for service in "${SERVICES[@]}"; do
  if ! docker ps | grep -q $service; then
    FAILED_SERVICES+=($service)
  fi
done

if [ ${#FAILED_SERVICES[@]} -gt 0 ]; then
  echo "CRITICAL: Failed services: ${FAILED_SERVICES[*]}"
  exit 2
else
  echo "OK: All services running"
  exit 0
fi
```

#### Performance Monitoring

```bash
#!/bin/bash
# performance_monitor.sh

# Check CPU usage
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')

# Check memory usage
MEM_USAGE=$(free | grep Mem | awk '{printf "%.2f", $3/$2 * 100.0}')

# Check disk usage
DISK_USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')

# Thresholds
CPU_THRESHOLD=80
MEM_THRESHOLD=85
DISK_THRESHOLD=90

# Check thresholds and alert
if (( $(echo "$CPU_USAGE > $CPU_THRESHOLD" | bc -l) )); then
  echo "WARNING: CPU usage is ${CPU_USAGE}%"
fi

if (( $(echo "$MEM_USAGE > $MEM_THRESHOLD" | bc -l) )); then
  echo "WARNING: Memory usage is ${MEM_USAGE}%"
fi

if [ $DISK_USAGE -gt $DISK_THRESHOLD ]; then
  echo "WARNING: Disk usage is ${DISK_USAGE}%"
fi
```

### Backup Procedures

#### Automated Backup Script

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/opt/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="wazuh_backup_$DATE"

mkdir -p $BACKUP_DIR/$BACKUP_NAME

# Backup Wazuh configuration
docker exec wazuh-manager tar czf /backup/wazuh_config.tar.gz /var/ossec/etc
docker cp wazuh-manager:/backup/wazuh_config.tar.gz $BACKUP_DIR/$BACKUP_NAME/

# Backup OpenSearch data
curl -X PUT "localhost:9200/_snapshot/backup" -H 'Content-Type: application/json' -d'
{
  "type": "fs",
  "settings": {
    "location": "/backup"
  }
}'

curl -X PUT "localhost:9200/_snapshot/backup/snapshot_$DATE" -H 'Content-Type: application/json' -d'
{
  "indices": "*",
  "ignore_unavailable": true,
  "include_global_state": false
}'

# Compress backup
cd $BACKUP_DIR
tar czf $BACKUP_NAME.tar.gz $BACKUP_NAME/
rm -rf $BACKUP_NAME/

# Upload to cloud storage (optional)
if [ "$UPLOAD_TO_S3" = "true" ]; then
  aws s3 cp $BACKUP_NAME.tar.gz s3://$S3_BUCKET/backups/
fi

# Cleanup old backups (keep last 7 days)
find $BACKUP_DIR -name "wazuh_backup_*.tar.gz" -mtime +7 -delete
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
