# Security Guide

This comprehensive security guide covers security hardening, best practices, threat prevention, and compliance considerations for the Wazuh SOC deployment project.

## 🛡️ Security Overview

The Wazuh SOC platform implements defense-in-depth security principles across multiple layers:

- **Network Security**: Firewall configuration and network segmentation
- **Transport Security**: SSL/TLS encryption and certificate management
- **Authentication & Authorization**: Multi-factor authentication and RBAC
- **Application Security**: Secure configuration and vulnerability management
- **Data Protection**: Encryption at rest and in transit
- **Monitoring & Auditing**: Security event logging and compliance

## 🔐 Authentication & Authorization

### Multi-Factor Authentication (MFA)

#### TOTP Integration

```yaml
# Enable TOTP in OpenSearch Dashboards
opensearch_security:
  config:
    dynamic:
      authc:
        basic_internal_auth_domain:
          http_enabled: true
          transport_enabled: true
          order: 1
          http_authenticator:
            type: basic
            challenge: true
          authentication_backend:
            type: internal
            config:
              totp_enabled: true
```

#### LDAP/Active Directory Integration

```yaml
# LDAP authentication configuration
opensearch_security:
  config:
    dynamic:
      authc:
        ldap_auth_domain:
          http_enabled: true
          transport_enabled: true
          order: 0
          http_authenticator:
            type: basic
            challenge: false
          authentication_backend:
            type: ldap
            config:
              hosts:
                - ldap.example.com:389
              bind_dn: cn=admin,dc=example,dc=com
              password: "${LDAP_PASSWORD}"
              userbase: 'ou=people,dc=example,dc=com'
              usersearch: '(uid={0})'
```

### Role-Based Access Control (RBAC)

#### Security Roles Definition

```yaml
# Custom security roles
wazuh_security_roles:
  security_analyst:
    cluster_permissions:
      - "cluster:monitor/main"
      - "cluster:monitor/health"
    index_permissions:
      - index_patterns: ["wazuh-alerts-*", "wazuh-events-*"]
        allowed_actions:
          - "indices:data/read/*"
          - "indices:admin/get"
    tenant_permissions:
      - tenant_patterns: ["analyst_workspace"]
        allowed_actions: ["kibana_all_read"]

  incident_responder:
    cluster_permissions:
      - "cluster:monitor/*"
      - "cluster:admin/opensearch/config/update"
    index_permissions:
      - index_patterns: ["wazuh-*"]
        allowed_actions:
          - "indices:data/read/*"
          - "indices:data/write/*"
          - "indices:admin/*"

  security_admin:
    cluster_permissions: ["*"]
    index_permissions:
      - index_patterns: ["*"]
        allowed_actions: ["*"]
```

#### User Management

```bash
#!/bin/bash
# User management script

# Create security analyst user
curl -X PUT "https://localhost:9200/_plugins/_security/api/internalusers/analyst1" \
  -u admin:SecretPassword \
  -H 'Content-Type: application/json' \
  -d '{
    "password": "AnalystPassword123!",
    "roles": ["security_analyst"],
    "attributes": {
      "department": "Security",
      "clearance_level": "classified"
    }
  }'

# Assign roles to user
curl -X PUT "https://localhost:9200/_plugins/_security/api/rolesmapping/security_analyst" \
  -u admin:SecretPassword \
  -H 'Content-Type: application/json' \
  -d '{
    "backend_roles": [],
    "hosts": [],
    "users": ["analyst1", "analyst2"]
  }'
```

## 🔒 Network Security

### Firewall Configuration

#### UFW (Ubuntu/Debian)

```bash
#!/bin/bash
# UFW firewall setup script

# Reset and set defaults
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# SSH access (restrict to specific IPs in production)
ufw allow from 192.168.1.0/24 to any port 22

# HTTP/HTTPS (public access)
ufw allow 80/tcp
ufw allow 443/tcp

# Wazuh Dashboard (restrict to authorized networks)
ufw allow from 10.0.0.0/8 to any port 5601

# Wazuh API (restrict to management networks)
ufw allow from 192.168.100.0/24 to any port 55000

# OpenSearch API (internal only)
ufw allow from 172.16.0.0/12 to any port 9200

# Agent communication
ufw allow 1514/tcp
ufw allow 1514/udp
ufw allow 1515/tcp

# Docker Swarm (if using multi-node)
ufw allow from 10.0.0.0/8 to any port 2377  # Management
ufw allow from 10.0.0.0/8 to any port 7946  # Node communication
ufw allow from 10.0.0.0/8 to any port 4789  # Overlay networks

# Enable firewall
ufw --force enable

# Verify configuration
ufw status numbered
```

#### iptables (RHEL/CentOS)

```bash
#!/bin/bash
# iptables configuration script

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# SSH (restrict source IPs)
iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT

# HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Wazuh services (restrict source networks)
iptables -A INPUT -s 10.0.0.0/8 -p tcp --dport 5601 -j ACCEPT
iptables -A INPUT -s 192.168.100.0/24 -p tcp --dport 55000 -j ACCEPT
iptables -A INPUT -s 172.16.0.0/12 -p tcp --dport 9200 -j ACCEPT

# Agent communication
iptables -A INPUT -p tcp --dport 1514 -j ACCEPT
iptables -A INPUT -p udp --dport 1514 -j ACCEPT
iptables -A INPUT -p tcp --dport 1515 -j ACCEPT

# Rate limiting for brute force protection
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j REJECT

# Save rules
iptables-save > /etc/sysconfig/iptables
```

### Network Segmentation

#### VLAN Configuration

```bash
# VLAN setup for network segmentation
# Management VLAN (VLAN 10)
vconfig add eth0 10
ifconfig eth0.10 192.168.10.100 netmask 255.255.255.0 up

# DMZ VLAN (VLAN 20) 
vconfig add eth0 20
ifconfig eth0.20 192.168.20.100 netmask 255.255.255.0 up

# Internal VLAN (VLAN 30)
vconfig add eth0 30
ifconfig eth0.30 192.168.30.100 netmask 255.255.255.0 up
```

#### Docker Network Security

```yaml
# Secure Docker network configuration
version: '3.8'

networks:
  wazuh_frontend:
    driver: overlay
    driver_opts:
      encrypted: "true"
    attachable: false
    
  wazuh_backend:
    driver: overlay
    driver_opts:
      encrypted: "true"
    internal: true  # No external access
    
  wazuh_management:
    driver: overlay
    driver_opts:
      encrypted: "true"
    attachable: false

services:
  wazuh.dashboard:
    networks:
      - wazuh_frontend
      - wazuh_backend
      
  wazuh.manager:
    networks:
      - wazuh_backend
      - wazuh_management
```

## 🔐 SSL/TLS Security

### Certificate Management

#### Let's Encrypt Integration

```bash
#!/bin/bash
# Automated Let's Encrypt certificate management

DOMAIN="wazuh.example.com"
EMAIL="security@example.com"
WEBROOT="/var/www/html"

# Install Certbot
apt-get update
apt-get install -y certbot python3-certbot-nginx

# Generate certificate
certbot --nginx \
  --non-interactive \
  --agree-tos \
  --email $EMAIL \
  --domains $DOMAIN \
  --redirect

# Setup auto-renewal
cat > /etc/cron.d/certbot << EOF
0 12 * * * root certbot renew --quiet && systemctl reload nginx
EOF

# Test renewal
certbot renew --dry-run
```

#### Custom CA Setup

```bash
#!/bin/bash
# Custom Certificate Authority setup

CA_DIR="/opt/ca"
mkdir -p $CA_DIR/{private,certs,crl,newcerts}

# Generate CA private key
openssl genrsa -aes256 -out $CA_DIR/private/ca.key.pem 4096
chmod 400 $CA_DIR/private/ca.key.pem

# Create CA certificate
openssl req -config $CA_DIR/openssl.conf \
  -key $CA_DIR/private/ca.key.pem \
  -new -x509 -days 7300 -sha256 -extensions v3_ca \
  -out $CA_DIR/certs/ca.cert.pem

# Generate server certificate
openssl genrsa -out $CA_DIR/private/wazuh.key.pem 2048
openssl req -config $CA_DIR/openssl.conf \
  -key $CA_DIR/private/wazuh.key.pem \
  -new -sha256 -out $CA_DIR/csr/wazuh.csr.pem

# Sign certificate
openssl ca -config $CA_DIR/openssl.conf \
  -extensions server_cert -days 375 -notext -md sha256 \
  -in $CA_DIR/csr/wazuh.csr.pem \
  -out $CA_DIR/certs/wazuh.cert.pem
```

### SSL Configuration

#### Nginx SSL Hardening

```nginx
# /etc/nginx/sites-available/wazuh-ssl.conf
server {
    listen 443 ssl http2;
    server_name wazuh.example.com;
    
    # SSL Certificate Configuration
    ssl_certificate /etc/letsencrypt/live/wazuh.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/wazuh.example.com/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/wazuh.example.com/chain.pem;
    
    # SSL Security Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # SSL Session Configuration
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'self';" always;
    
    # Remove server tokens
    server_tokens off;
    
    location / {
        proxy_pass http://wazuh_dashboard;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Security headers for proxied content
        proxy_hide_header X-Powered-By;
    }
}
```

## 🛠️ System Hardening

### Operating System Hardening

#### Ubuntu/Debian Hardening Script

```bash
#!/bin/bash
# System hardening script for Ubuntu/Debian

set -euo pipefail

echo "Starting system hardening..."

# Update system
apt-get update && apt-get upgrade -y

# Install security tools
apt-get install -y \
    fail2ban \
    rkhunter \
    chkrootkit \
    lynis \
    aide \
    auditd \
    apparmor \
    apparmor-profiles \
    apparmor-utils

# Configure automatic updates
cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Secure shared memory
if ! grep -q "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" /etc/fstab; then
    echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
fi

# Disable unused filesystems
cat > /etc/modprobe.d/blacklist-rare-filesystems.conf << EOF
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF

# Network security
cat >> /etc/sysctl.conf << EOF
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_all = 1

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
EOF

sysctl -p

# SSH hardening
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
cat > /etc/ssh/sshd_config << EOF
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentication
LoginGraceTime 60
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 2
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes

# Security options
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
Compression delayed
ClientAliveInterval 300
ClientAliveCountMax 2
AllowTcpForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no

# Logging
SyslogFacility AUTHPRIV
LogLevel VERBOSE
EOF

systemctl restart ssh

# Configure fail2ban
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[ssh]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-limit-req]
enabled = true
port = http,https
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 3
EOF

systemctl enable fail2ban
systemctl start fail2ban

echo "System hardening completed."
```

### Docker Security Hardening

#### Docker Daemon Configuration

```json
{
  "hosts": ["unix:///var/run/docker.sock"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "userland-proxy": false,
  "no-new-privileges": true,
  "selinux-enabled": true,
  "userns-remap": "default",
  "disable-legacy-registry": true,
  "live-restore": true,
  "icc": false,
  "default-ulimits": {
    "nofile": {
      "hard": 64000,
      "soft": 64000
    }
  },
  "storage-driver": "overlay2",
  "storage-opts": [
    "overlay2.override_kernel_check=true"
  ]
}
```

#### Secure Container Configuration

```yaml
# Security-hardened container configuration
version: '3.8'

services:
  wazuh.manager:
    image: wazuh/wazuh-manager:4.7.2
    
    # Security context
    user: "1000:1000"
    read_only: true
    cap_drop:
      - ALL
    cap_add:
      - SETUID
      - SETGID
      - CHOWN
      - DAC_OVERRIDE
    
    # Resource limits
    mem_limit: 4g
    mem_reservation: 2g
    cpus: '2.0'
    pids_limit: 1024
    
    # Security options
    security_opt:
      - no-new-privileges:true
      - apparmor:docker-default
      - seccomp:unconfined
    
    # Tmpfs mounts for writable areas
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
      - /var/run:noexec,nosuid,size=100m
    
    # Health check
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:55000 || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
```

## 🔍 Security Monitoring

### Security Event Rules

#### Custom Wazuh Rules

```xml
<!-- Custom security rules -->
<group name="local,syslog,sshd,authentication_failed">
  
  <!-- SSH brute force detection -->
  <rule id="100001" level="10" frequency="5" timeframe="300">
    <if_matched_sid>5503</if_matched_sid>
    <description>SSH brute force attack detected</description>
    <group>authentication_failure,pci_dss_8.2.3,pci_dss_8.2.5,gdpr_IV_32.2,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7</group>
  </rule>
  
  <!-- Privilege escalation detection -->
  <rule id="100002" level="12">
    <decoded_as>sudo</decoded_as>
    <field name="command">su -|sudo -u root|sudo su</field>
    <description>Privilege escalation attempt detected</description>
    <group>privilege_escalation,pci_dss_10.2.2,gpg13_7.8,gdpr_IV_32.2</group>
  </rule>
  
  <!-- File integrity monitoring -->
  <rule id="100003" level="7">
    <category>ossec</category>
    <decoded_as>syscheck</decoded_as>
    <field name="file">/etc/passwd|/etc/shadow|/etc/hosts</field>
    <description>Critical system file modified</description>
    <group>file_monitoring,pci_dss_11.5,gdpr_IV_32.2</group>
  </rule>
  
  <!-- Container escape detection -->
  <rule id="100004" level="15">
    <decoded_as>docker</decoded_as>
    <field name="action">exec|run</field>
    <field name="flags">--privileged|--pid=host|--net=host</field>
    <description>Potential container escape attempt</description>
    <group>container_security,pci_dss_2.2.4</group>
  </rule>
  
</group>
```

#### Active Response Rules

```xml
<!-- Active response configuration -->
<active-response>
  <!-- Block SSH brute force attacks -->
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100001</rules_id>
  <timeout>1800</timeout>
</active-response>

<active-response>
  <!-- Disable user account on privilege escalation -->
  <command>disable-account</command>
  <location>local</location>
  <rules_id>100002</rules_id>
  <timeout>3600</timeout>
</active-response>
```

### Security Dashboards

#### Custom Dashboard Configuration

```json
{
  "dashboard": {
    "title": "Security Operations Center",
    "panels": [
      {
        "title": "Security Alerts by Severity",
        "type": "visualization",
        "query": {
          "bool": {
            "must": [
              {"range": {"@timestamp": {"gte": "now-24h"}}},
              {"range": {"rule.level": {"gte": 7}}}
            ]
          }
        },
        "aggregations": {
          "severity_levels": {
            "terms": {
              "field": "rule.level",
              "size": 10
            }
          }
        }
      },
      {
        "title": "Top Attack Sources",
        "type": "visualization",
        "query": {
          "bool": {
            "must": [
              {"range": {"@timestamp": {"gte": "now-24h"}}},
              {"exists": {"field": "data.srcip"}}
            ]
          }
        },
        "aggregations": {
          "top_sources": {
            "terms": {
              "field": "data.srcip.keyword",
              "size": 20
            }
          }
        }
      }
    ]
  }
}
```

## 🏛️ Compliance & Governance

### PCI DSS Compliance

#### PCI DSS Configuration

```xml
<!-- PCI DSS compliance rules -->
<group name="pci_dss">
  
  <!-- Requirement 2.2.4: System security parameters -->
  <rule id="102001" level="3">
    <category>ossec</category>
    <decoded_as>rootcheck</decoded_as>
    <field name="title">System configuration check</field>
    <description>PCI DSS: System security parameters verified</description>
    <group>pci_dss_2.2.4</group>
  </rule>
  
  <!-- Requirement 8.2.3: Password complexity -->
  <rule id="102002" level="5">
    <decoded_as>pam</decoded_as>
    <field name="message">password check failed</field>
    <description>PCI DSS: Password complexity requirements not met</description>
    <group>pci_dss_8.2.3</group>
  </rule>
  
  <!-- Requirement 10.2.1: User access to cardholder data -->
  <rule id="102003" level="7">
    <category>web-log</category>
    <field name="url">/cardholder-data/</field>
    <description>PCI DSS: Access to cardholder data environment</description>
    <group>pci_dss_10.2.1</group>
  </rule>
  
</group>
```

### GDPR Compliance

#### Data Protection Monitoring

```xml
<!-- GDPR compliance rules -->
<group name="gdpr">
  
  <!-- Article 32: Security of processing -->
  <rule id="103001" level="5">
    <category>ossec</category>
    <decoded_as>syscheck</decoded_as>
    <field name="file">/var/www/html/personal-data/</field>
    <description>GDPR: Personal data file accessed or modified</description>
    <group>gdpr_IV_32.2</group>
  </rule>
  
  <!-- Article 33: Data breach notification -->
  <rule id="103002" level="12">
    <decoded_as>mysql</decoded_as>
    <field name="query">SELECT.*personal_data</field>
    <description>GDPR: Potential personal data breach detected</description>
    <group>gdpr_IV_33.1</group>
  </rule>
  
</group>
```

### SOX Compliance

#### Financial Controls Monitoring

```xml
<!-- SOX compliance rules -->
<group name="sox">
  
  <!-- Section 404: Internal controls -->
  <rule id="104001" level="8">
    <category>audit</category>
    <field name="action">financial_transaction</field>
    <description>SOX: Financial transaction audit trail</description>
    <group>sox_404</group>
  </rule>
  
</group>
```

## 🚨 Incident Response

### Automated Response Scripts

#### IP Blocking Script

```bash
#!/bin/bash
# Automated IP blocking for security incidents

ATTACKER_IP=$1
BLOCK_DURATION=${2:-3600}  # Default 1 hour
LOG_FILE="/var/log/wazuh/active-response.log"

if [ -z "$ATTACKER_IP" ]; then
    echo "Usage: $0 <IP_ADDRESS> [DURATION_SECONDS]"
    exit 1
fi

# Log the action
echo "$(date): Blocking IP $ATTACKER_IP for $BLOCK_DURATION seconds" >> $LOG_FILE

# Add firewall rule
iptables -I INPUT -s $ATTACKER_IP -j DROP

# Schedule removal
cat << EOF > /tmp/unblock_${ATTACKER_IP//\./_}.sh
#!/bin/bash
iptables -D INPUT -s $ATTACKER_IP -j DROP
echo "$(date): Unblocked IP $ATTACKER_IP" >> $LOG_FILE
rm /tmp/unblock_${ATTACKER_IP//\./_}.sh
EOF

chmod +x /tmp/unblock_${ATTACKER_IP//\./_}.sh
echo "/tmp/unblock_${ATTACKER_IP//\./_}.sh" | at now + $BLOCK_DURATION seconds

echo "IP $ATTACKER_IP blocked successfully"
```

#### Account Lockout Script

```bash
#!/bin/bash
# Automated user account lockout

USERNAME=$1
LOCKOUT_DURATION=${2:-3600}
LOG_FILE="/var/log/wazuh/active-response.log"

if [ -z "$USERNAME" ]; then
    echo "Usage: $0 <USERNAME> [DURATION_SECONDS]"
    exit 1
fi

# Log the action
echo "$(date): Locking account $USERNAME for $LOCKOUT_DURATION seconds" >> $LOG_FILE

# Lock the account
passwd -l $USERNAME

# Schedule unlock
cat << EOF > /tmp/unlock_${USERNAME}.sh
#!/bin/bash
passwd -u $USERNAME
echo "$(date): Unlocked account $USERNAME" >> $LOG_FILE
rm /tmp/unlock_${USERNAME}.sh
EOF

chmod +x /tmp/unlock_${USERNAME}.sh
echo "/tmp/unlock_${USERNAME}.sh" | at now + $LOCKOUT_DURATION seconds

echo "Account $USERNAME locked successfully"
```

## 📊 Security Metrics & KPIs

### Security Dashboard KPIs

```json
{
  "security_metrics": {
    "incident_response_time": {
      "target": "< 15 minutes",
      "current": "12 minutes",
      "trend": "improving"
    },
    "threat_detection_rate": {
      "target": "> 95%",
      "current": "97.3%",
      "trend": "stable"
    },
    "false_positive_rate": {
      "target": "< 5%", 
      "current": "3.2%",
      "trend": "improving"
    },
    "compliance_score": {
      "pci_dss": "98%",
      "gdpr": "96%",
      "sox": "97%"
    }
  }
}
```

### Automated Security Reports

```python
#!/usr/bin/env python3
# Security metrics report generator

import json
import datetime
from elasticsearch import Elasticsearch

class SecurityReportGenerator:
    def __init__(self, es_host="localhost", es_port=9200):
        self.es = Elasticsearch([f"{es_host}:{es_port}"])
    
    def generate_daily_report(self):
        """Generate daily security report"""
        end_time = datetime.datetime.now()
        start_time = end_time - datetime.timedelta(days=1)
        
        # High severity alerts
        high_severity = self.get_alerts_by_level(12, 15, start_time, end_time)
        
        # Attack sources
        attack_sources = self.get_top_attack_sources(start_time, end_time)
        
        # Blocked IPs
        blocked_ips = self.get_blocked_ips(start_time, end_time)
        
        report = {
            "date": end_time.strftime("%Y-%m-%d"),
            "summary": {
                "high_severity_alerts": len(high_severity),
                "unique_attack_sources": len(attack_sources),
                "blocked_ips": len(blocked_ips)
            },
            "details": {
                "high_severity_alerts": high_severity,
                "top_attack_sources": attack_sources[:10],
                "blocked_ips": blocked_ips
            }
        }
        
        return report
    
    def get_alerts_by_level(self, min_level, max_level, start_time, end_time):
        """Get alerts by severity level"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}},
                        {"range": {"rule.level": {"gte": min_level, "lte": max_level}}}
                    ]
                }
            }
        }
        
        result = self.es.search(index="wazuh-alerts-*", body=query, size=1000)
        return [hit["_source"] for hit in result["hits"]["hits"]]

if __name__ == "__main__":
    generator = SecurityReportGenerator()
    report = generator.generate_daily_report()
    print(json.dumps(report, indent=2, default=str))
```

## 🔧 Security Tools Integration

### SIEM Integration

#### Splunk Integration

```python
# Splunk HEC integration
import requests
import json

class SplunkHECClient:
    def __init__(self, hec_url, token):
        self.hec_url = hec_url
        self.token = token
        self.headers = {
            'Authorization': f'Splunk {token}',
            'Content-Type': 'application/json'
        }
    
    def send_event(self, event_data):
        """Send event to Splunk HEC"""
        payload = {
            "time": event_data.get("timestamp"),
            "host": event_data.get("agent", {}).get("name"),
            "source": "wazuh",
            "sourcetype": "wazuh:alert",
            "index": "security",
            "event": event_data
        }
        
        response = requests.post(
            f"{self.hec_url}/services/collector/event",
            headers=self.headers,
            data=json.dumps(payload),
            verify=False
        )
        
        return response.status_code == 200
```

#### QRadar Integration

```python
# IBM QRadar SIEM integration
import socket
import json
import syslog

class QRadarSIEMClient:
    def __init__(self, qradar_host, port=514):
        self.qradar_host = qradar_host
        self.port = port
    
    def send_alert(self, alert_data):
        """Send alert to QRadar via syslog"""
        priority = syslog.LOG_ALERT | syslog.LOG_LOCAL0
        
        message = f"CEF:0|Wazuh|Manager|4.7.2|{alert_data['rule']['id']}|{alert_data['rule']['description']}|{alert_data['rule']['level']}|src={alert_data.get('data', {}).get('srcip', 'unknown')} dst={alert_data.get('agent', {}).get('ip', 'unknown')}"
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(message.encode(), (self.qradar_host, self.port))
            return True
        except Exception as e:
            print(f"Error sending to QRadar: {e}")
            return False
        finally:
            sock.close()
```

---

This security guide provides comprehensive coverage of security hardening, monitoring, and compliance. For additional security information, see:
- [Troubleshooting Guide](troubleshooting.md)
- [Architecture Guide](architecture.md)  
- [API Documentation](api.md)
