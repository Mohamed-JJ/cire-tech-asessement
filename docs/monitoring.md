# Monitoring & Observability Guide

This comprehensive monitoring guide covers observability, alerting, performance monitoring, and operational insights for the Wazuh SOC deployment project.

## 📊 Monitoring Overview

The Wazuh SOC platform implements comprehensive observability across multiple layers:

- **Infrastructure Monitoring**: System resources, network, and hardware health
- **Application Monitoring**: Service performance and application metrics
- **Security Monitoring**: Threat detection and security event analysis
- **Log Aggregation**: Centralized logging and log analysis
- **Performance Monitoring**: Response times and throughput analysis
- **Alerting & Notifications**: Proactive incident detection and escalation

## 🔍 Infrastructure Monitoring

### System Resource Monitoring

#### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "wazuh_rules.yml"
  - "infrastructure_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['wazuh-manager:9100', 'wazuh-indexer:9100', 'wazuh-dashboard:9100']

  - job_name: 'docker'
    static_configs:
      - targets: ['localhost:9323']

  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx-exporter:9113']

  - job_name: 'opensearch'
    static_configs:
      - targets: ['wazuh-indexer:9200']
    metrics_path: '/_prometheus/metrics'
    scrape_interval: 30s

  - job_name: 'wazuh-manager'
    static_configs:
      - targets: ['wazuh-manager:55000']
    metrics_path: '/stats'
    scrape_interval: 30s
```

#### Node Exporter Setup

```yaml
# docker-compose.monitoring.yml
version: '3.8'

services:
  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    restart: unless-stopped
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.rootfs=/rootfs'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.ignored-mount-points=^/(sys|proc|dev|host|etc)($$|/)'
    ports:
      - "9100:9100"
    networks:
      - monitoring

  cadvisor:
    image: gcr.io/cadvisor/cadvisor:latest
    container_name: cadvisor
    restart: unless-stopped
    privileged: true
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:ro
      - /sys:/sys:ro
      - /var/lib/docker/:/var/lib/docker:ro
      - /dev/disk/:/dev/disk:ro
    ports:
      - "8080:8080"
    networks:
      - monitoring

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    volumes:
      - ./config/prometheus:/etc/prometheus
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=200h'
      - '--web.enable-lifecycle'
    ports:
      - "9090:9090"
    networks:
      - monitoring

networks:
  monitoring:
    driver: bridge

volumes:
  prometheus_data: {}
```

### Performance Monitoring Scripts

#### System Performance Monitor

```bash
#!/bin/bash
# System performance monitoring script

LOGFILE="/var/log/wazuh/system-performance.log"
THRESHOLD_CPU=80
THRESHOLD_MEMORY=85
THRESHOLD_DISK=90

# Function to log with timestamp
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOGFILE
}

# CPU utilization check
check_cpu() {
    CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2+$4}' | sed 's/%us,//')
    CPU_USAGE=${CPU_USAGE%.*}
    
    if [ "$CPU_USAGE" -gt "$THRESHOLD_CPU" ]; then
        log_message "ALERT: High CPU usage detected: ${CPU_USAGE}%"
        # Send alert to Wazuh
        logger -p local0.warning "High CPU usage: ${CPU_USAGE}%"
    fi
    
    echo "CPU Usage: ${CPU_USAGE}%"
}

# Memory utilization check
check_memory() {
    MEMORY_USAGE=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')
    
    if [ "$MEMORY_USAGE" -gt "$THRESHOLD_MEMORY" ]; then
        log_message "ALERT: High memory usage detected: ${MEMORY_USAGE}%"
        logger -p local0.warning "High memory usage: ${MEMORY_USAGE}%"
    fi
    
    echo "Memory Usage: ${MEMORY_USAGE}%"
}

# Disk utilization check
check_disk() {
    DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    if [ "$DISK_USAGE" -gt "$THRESHOLD_DISK" ]; then
        log_message "ALERT: High disk usage detected: ${DISK_USAGE}%"
        logger -p local0.warning "High disk usage: ${DISK_USAGE}%"
    fi
    
    echo "Disk Usage: ${DISK_USAGE}%"
}

# Network connectivity check
check_network() {
    # Check if services are responding
    SERVICES=("wazuh-manager:55000" "wazuh-indexer:9200" "wazuh-dashboard:5601")
    
    for service in "${SERVICES[@]}"; do
        host=$(echo $service | cut -d: -f1)
        port=$(echo $service | cut -d: -f2)
        
        if ! nc -z $host $port 2>/dev/null; then
            log_message "ALERT: Service $service is not responding"
            logger -p local0.error "Service $service is down"
        else
            echo "Service $service: OK"
        fi
    done
}

# Docker container health check
check_containers() {
    UNHEALTHY_CONTAINERS=$(docker ps --filter "health=unhealthy" --format "{{.Names}}")
    
    if [ ! -z "$UNHEALTHY_CONTAINERS" ]; then
        log_message "ALERT: Unhealthy containers detected: $UNHEALTHY_CONTAINERS"
        logger -p local0.error "Unhealthy containers: $UNHEALTHY_CONTAINERS"
    fi
    
    STOPPED_CONTAINERS=$(docker ps -a --filter "status=exited" --format "{{.Names}}")
    if [ ! -z "$STOPPED_CONTAINERS" ]; then
        log_message "WARNING: Stopped containers detected: $STOPPED_CONTAINERS"
        logger -p local0.warning "Stopped containers: $STOPPED_CONTAINERS"
    fi
}

# Main monitoring loop
main() {
    echo "=== System Performance Check $(date) ==="
    check_cpu
    check_memory
    check_disk
    check_network
    check_containers
    echo "=== End Performance Check ==="
}

# Run monitoring
main

# Schedule this script to run every 5 minutes via cron:
# */5 * * * * /opt/wazuh/scripts/performance_monitor.sh
```

## 📈 Application Monitoring

### Wazuh Service Monitoring

#### Wazuh API Health Check

```python
#!/usr/bin/env python3
"""
Wazuh API health monitoring script
"""

import requests
import json
import sys
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/wazuh/api-health.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class WazuhHealthMonitor:
    def __init__(self, api_url, username, password):
        self.api_url = api_url
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.token = None
        
    def authenticate(self):
        """Authenticate with Wazuh API"""
        try:
            auth_url = f"{self.api_url}/security/user/authenticate"
            response = self.session.post(
                auth_url,
                auth=(self.username, self.password),
                verify=False
            )
            
            if response.status_code == 200:
                self.token = response.json()['data']['token']
                self.session.headers.update({'Authorization': f'Bearer {self.token}'})
                return True
            else:
                logger.error(f"Authentication failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
    
    def check_manager_status(self):
        """Check Wazuh Manager status"""
        try:
            response = self.session.get(f"{self.api_url}/manager/status", verify=False)
            if response.status_code == 200:
                status_data = response.json()['data']['affected_items'][0]
                logger.info(f"Manager status: {status_data}")
                return status_data
            else:
                logger.error(f"Manager status check failed: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Manager status error: {e}")
            return None
    
    def check_agents_status(self):
        """Check agents status"""
        try:
            response = self.session.get(f"{self.api_url}/agents", verify=False)
            if response.status_code == 200:
                agents = response.json()['data']['affected_items']
                
                status_summary = {
                    'total': len(agents),
                    'active': len([a for a in agents if a['status'] == 'active']),
                    'disconnected': len([a for a in agents if a['status'] == 'disconnected']),
                    'never_connected': len([a for a in agents if a['status'] == 'never_connected'])
                }
                
                logger.info(f"Agents status: {status_summary}")
                
                # Alert on high disconnection rate
                if status_summary['total'] > 0:
                    disconnection_rate = (status_summary['disconnected'] / status_summary['total']) * 100
                    if disconnection_rate > 20:
                        logger.warning(f"High agent disconnection rate: {disconnection_rate:.1f}%")
                
                return status_summary
            else:
                logger.error(f"Agents status check failed: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Agents status error: {e}")
            return None
    
    def check_cluster_status(self):
        """Check cluster status (if applicable)"""
        try:
            response = self.session.get(f"{self.api_url}/cluster/status", verify=False)
            if response.status_code == 200:
                cluster_data = response.json()['data']['affected_items'][0]
                logger.info(f"Cluster status: {cluster_data}")
                return cluster_data
            else:
                logger.info("Cluster not configured or status unavailable")
                return None
        except Exception as e:
            logger.error(f"Cluster status error: {e}")
            return None
    
    def check_rules_and_decoders(self):
        """Check rules and decoders count"""
        try:
            # Check rules
            rules_response = self.session.get(f"{self.api_url}/rules", verify=False)
            decoders_response = self.session.get(f"{self.api_url}/decoders", verify=False)
            
            rules_count = 0
            decoders_count = 0
            
            if rules_response.status_code == 200:
                rules_count = rules_response.json()['data']['total_affected_items']
            
            if decoders_response.status_code == 200:
                decoders_count = decoders_response.json()['data']['total_affected_items']
            
            logger.info(f"Rules: {rules_count}, Decoders: {decoders_count}")
            return {'rules': rules_count, 'decoders': decoders_count}
            
        except Exception as e:
            logger.error(f"Rules/decoders check error: {e}")
            return None
    
    def generate_health_report(self):
        """Generate comprehensive health report"""
        if not self.authenticate():
            return False
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'manager_status': self.check_manager_status(),
            'agents_status': self.check_agents_status(),
            'cluster_status': self.check_cluster_status(),
            'rules_decoders': self.check_rules_and_decoders()
        }
        
        # Save report
        with open('/var/log/wazuh/health-report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        return report

if __name__ == "__main__":
    # Configuration
    API_URL = "https://localhost:55000"
    USERNAME = "wazuh"
    PASSWORD = "wazuh"  # Use environment variable in production
    
    monitor = WazuhHealthMonitor(API_URL, USERNAME, PASSWORD)
    report = monitor.generate_health_report()
    
    if report:
        print("Health check completed successfully")
        sys.exit(0)
    else:
        print("Health check failed")
        sys.exit(1)
```

### OpenSearch Monitoring

#### OpenSearch Health Check

```python
#!/usr/bin/env python3
"""
OpenSearch cluster health monitoring
"""

import requests
import json
import logging
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings for development
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

class OpenSearchMonitor:
    def __init__(self, host="localhost", port=9200, username="admin", password="admin"):
        self.base_url = f"https://{host}:{port}"
        self.auth = (username, password)
        
    def check_cluster_health(self):
        """Check OpenSearch cluster health"""
        try:
            response = requests.get(
                f"{self.base_url}/_cluster/health",
                auth=self.auth,
                verify=False
            )
            
            if response.status_code == 200:
                health_data = response.json()
                logger.info(f"Cluster health: {health_data['status']}")
                
                if health_data['status'] == 'red':
                    logger.error("Cluster status is RED - immediate attention required")
                elif health_data['status'] == 'yellow':
                    logger.warning("Cluster status is YELLOW - some shards are unassigned")
                
                return health_data
            else:
                logger.error(f"Health check failed: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Health check error: {e}")
            return None
    
    def check_node_stats(self):
        """Check node statistics"""
        try:
            response = requests.get(
                f"{self.base_url}/_nodes/stats",
                auth=self.auth,
                verify=False
            )
            
            if response.status_code == 200:
                stats_data = response.json()
                node_stats = {}
                
                for node_id, node_data in stats_data['nodes'].items():
                    node_name = node_data['name']
                    jvm = node_data['jvm']
                    fs = node_data['fs']['total']
                    
                    node_stats[node_name] = {
                        'heap_used_percent': jvm['mem']['heap_used_percent'],
                        'disk_used_percent': ((fs['total_in_bytes'] - fs['available_in_bytes']) / fs['total_in_bytes']) * 100,
                        'uptime': jvm['uptime_in_millis']
                    }
                    
                    # Check for high resource usage
                    if jvm['mem']['heap_used_percent'] > 80:
                        logger.warning(f"High heap usage on {node_name}: {jvm['mem']['heap_used_percent']}%")
                    
                    if node_stats[node_name]['disk_used_percent'] > 85:
                        logger.warning(f"High disk usage on {node_name}: {node_stats[node_name]['disk_used_percent']:.1f}%")
                
                return node_stats
                
        except Exception as e:
            logger.error(f"Node stats error: {e}")
            return None
    
    def check_index_health(self):
        """Check index health and sizes"""
        try:
            response = requests.get(
                f"{self.base_url}/_cat/indices?v&h=index,health,status,docs.count,store.size&format=json",
                auth=self.auth,
                verify=False
            )
            
            if response.status_code == 200:
                indices_data = response.json()
                
                for index in indices_data:
                    if index['health'] == 'red':
                        logger.error(f"Index {index['index']} is in RED state")
                    elif index['health'] == 'yellow':
                        logger.warning(f"Index {index['index']} is in YELLOW state")
                
                return indices_data
                
        except Exception as e:
            logger.error(f"Index health error: {e}")
            return None
    
    def check_performance_metrics(self):
        """Check performance metrics"""
        try:
            response = requests.get(
                f"{self.base_url}/_cluster/stats",
                auth=self.auth,
                verify=False
            )
            
            if response.status_code == 200:
                stats = response.json()
                
                performance_metrics = {
                    'total_shards': stats['indices']['shards']['total'],
                    'total_docs': stats['indices']['docs']['count'],
                    'store_size_gb': round(stats['indices']['store']['size_in_bytes'] / (1024**3), 2),
                    'query_time_ms': stats['indices']['query_cache']['total_count'],
                    'indexing_rate': stats['indices']['indexing']['index_total']
                }
                
                logger.info(f"Performance metrics: {performance_metrics}")
                return performance_metrics
                
        except Exception as e:
            logger.error(f"Performance metrics error: {e}")
            return None

if __name__ == "__main__":
    monitor = OpenSearchMonitor()
    
    # Run all checks
    cluster_health = monitor.check_cluster_health()
    node_stats = monitor.check_node_stats()
    index_health = monitor.check_index_health()
    performance = monitor.check_performance_metrics()
    
    # Generate report
    report = {
        'timestamp': datetime.now().isoformat(),
        'cluster_health': cluster_health,
        'node_stats': node_stats,
        'index_health': index_health,
        'performance_metrics': performance
    }
    
    with open('/var/log/wazuh/opensearch-health.json', 'w') as f:
        json.dump(report, f, indent=2)
```

## 🚨 Alerting & Notifications

### Alertmanager Configuration

```yaml
# alertmanager.yml
global:
  smtp_smarthost: 'localhost:587'
  smtp_from: 'alerts@example.com'
  slack_api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'

templates:
  - '/etc/alertmanager/templates/*.tmpl'

route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'
  routes:
  - match:
      severity: critical
    receiver: 'critical-alerts'
  - match:
      severity: warning
    receiver: 'warning-alerts'

receivers:
- name: 'web.hook'
  webhook_configs:
  - url: 'http://localhost:5001/'

- name: 'critical-alerts'
  email_configs:
  - to: 'security-team@example.com'
    subject: 'CRITICAL: {{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'
    body: |
      {{ range .Alerts }}
      Alert: {{ .Annotations.summary }}
      Description: {{ .Annotations.description }}
      Severity: {{ .Labels.severity }}
      Instance: {{ .Labels.instance }}
      Time: {{ .StartsAt }}
      {{ end }}
  slack_configs:
  - channel: '#security-alerts'
    color: 'danger'
    title: 'Critical Security Alert'
    text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'

- name: 'warning-alerts'
  email_configs:
  - to: 'operations@example.com'
    subject: 'WARNING: {{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'
    body: |
      {{ range .Alerts }}
      Alert: {{ .Annotations.summary }}
      Description: {{ .Annotations.description }}
      Severity: {{ .Labels.severity }}
      Instance: {{ .Labels.instance }}
      Time: {{ .StartsAt }}
      {{ end }}

inhibit_rules:
- source_match:
    severity: 'critical'
  target_match:
    severity: 'warning'
  equal: ['alertname', 'cluster', 'service']
```

### Custom Alert Rules

```yaml
# wazuh_rules.yml
groups:
- name: wazuh.rules
  rules:
  - alert: WazuhManagerDown
    expr: up{job="wazuh-manager"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Wazuh Manager is down"
      description: "Wazuh Manager has been down for more than 1 minute"

  - alert: HighSecurityAlertRate
    expr: rate(wazuh_alerts_total{level=~"12|13|14|15"}[5m]) > 10
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High rate of security alerts"
      description: "High severity alerts rate is {{ $value }} per second"

  - alert: OpenSearchClusterRed
    expr: opensearch_cluster_status{color="red"} == 1
    for: 30s
    labels:
      severity: critical
    annotations:
      summary: "OpenSearch cluster is in red state"
      description: "OpenSearch cluster health is red, immediate attention required"

  - alert: HighMemoryUsage
    expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes > 0.90
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High memory usage detected"
      description: "Memory usage is above 90% on {{ $labels.instance }}"

  - alert: HighDiskUsage
    expr: (node_filesystem_size_bytes - node_filesystem_avail_bytes) / node_filesystem_size_bytes > 0.85
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High disk usage detected"
      description: "Disk usage is above 85% on {{ $labels.instance }}"

  - alert: ContainerHighCPU
    expr: rate(container_cpu_usage_seconds_total[1m]) * 100 > 80
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Container high CPU usage"
      description: "Container {{ $labels.name }} CPU usage is above 80%"

  - alert: DockerContainerDown
    expr: up{job="docker"} == 0
    for: 30s
    labels:
      severity: critical
    annotations:
      summary: "Docker container is down"
      description: "Docker container {{ $labels.instance }} has been down for more than 30 seconds"
```

### Notification Integrations

#### Slack Integration

```python
#!/usr/bin/env python3
"""
Slack notification integration for Wazuh alerts
"""

import requests
import json
import sys
from datetime import datetime

class SlackNotifier:
    def __init__(self, webhook_url, channel="#security-alerts"):
        self.webhook_url = webhook_url
        self.channel = channel
    
    def send_alert(self, alert_data):
        """Send alert to Slack"""
        
        # Extract alert information
        rule_level = alert_data.get('rule', {}).get('level', 0)
        rule_description = alert_data.get('rule', {}).get('description', 'Unknown')
        agent_name = alert_data.get('agent', {}).get('name', 'Unknown')
        timestamp = alert_data.get('timestamp', datetime.now().isoformat())
        
        # Determine color based on severity
        if rule_level >= 12:
            color = "danger"  # Red
            emoji = ":rotating_light:"
        elif rule_level >= 7:
            color = "warning"  # Orange
            emoji = ":warning:"
        else:
            color = "good"  # Green
            emoji = ":information_source:"
        
        # Create Slack message
        message = {
            "channel": self.channel,
            "username": "Wazuh SOC",
            "icon_emoji": ":shield:",
            "attachments": [
                {
                    "color": color,
                    "title": f"{emoji} Security Alert - Level {rule_level}",
                    "text": rule_description,
                    "fields": [
                        {
                            "title": "Agent",
                            "value": agent_name,
                            "short": True
                        },
                        {
                            "title": "Timestamp",
                            "value": timestamp,
                            "short": True
                        },
                        {
                            "title": "Rule ID",
                            "value": alert_data.get('rule', {}).get('id', 'Unknown'),
                            "short": True
                        }
                    ],
                    "footer": "Wazuh SOC Platform",
                    "ts": int(datetime.now().timestamp())
                }
            ]
        }
        
        # Add additional context if available
        if 'data' in alert_data:
            data_fields = []
            for key, value in alert_data['data'].items():
                if key in ['srcip', 'dstip', 'srcport', 'dstport', 'protocol']:
                    data_fields.append({
                        "title": key.capitalize(),
                        "value": str(value),
                        "short": True
                    })
            
            message["attachments"][0]["fields"].extend(data_fields)
        
        try:
            response = requests.post(self.webhook_url, json=message)
            return response.status_code == 200
        except Exception as e:
            print(f"Error sending Slack notification: {e}")
            return False

if __name__ == "__main__":
    # Example usage
    webhook_url = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
    notifier = SlackNotifier(webhook_url)
    
    # Sample alert data
    sample_alert = {
        "rule": {
            "id": "5503",
            "level": 10,
            "description": "SSH authentication failed"
        },
        "agent": {
            "name": "web-server-01"
        },
        "data": {
            "srcip": "192.168.1.100",
            "dstport": "22"
        },
        "timestamp": datetime.now().isoformat()
    }
    
    success = notifier.send_alert(sample_alert)
    print(f"Notification sent: {success}")
```

#### Email Notifications

```python
#!/usr/bin/env python3
"""
Email notification system for Wazuh alerts
"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import json

class EmailNotifier:
    def __init__(self, smtp_server, smtp_port, username, password):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
    
    def send_alert_email(self, alert_data, recipients):
        """Send alert email notification"""
        
        # Create message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"Security Alert - Level {alert_data.get('rule', {}).get('level', 0)}"
        msg["From"] = self.username
        msg["To"] = ", ".join(recipients)
        
        # Create HTML content
        html_content = self._generate_html_alert(alert_data)
        html_part = MIMEText(html_content, "html")
        
        # Create plain text content
        text_content = self._generate_text_alert(alert_data)
        text_part = MIMEText(text_content, "plain")
        
        # Add parts to message
        msg.attach(text_part)
        msg.attach(html_part)
        
        try:
            # Create secure connection and send email
            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls(context=context)
                server.login(self.username, self.password)
                server.sendmail(self.username, recipients, msg.as_string())
            return True
        except Exception as e:
            print(f"Error sending email: {e}")
            return False
    
    def _generate_html_alert(self, alert_data):
        """Generate HTML email content"""
        rule = alert_data.get('rule', {})
        agent = alert_data.get('agent', {})
        data = alert_data.get('data', {})
        
        html = f"""
        <html>
        <body>
            <h2 style="color: {'red' if rule.get('level', 0) >= 12 else 'orange' if rule.get('level', 0) >= 7 else 'green'};">
                Security Alert - Level {rule.get('level', 0)}
            </h2>
            
            <table border="1" cellpadding="10" cellspacing="0" style="border-collapse: collapse;">
                <tr>
                    <td><strong>Rule Description:</strong></td>
                    <td>{rule.get('description', 'Unknown')}</td>
                </tr>
                <tr>
                    <td><strong>Rule ID:</strong></td>
                    <td>{rule.get('id', 'Unknown')}</td>
                </tr>
                <tr>
                    <td><strong>Agent:</strong></td>
                    <td>{agent.get('name', 'Unknown')}</td>
                </tr>
                <tr>
                    <td><strong>Timestamp:</strong></td>
                    <td>{alert_data.get('timestamp', datetime.now().isoformat())}</td>
                </tr>
        """
        
        # Add data fields if available
        for key, value in data.items():
            html += f"""
                <tr>
                    <td><strong>{key.capitalize()}:</strong></td>
                    <td>{value}</td>
                </tr>
            """
        
        html += """
            </table>
            
            <br>
            <p><em>This is an automated security alert from the Wazuh SOC platform.</em></p>
        </body>
        </html>
        """
        
        return html
    
    def _generate_text_alert(self, alert_data):
        """Generate plain text email content"""
        rule = alert_data.get('rule', {})
        agent = alert_data.get('agent', {})
        data = alert_data.get('data', {})
        
        text = f"""
SECURITY ALERT - LEVEL {rule.get('level', 0)}

Rule Description: {rule.get('description', 'Unknown')}
Rule ID: {rule.get('id', 'Unknown')}
Agent: {agent.get('name', 'Unknown')}
Timestamp: {alert_data.get('timestamp', datetime.now().isoformat())}

"""
        
        # Add data fields if available
        if data:
            text += "Alert Data:\n"
            for key, value in data.items():
                text += f"{key.capitalize()}: {value}\n"
        
        text += "\nThis is an automated security alert from the Wazuh SOC platform."
        
        return text

if __name__ == "__main__":
    # Configuration
    SMTP_SERVER = "smtp.example.com"
    SMTP_PORT = 587
    USERNAME = "alerts@example.com"
    PASSWORD = "your-password"
    RECIPIENTS = ["security@example.com", "admin@example.com"]
    
    notifier = EmailNotifier(SMTP_SERVER, SMTP_PORT, USERNAME, PASSWORD)
    
    # Sample alert
    sample_alert = {
        "rule": {
            "id": "5503",
            "level": 10,
            "description": "SSH authentication failed"
        },
        "agent": {
            "name": "web-server-01"
        },
        "data": {
            "srcip": "192.168.1.100",
            "user": "admin",
            "dstport": "22"
        },
        "timestamp": datetime.now().isoformat()
    }
    
    success = notifier.send_alert_email(sample_alert, RECIPIENTS)
    print(f"Email sent: {success}")
```

## 📊 Dashboards & Visualization

### Grafana Dashboard Configuration

#### Main SOC Dashboard

```json
{
  "dashboard": {
    "title": "Wazuh SOC Operations Dashboard",
    "tags": ["wazuh", "security", "soc"],
    "timezone": "UTC",
    "panels": [
      {
        "id": 1,
        "title": "Security Alerts by Severity",
        "type": "stat",
        "targets": [
          {
            "expr": "sum by (level) (wazuh_alerts_total)",
            "legendFormat": "Level {{level}}"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "color": {
              "mode": "palette-classic"
            },
            "custom": {
              "displayMode": "list",
              "orientation": "horizontal"
            }
          }
        }
      },
      {
        "id": 2,
        "title": "System Resource Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "100 - (avg by (instance) (irate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)",
            "legendFormat": "CPU Usage - {{instance}}"
          },
          {
            "expr": "(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100",
            "legendFormat": "Memory Usage - {{instance}}"
          }
        ]
      },
      {
        "id": 3,
        "title": "OpenSearch Cluster Health",
        "type": "singlestat",
        "targets": [
          {
            "expr": "opensearch_cluster_status",
            "legendFormat": "Cluster Status"
          }
        ]
      },
      {
        "id": 4,
        "title": "Top Attack Sources",
        "type": "table",
        "targets": [
          {
            "expr": "topk(10, sum by (srcip) (wazuh_alerts_total{srcip!=\"\"}))",
            "format": "table"
          }
        ]
      },
      {
        "id": 5,
        "title": "Agent Status Distribution",
        "type": "piechart",
        "targets": [
          {
            "expr": "sum by (status) (wazuh_agents_status)",
            "legendFormat": "{{status}}"
          }
        ]
      }
    ],
    "time": {
      "from": "now-24h",
      "to": "now"
    },
    "refresh": "30s"
  }
}
```

### Custom Metrics Collection

#### Wazuh Metrics Exporter

```python
#!/usr/bin/env python3
"""
Custom Prometheus metrics exporter for Wazuh
"""

import time
import requests
import json
from prometheus_client import start_http_server, Gauge, Counter
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Prometheus metrics
WAZUH_ALERTS_TOTAL = Counter('wazuh_alerts_total', 'Total Wazuh alerts', ['level', 'rule_id', 'agent_name'])
WAZUH_AGENTS_ACTIVE = Gauge('wazuh_agents_active', 'Number of active agents')
WAZUH_AGENTS_DISCONNECTED = Gauge('wazuh_agents_disconnected', 'Number of disconnected agents')
WAZUH_MANAGER_UPTIME = Gauge('wazuh_manager_uptime_seconds', 'Wazuh manager uptime in seconds')
OPENSEARCH_CLUSTER_STATUS = Gauge('opensearch_cluster_status', 'OpenSearch cluster status', ['color'])

class WazuhMetricsExporter:
    def __init__(self, wazuh_api_url, opensearch_url, username, password):
        self.wazuh_api_url = wazuh_api_url
        self.opensearch_url = opensearch_url
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.token = None
        
    def authenticate(self):
        """Authenticate with Wazuh API"""
        try:
            response = self.session.post(
                f"{self.wazuh_api_url}/security/user/authenticate",
                auth=(self.username, self.password),
                verify=False
            )
            if response.status_code == 200:
                self.token = response.json()['data']['token']
                self.session.headers.update({'Authorization': f'Bearer {self.token}'})
                return True
        except Exception as e:
            print(f"Authentication error: {e}")
        return False
    
    def collect_agent_metrics(self):
        """Collect agent status metrics"""
        try:
            response = self.session.get(f"{self.wazuh_api_url}/agents", verify=False)
            if response.status_code == 200:
                agents = response.json()['data']['affected_items']
                
                active_count = len([a for a in agents if a['status'] == 'active'])
                disconnected_count = len([a for a in agents if a['status'] == 'disconnected'])
                
                WAZUH_AGENTS_ACTIVE.set(active_count)
                WAZUH_AGENTS_DISCONNECTED.set(disconnected_count)
                
        except Exception as e:
            print(f"Error collecting agent metrics: {e}")
    
    def collect_opensearch_metrics(self):
        """Collect OpenSearch cluster metrics"""
        try:
            response = requests.get(
                f"{self.opensearch_url}/_cluster/health",
                auth=(self.username, self.password),
                verify=False
            )
            if response.status_code == 200:
                health = response.json()
                
                # Set cluster status (0=red, 1=yellow, 2=green)
                status_map = {'red': 0, 'yellow': 1, 'green': 2}
                OPENSEARCH_CLUSTER_STATUS.labels(color=health['status']).set(status_map[health['status']])
                
        except Exception as e:
            print(f"Error collecting OpenSearch metrics: {e}")
    
    def collect_alert_metrics(self):
        """Collect alert metrics from OpenSearch"""
        try:
            # Query recent alerts
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": "now-5m"
                        }
                    }
                },
                "aggs": {
                    "by_level": {
                        "terms": {
                            "field": "rule.level"
                        }
                    }
                }
            }
            
            response = requests.post(
                f"{self.opensearch_url}/wazuh-alerts-*/_search",
                auth=(self.username, self.password),
                json=query,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Update alert counters
                for bucket in data.get('aggregations', {}).get('by_level', {}).get('buckets', []):
                    level = bucket['key']
                    count = bucket['doc_count']
                    WAZUH_ALERTS_TOTAL.labels(level=level, rule_id='', agent_name='').inc(count)
                    
        except Exception as e:
            print(f"Error collecting alert metrics: {e}")
    
    def run(self):
        """Main collection loop"""
        while True:
            if not self.token and not self.authenticate():
                print("Failed to authenticate, retrying in 30 seconds...")
                time.sleep(30)
                continue
                
            self.collect_agent_metrics()
            self.collect_opensearch_metrics()
            self.collect_alert_metrics()
            
            time.sleep(30)

if __name__ == "__main__":
    # Configuration
    WAZUH_API_URL = "https://localhost:55000"
    OPENSEARCH_URL = "https://localhost:9200"
    USERNAME = "admin"
    PASSWORD = "admin"
    METRICS_PORT = 8000
    
    # Start Prometheus metrics server
    start_http_server(METRICS_PORT)
    print(f"Metrics server started on port {METRICS_PORT}")
    
    # Start metrics collection
    exporter = WazuhMetricsExporter(WAZUH_API_URL, OPENSEARCH_URL, USERNAME, PASSWORD)
    exporter.run()
```

## 📋 Maintenance & Operations

### Log Rotation and Management

```bash
#!/bin/bash
# Log rotation and cleanup script

LOG_DIRS=(
    "/var/log/wazuh"
    "/var/log/opensearch"
    "/var/log/nginx"
    "/var/log/prometheus"
)

RETENTION_DAYS=30
COMPRESSION_DAYS=7

for log_dir in "${LOG_DIRS[@]}"; do
    if [ -d "$log_dir" ]; then
        echo "Processing log directory: $log_dir"
        
        # Compress logs older than 7 days
        find "$log_dir" -name "*.log" -type f -mtime +$COMPRESSION_DAYS -exec gzip {} \;
        
        # Remove logs older than 30 days
        find "$log_dir" -name "*.log.gz" -type f -mtime +$RETENTION_DAYS -delete
        
        # Remove empty directories
        find "$log_dir" -type d -empty -delete
    fi
done

# OpenSearch index cleanup
curl -X DELETE "https://localhost:9200/wazuh-alerts-$(date -d '30 days ago' +%Y.%m.%d)" \
  -u admin:admin -k 2>/dev/null

echo "Log cleanup completed"
```

### Health Check Automation

```bash
#!/bin/bash
# Automated health check script

HEALTH_CHECK_LOG="/var/log/wazuh/health-checks.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$HEALTH_CHECK_LOG"
}

# Check Docker containers
check_docker_health() {
    log_message "Checking Docker container health..."
    
    unhealthy_containers=$(docker ps --filter "health=unhealthy" --format "{{.Names}}")
    if [ ! -z "$unhealthy_containers" ]; then
        log_message "ALERT: Unhealthy containers found: $unhealthy_containers"
        return 1
    fi
    
    log_message "All Docker containers are healthy"
    return 0
}

# Check service endpoints
check_endpoints() {
    log_message "Checking service endpoints..."
    
    endpoints=(
        "https://localhost:5601:Wazuh Dashboard"
        "https://localhost:9200:OpenSearch"
        "https://localhost:55000:Wazuh API"
    )
    
    for endpoint in "${endpoints[@]}"; do
        url=$(echo $endpoint | cut -d: -f1-2)
        name=$(echo $endpoint | cut -d: -f3)
        
        if curl -k -s --connect-timeout 10 "$url" > /dev/null; then
            log_message "$name endpoint is responding"
        else
            log_message "ALERT: $name endpoint is not responding"
            return 1
        fi
    done
    
    return 0
}

# Check disk space
check_disk_space() {
    log_message "Checking disk space..."
    
    usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ "$usage" -gt 85 ]; then
        log_message "ALERT: High disk usage: ${usage}%"
        return 1
    fi
    
    log_message "Disk usage is normal: ${usage}%"
    return 0
}

# Main health check
main() {
    log_message "Starting health check..."
    
    exit_code=0
    
    check_docker_health || exit_code=1
    check_endpoints || exit_code=1
    check_disk_space || exit_code=1
    
    if [ $exit_code -eq 0 ]; then
        log_message "Health check passed"
    else
        log_message "Health check failed - alerts generated"
    fi
    
    return $exit_code
}

main
```

---

This monitoring guide provides comprehensive observability coverage for the Wazuh SOC platform. For additional operational information, see:
- [Troubleshooting Guide](troubleshooting.md)
- [Security Guide](security.md)
- [API Documentation](api.md)
