# API Documentation

This document provides comprehensive API documentation for the Wazuh SOC deployment project, including REST API endpoints, authentication methods, and integration examples.

## 🔗 API Overview

The Wazuh SOC platform exposes several APIs for integration and automation:

- **Wazuh Manager API**: Core security management operations
- **OpenSearch API**: Data search and analytics
- **Dashboard API**: Web interface operations
- **Custom Health API**: System monitoring endpoints

## 📡 Wazuh Manager API

### Base Information

```
Base URL: https://your-server.com:55000
API Version: 4.7.2
Authentication: Basic Auth, JWT Token
Content-Type: application/json
```

### Authentication

#### Basic Authentication

```bash
# Basic Auth with username/password
curl -u admin:SecretPassword https://localhost:55000/

# Response includes authentication token
{
  "data": {
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
  }
}
```

#### JWT Token Authentication

```bash
# Get authentication token
TOKEN=$(curl -u admin:SecretPassword -X POST "https://localhost:55000/security/user/authenticate" | jq -r '.data.token')

# Use token for subsequent requests
curl -H "Authorization: Bearer $TOKEN" https://localhost:55000/agents
```

### Core Endpoints

#### Agents Management

##### List All Agents

```bash
GET /agents
```

**Parameters:**
- `offset` (int): Skip first n results
- `limit` (int): Maximum number of results (default: 500)
- `select` (string): Fields to return
- `sort` (string): Sort criteria
- `search` (string): Search term
- `status` (string): Agent status (active, pending, never_connected, disconnected)

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/agents?status=active&limit=10"

# Response
{
  "data": {
    "affected_items": [
      {
        "id": "001",
        "name": "server01",
        "ip": "192.168.1.100",
        "status": "active",
        "os": {
          "platform": "ubuntu",
          "name": "Ubuntu",
          "version": "20.04"
        },
        "node_name": "node01",
        "dateAdd": "2024-01-01T10:00:00.000Z",
        "lastKeepAlive": "2024-01-01T12:00:00.000Z"
      }
    ],
    "total_affected_items": 1,
    "total_failed_items": 0,
    "failed_items": []
  }
}
```

##### Get Agent Details

```bash
GET /agents/{agent_id}
```

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://localhost:55000/agents/001

# Response
{
  "data": {
    "affected_items": [
      {
        "id": "001",
        "name": "server01",
        "ip": "192.168.1.100",
        "status": "active",
        "configSum": "ab73af41699f13fdd85a3b5e3e7b",
        "mergedSum": "dd265d6e7e4ae8e6e5c5b4b8f5c5",
        "os": {
          "arch": "x86_64",
          "major": "20",
          "minor": "04",
          "name": "Ubuntu",
          "platform": "ubuntu",
          "uname": "Linux |server01 |5.4.0-74-generic |#83-Ubuntu SMP",
          "version": "20.04"
        }
      }
    ]
  }
}
```

##### Add New Agent

```bash
POST /agents
```

**Request Body:**

```json
{
  "name": "new-agent",
  "ip": "192.168.1.200",
  "force": {
    "enabled": true,
    "disconnected_time": {
      "enabled": true,
      "value": "1h"
    },
    "after_registration_time": "1h"
  }
}
```

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST https://localhost:55000/agents \
  -d '{
    "name": "web-server-01",
    "ip": "10.0.1.100"
  }'

# Response
{
  "data": {
    "id": "002",
    "key": "MDI1IGFnZW50LTAxIDEwLjAuMS4xMDAgMTk4N..."
  }
}
```

##### Delete Agent

```bash
DELETE /agents
```

**Parameters:**
- `agents_list` (string): Comma-separated list of agent IDs
- `purge` (boolean): Remove agent files completely

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  -X DELETE "https://localhost:55000/agents?agents_list=002&purge=true"
```

#### Rules Management

##### List Rules

```bash
GET /rules
```

**Parameters:**
- `rule_ids` (string): Comma-separated list of rule IDs
- `status` (string): Rule status (enabled, disabled)
- `group` (string): Rule group
- `level` (string): Rule level
- `filename` (string): Rules filename
- `relative_dirname` (string): Relative directory path
- `pci_dss` (string): PCI DSS requirement
- `gpg13` (string): GPG 13 requirement
- `gdpr` (string): GDPR requirement
- `hipaa` (string): HIPAA requirement
- `nist_800_53` (string): NIST 800-53 requirement

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/rules?level=10&limit=5"

# Response
{
  "data": {
    "affected_items": [
      {
        "id": 100002,
        "level": 10,
        "description": "System disconnected.",
        "groups": ["wazuh", "agent"],
        "status": "enabled",
        "filename": "agent.xml",
        "relative_dirname": "ruleset/rules",
        "pci_dss": ["10.6.1"],
        "gpg13": ["4.14"],
        "gdpr": ["IV_35.7.d"]
      }
    ]
  }
}
```

##### Get Rule Details

```bash
GET /rules/{rule_id}
```

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://localhost:55000/rules/5503

# Response
{
  "data": {
    "affected_items": [
      {
        "id": 5503,
        "level": 5,
        "description": "User authentication failure.",
        "groups": ["authentication_failure", "pam", "syslog"],
        "firedtimes": 4321,
        "mail": false,
        "status": "enabled",
        "details": {
          "regex": "authentication failure",
          "decoded_as": "pam"
        }
      }
    ]
  }
}
```

#### Alerts & Events

##### Get Alerts

```bash
GET /alerts
```

**Parameters:**
- `offset` (int): Skip first n results  
- `limit` (int): Maximum results (default: 500)
- `sort` (string): Sort criteria
- `search` (string): Search term
- `rule.id` (int): Filter by rule ID
- `rule.level` (string): Filter by rule level
- `agent.id` (string): Filter by agent ID
- `timestamp` (string): Filter by timestamp

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/alerts?rule.level=10&limit=3"

# Response
{
  "data": {
    "affected_items": [
      {
        "id": "1641852487.49031",
        "timestamp": "2024-01-01T12:34:56.789Z",
        "rule": {
          "id": 100002,
          "level": 10,
          "description": "System disconnected",
          "groups": ["wazuh", "agent"]
        },
        "agent": {
          "id": "001",
          "name": "server01",
          "ip": "192.168.1.100"
        },
        "manager": {
          "name": "wazuh-manager"
        },
        "cluster": {
          "name": "wazuh",
          "node": "node01"
        },
        "full_log": "2024/01/01 12:34:56 wazuh-agent: Agent disconnected.",
        "decoder": {
          "name": "wazuh"
        },
        "location": "/var/ossec/logs/alerts/alerts.log"
      }
    ]
  }
}
```

##### Get Alert Summary

```bash
GET /alerts/summary
```

**Parameters:**
- `agents_list` (string): Comma-separated agent IDs
- `rule.level` (string): Rule level range
- `timestamp` (string): Time range

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/alerts/summary?rule.level=5-15"

# Response
{
  "data": {
    "totalAlerts": 15420,
    "level_distribution": {
      "5": 8523,
      "7": 4231,
      "10": 2145,
      "12": 412,
      "15": 109
    },
    "top_agents": [
      {"id": "001", "name": "server01", "count": 3421},
      {"id": "002", "name": "web01", "count": 2876}
    ],
    "top_rules": [
      {"id": 5503, "description": "Authentication failure", "count": 1234},
      {"id": 1002, "description": "Unknown problem", "count": 876}
    ]
  }
}
```

#### System Information

##### Manager Information

```bash
GET /manager/info
```

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://localhost:55000/manager/info

# Response  
{
  "data": {
    "affected_items": [
      {
        "version": "v4.7.2",
        "compilation_date": "2024-01-01",
        "installation_date": "2024-01-01T00:00:00.000Z",
        "path": "/var/ossec",
        "type": "server",
        "max_agents": "14000",
        "openssl_support": "yes",
        "ruleset_version": "4.7.2",
        "tz_offset": "+0000",
        "tz_name": "UTC"
      }
    ]
  }
}
```

##### Manager Status

```bash
GET /manager/status
```

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://localhost:55000/manager/status

# Response
{
  "data": {
    "affected_items": [
      {
        "wazuh-modulesd": "running",
        "wazuh-monitord": "running", 
        "wazuh-logcollector": "running",
        "wazuh-remoted": "running",
        "wazuh-execd": "running",
        "wazuh-analysisd": "running",
        "wazuh-authd": "running",
        "wazuh-syscheckd": "running",
        "wazuh-clusterd": "running",
        "wazuh-apid": "running"
      }
    ]
  }
}
```

##### Manager Statistics

```bash
GET /manager/stats
```

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://localhost:55000/manager/stats

# Response
{
  "data": {
    "affected_items": [
      {
        "analysisd": {
          "events_processed": 1847123,
          "events_received": 1847123,
          "events_dropped": 0,
          "alerts_written": 4231,
          "firewall_written": 0,
          "fts_written": 0
        },
        "remoted": {
          "queue_size": 0,
          "total_queue_size": 131072,
          "tcp_sessions": 3,
          "evt_count": 1847123,
          "ctrl_msg_count": 523,
          "discarded_count": 0,
          "sent_breakdown": {
            "agent_ack": 421,
            "agent_startup": 12,
            "agent_shutdown": 8
          }
        }
      }
    ]
  }
}
```

#### Configuration Management

##### Get Configuration

```bash
GET /manager/configuration
```

**Parameters:**
- `component` (string): Configuration component
- `configuration` (string): Configuration section

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/manager/configuration?component=analysis&configuration=global"

# Response
{
  "data": {
    "affected_items": [
      {
        "analysis": {
          "global": {
            "email_notification": "yes",
            "alerts_log": "yes",
            "jsonout_output": "yes",
            "stats": "yes",
            "memory_size": 8192,
            "white_list": ["127.0.0.1", "^localhost.localdomain$"]
          }
        }
      }
    ]
  }
}
```

##### Update Configuration

```bash
PUT /manager/configuration
```

**Request Body:**

```xml
<ossec_config>
  <global>
    <email_notification>yes</email_notification>
    <smtp_server>smtp.example.com</smtp_server>
    <email_from>wazuh@example.com</email_from>
    <email_to>admin@example.com</email_to>
  </global>
</ossec_config>
```

#### Security Management

##### List Users

```bash
GET /security/users
```

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://localhost:55000/security/users

# Response
{
  "data": {
    "affected_items": [
      {
        "id": 1,
        "username": "admin",
        "allow_run_as": false,
        "roles": [1, 2]
      },
      {
        "id": 2,
        "username": "readonly",
        "allow_run_as": false,
        "roles": [3]
      }
    ]
  }
}
```

##### Create User

```bash
POST /security/users
```

**Request Body:**

```json
{
  "username": "analyst",
  "password": "AnalystPassword123!"
}
```

##### Assign Roles

```bash
POST /security/users/{user_id}/roles
```

**Request Body:**

```json
{
  "role_ids": [3, 4]
}
```

## 🔍 OpenSearch API

### Base Information

```
Base URL: https://your-server.com:9200
API Version: 2.10.0
Authentication: Basic Auth
Content-Type: application/json
```

### Cluster Operations

#### Cluster Health

```bash
curl -u admin:SecretPassword \
  -X GET "https://localhost:9200/_cluster/health?pretty"

# Response
{
  "cluster_name": "wazuh-cluster",
  "status": "green",
  "timed_out": false,
  "number_of_nodes": 3,
  "number_of_data_nodes": 3,
  "active_primary_shards": 15,
  "active_shards": 30,
  "relocating_shards": 0,
  "initializing_shards": 0,
  "unassigned_shards": 0,
  "delayed_unassigned_shards": 0,
  "number_of_pending_tasks": 0,
  "number_of_in_flight_fetch": 0,
  "task_max_waiting_in_queue_millis": 0,
  "active_shards_percent_as_number": 100.0
}
```

#### Cluster Statistics

```bash
curl -u admin:SecretPassword \
  -X GET "https://localhost:9200/_cluster/stats?pretty"

# Response
{
  "cluster_name": "wazuh-cluster",
  "nodes": {
    "count": {
      "total": 3,
      "data": 3,
      "cluster_manager": 1,
      "coordinating_only": 0
    },
    "os": {
      "available_processors": 12,
      "allocated_processors": 12,
      "mem": {
        "total_in_bytes": 25769803776
      }
    }
  },
  "indices": {
    "count": 5,
    "shards": {
      "total": 30,
      "primaries": 15
    },
    "docs": {
      "count": 2547123,
      "deleted": 142
    },
    "store": {
      "size_in_bytes": 15234567890
    }
  }
}
```

### Index Operations

#### List Indices

```bash
curl -u admin:SecretPassword \
  -X GET "https://localhost:9200/_cat/indices?v&s=index"

# Response
health status index                uuid                   pri rep docs.count docs.deleted store.size pri.store.size
green  open   wazuh-alerts-4.x-*  uP2tG3H1S_yzQNjTKzE_1w   5   1    1547832        0        8.1gb        4.2gb
green  open   wazuh-events-4.x-*  mK5sL8Y2T9uCFGhXvB_2w   5   1     999645        0        3.7gb        1.9gb
```

#### Create Index

```bash
curl -u admin:SecretPassword \
  -X PUT "https://localhost:9200/my-index" \
  -H 'Content-Type: application/json' \
  -d '{
    "settings": {
      "index": {
        "number_of_shards": 3,
        "number_of_replicas": 1
      }
    },
    "mappings": {
      "properties": {
        "timestamp": {
          "type": "date",
          "format": "strict_date_optional_time||epoch_millis"
        },
        "message": {
          "type": "text",
          "analyzer": "standard"
        }
      }
    }
  }'
```

### Search Operations

#### Basic Search

```bash
curl -u admin:SecretPassword \
  -X GET "https://localhost:9200/wazuh-alerts-*/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 10,
    "sort": [
      {
        "timestamp": {
          "order": "desc"
        }
      }
    ],
    "query": {
      "bool": {
        "must": [
          {
            "range": {
              "timestamp": {
                "gte": "now-1h"
              }
            }
          },
          {
            "term": {
              "rule.level": 10
            }
          }
        ]
      }
    }
  }'
```

#### Aggregation Search

```bash
curl -u admin:SecretPassword \
  -X GET "https://localhost:9200/wazuh-alerts-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 0,
    "aggs": {
      "alerts_by_level": {
        "terms": {
          "field": "rule.level",
          "size": 10
        }
      },
      "alerts_over_time": {
        "date_histogram": {
          "field": "timestamp",
          "interval": "1h"
        }
      }
    }
  }'

# Response
{
  "aggregations": {
    "alerts_by_level": {
      "buckets": [
        {
          "key": 5,
          "doc_count": 15423
        },
        {
          "key": 3,
          "doc_count": 8734
        }
      ]
    },
    "alerts_over_time": {
      "buckets": [
        {
          "key_as_string": "2024-01-01T12:00:00.000Z",
          "key": 1704110400000,
          "doc_count": 234
        }
      ]
    }
  }
}
```

## 🖥️ Dashboard API

### Base Information

```
Base URL: https://your-server.com:5601
API Version: 4.7.2
Authentication: Session-based
Content-Type: application/json
```

### Authentication

#### Login Session

```bash
# Get login page
curl -c cookies.txt https://localhost:5601/api/status

# Login with credentials
curl -b cookies.txt -c cookies.txt \
  -X POST https://localhost:5601/auth/login \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "admin",
    "password": "SecretPassword"
  }'
```

### Status & Health

#### API Status

```bash
curl -b cookies.txt \
  https://localhost:5601/api/status

# Response
{
  "name": "wazuh-dashboard",
  "version": {
    "number": "4.7.2",
    "build_hash": "abc123def456",
    "build_number": 47801,
    "build_snapshot": false
  },
  "status": {
    "overall": {
      "state": "green",
      "title": "Green",
      "nickname": "Looking good"
    },
    "statuses": [
      {
        "id": "opensearch",
        "state": "green",
        "message": "Ready"
      }
    ]
  }
}
```

### Saved Objects

#### Export Objects

```bash
curl -b cookies.txt \
  -X POST https://localhost:5601/api/saved_objects/_export \
  -H 'Content-Type: application/json' \
  -d '{
    "type": ["dashboard", "visualization", "search"],
    "includeReferencesDeep": true
  }' > exported_objects.ndjson
```

#### Import Objects

```bash
curl -b cookies.txt \
  -X POST https://localhost:5601/api/saved_objects/_import \
  -H 'osd-xsrf: true' \
  -F file=@exported_objects.ndjson
```

## 🏥 Custom Health API

### Health Check Endpoints

The project includes custom health check endpoints for monitoring:

#### Service Health

```bash
# Check overall system health
curl http://localhost:80/health

# Response
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00.000Z",
  "services": {
    "wazuh-manager": {
      "status": "healthy",
      "response_time": 45,
      "last_check": "2024-01-01T12:00:00.000Z"
    },
    "opensearch": {
      "status": "healthy", 
      "response_time": 23,
      "last_check": "2024-01-01T12:00:00.000Z"
    },
    "dashboard": {
      "status": "healthy",
      "response_time": 67,
      "last_check": "2024-01-01T12:00:00.000Z"
    }
  },
  "system": {
    "cpu_usage": "15%",
    "memory_usage": "45%",
    "disk_usage": "67%",
    "load_average": 0.85
  }
}
```

#### Individual Service Health

```bash
# Check specific service
curl http://localhost:80/health/manager
curl http://localhost:80/health/indexer
curl http://localhost:80/health/dashboard
```

## 📚 SDK & Client Libraries

### Python SDK

#### Installation

```bash
pip install wazuh-api-client
```

#### Basic Usage

```python
from wazuh_api_client import WazuhAPI

# Initialize client
client = WazuhAPI(
    host='localhost',
    port=55000,
    username='admin',
    password='SecretPassword',
    protocol='https',
    verify=False
)

# Authenticate
token = client.authenticate()

# Get agents
agents = client.agents.list(status='active')
print(f"Active agents: {len(agents['data']['affected_items'])}")

# Get alerts
alerts = client.alerts.list(
    rule_level='10-15',
    limit=50,
    sort='-timestamp'
)

# Add new agent
new_agent = client.agents.add(
    name='web-server-02',
    ip='10.0.1.101'
)
print(f"Agent added with ID: {new_agent['data']['id']}")
```

#### Advanced Usage

```python
import asyncio
from wazuh_api_client.async_client import AsyncWazuhAPI

async def monitor_alerts():
    """Monitor high-severity alerts"""
    client = AsyncWazuhAPI(
        host='localhost',
        port=55000,
        username='admin',
        password='SecretPassword'
    )
    
    await client.authenticate()
    
    while True:
        # Get critical alerts from last 5 minutes
        alerts = await client.alerts.list(
            rule_level='12-15',
            timestamp='now-5m',
            limit=100
        )
        
        for alert in alerts['data']['affected_items']:
            print(f"CRITICAL ALERT: {alert['rule']['description']}")
            print(f"Agent: {alert['agent']['name']}")
            print(f"Time: {alert['timestamp']}")
            print("-" * 50)
        
        # Wait 5 minutes before next check
        await asyncio.sleep(300)

# Run monitoring
asyncio.run(monitor_alerts())
```

### JavaScript/Node.js SDK

#### Installation

```bash
npm install wazuh-api-client
```

#### Basic Usage

```javascript
const WazuhAPI = require('wazuh-api-client');

// Initialize client
const client = new WazuhAPI({
  host: 'localhost',
  port: 55000,
  username: 'admin', 
  password: 'SecretPassword',
  protocol: 'https',
  rejectUnauthorized: false
});

// Authenticate and get agents
async function getActiveAgents() {
  try {
    await client.authenticate();
    
    const agents = await client.agents.list({
      status: 'active',
      limit: 100
    });
    
    console.log(`Found ${agents.data.affected_items.length} active agents`);
    return agents.data.affected_items;
    
  } catch (error) {
    console.error('Error fetching agents:', error.message);
  }
}

// Monitor alerts in real-time
async function monitorAlerts() {
  const alerts = await client.alerts.list({
    rule_level: '10-15',
    timestamp: 'now-1h',
    sort: '-timestamp'
  });
  
  alerts.data.affected_items.forEach(alert => {
    console.log(`Alert: ${alert.rule.description}`);
    console.log(`Agent: ${alert.agent.name}`);
    console.log(`Level: ${alert.rule.level}`);
  });
}

// Execute functions
getActiveAgents();
monitorAlerts();
```

### cURL Examples Collection

#### Authentication Examples

```bash
# File: examples/auth.sh

# Basic authentication
curl -u admin:SecretPassword https://localhost:55000/

# Get JWT token
TOKEN=$(curl -s -u admin:SecretPassword -X POST "https://localhost:55000/security/user/authenticate" | jq -r '.data.token')

# Use JWT token
curl -H "Authorization: Bearer $TOKEN" https://localhost:55000/agents
```

#### Agent Management Examples

```bash
# File: examples/agents.sh

# List all agents
curl -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/agents?pretty=true"

# Get specific agent
curl -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/agents/001?pretty=true"

# Add new agent
curl -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST https://localhost:55000/agents \
  -d '{
    "name": "test-server",
    "ip": "192.168.1.50"
  }'

# Delete agent
curl -H "Authorization: Bearer $TOKEN" \
  -X DELETE "https://localhost:55000/agents?agents_list=002&purge=true"
```

#### Alert Monitoring Examples

```bash
# File: examples/alerts.sh

# Get recent high-severity alerts
curl -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/alerts?rule.level=10-15&timestamp=now-1h&pretty=true"

# Get alerts for specific agent
curl -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/alerts?agent.id=001&limit=20&pretty=true"

# Get alert summary
curl -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/alerts/summary?rule.level=5-15&pretty=true"
```

## 🔧 Integration Examples

### Webhook Integration

#### Alert Forwarding

```python
# webhook_forwarder.py
import requests
import json
from wazuh_api_client import WazuhAPI

class AlertForwarder:
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url
        self.wazuh = WazuhAPI(
            host='localhost',
            port=55000,
            username='admin',
            password='SecretPassword'
        )
        self.wazuh.authenticate()
    
    def forward_alert(self, alert):
        """Forward alert to webhook endpoint"""
        payload = {
            'alert_id': alert['id'],
            'timestamp': alert['timestamp'],
            'rule_id': alert['rule']['id'],
            'rule_description': alert['rule']['description'],
            'rule_level': alert['rule']['level'],
            'agent_name': alert['agent']['name'],
            'agent_ip': alert['agent']['ip'],
            'full_log': alert['full_log']
        }
        
        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            print(f"Alert {alert['id']} forwarded successfully")
            
        except requests.RequestException as e:
            print(f"Failed to forward alert {alert['id']}: {e}")
    
    def monitor_and_forward(self):
        """Monitor for new high-severity alerts"""
        while True:
            alerts = self.wazuh.alerts.list(
                rule_level='10-15',
                timestamp='now-5m',
                limit=100
            )
            
            for alert in alerts['data']['affected_items']:
                self.forward_alert(alert)
            
            time.sleep(300)  # Check every 5 minutes

# Usage
forwarder = AlertForwarder('https://your-webhook.com/alerts')
forwarder.monitor_and_forward()
```

### Slack Integration

```python
# slack_integration.py
import json
import requests
from datetime import datetime

class SlackAlerter:
    def __init__(self, webhook_url, channel='#security-alerts'):
        self.webhook_url = webhook_url
        self.channel = channel
    
    def format_alert_message(self, alert):
        """Format alert for Slack"""
        level_emoji = {
            3: ':warning:',
            5: ':warning:',
            7: ':rotating_light:',
            10: ':rotating_light:',
            12: ':fire:',
            15: ':fire:'
        }
        
        emoji = level_emoji.get(alert['rule']['level'], ':information_source:')
        
        message = {
            'channel': self.channel,
            'username': 'Wazuh SOC',
            'icon_emoji': ':shield:',
            'attachments': [
                {
                    'color': 'danger' if alert['rule']['level'] >= 10 else 'warning',
                    'title': f"{emoji} Security Alert - Level {alert['rule']['level']}",
                    'fields': [
                        {
                            'title': 'Rule Description',
                            'value': alert['rule']['description'],
                            'short': False
                        },
                        {
                            'title': 'Agent',
                            'value': f"{alert['agent']['name']} ({alert['agent']['ip']})",
                            'short': True
                        },
                        {
                            'title': 'Time',
                            'value': alert['timestamp'],
                            'short': True
                        },
                        {
                            'title': 'Log Message',
                            'value': f"```{alert['full_log'][:500]}```",
                            'short': False
                        }
                    ],
                    'footer': f"Rule ID: {alert['rule']['id']}",
                    'ts': int(datetime.now().timestamp())
                }
            ]
        }
        return message
    
    def send_alert(self, alert):
        """Send alert to Slack"""
        message = self.format_alert_message(alert)
        
        try:
            response = requests.post(
                self.webhook_url,
                json=message,
                timeout=10
            )
            response.raise_for_status()
            
        except requests.RequestException as e:
            print(f"Failed to send Slack alert: {e}")

# Usage
slack = SlackAlerter('https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK')
# slack.send_alert(alert_data)
```

## 📈 Monitoring & Metrics

### Prometheus Integration

```python
# prometheus_exporter.py
from prometheus_client import start_http_server, Gauge, Counter
from wazuh_api_client import WazuhAPI
import time

# Define metrics
agents_total = Gauge('wazuh_agents_total', 'Total number of agents')
agents_active = Gauge('wazuh_agents_active', 'Number of active agents')
alerts_total = Counter('wazuh_alerts_total', 'Total alerts', ['level'])
manager_status = Gauge('wazuh_manager_status', 'Manager service status', ['service'])

class WazuhMetricsExporter:
    def __init__(self):
        self.wazuh = WazuhAPI(
            host='localhost',
            port=55000,
            username='admin',
            password='SecretPassword'
        )
        self.wazuh.authenticate()
    
    def collect_agent_metrics(self):
        """Collect agent metrics"""
        try:
            # Get all agents
            all_agents = self.wazuh.agents.list(limit=10000)
            agents_total.set(len(all_agents['data']['affected_items']))
            
            # Get active agents
            active_agents = self.wazuh.agents.list(status='active', limit=10000)
            agents_active.set(len(active_agents['data']['affected_items']))
            
        except Exception as e:
            print(f"Error collecting agent metrics: {e}")
    
    def collect_alert_metrics(self):
        """Collect alert metrics"""
        try:
            # Get alerts from last hour by level
            for level in [3, 5, 7, 10, 12, 15]:
                alerts = self.wazuh.alerts.list(
                    rule_level=str(level),
                    timestamp='now-1h',
                    limit=10000
                )
                
                alert_count = len(alerts['data']['affected_items'])
                alerts_total.labels(level=level).inc(alert_count)
                
        except Exception as e:
            print(f"Error collecting alert metrics: {e}")
    
    def collect_manager_metrics(self):
        """Collect manager service metrics"""
        try:
            status = self.wazuh.manager.get_status()
            services = status['data']['affected_items'][0]
            
            for service, state in services.items():
                manager_status.labels(service=service).set(
                    1 if state == 'running' else 0
                )
                
        except Exception as e:
            print(f"Error collecting manager metrics: {e}")
    
    def collect_metrics(self):
        """Collect all metrics"""
        while True:
            self.collect_agent_metrics()
            self.collect_alert_metrics()
            self.collect_manager_metrics()
            time.sleep(60)  # Collect every minute

# Start metrics server
if __name__ == '__main__':
    start_http_server(8000)
    print("Prometheus metrics server started on port 8000")
    
    exporter = WazuhMetricsExporter()
    exporter.collect_metrics()
```

## 📋 Error Handling & Rate Limiting

### Error Response Format

```json
{
  "data": {
    "affected_items": [],
    "total_affected_items": 0,
    "total_failed_items": 1,
    "failed_items": [
      {
        "error": {
          "code": 1701,
          "message": "Agent does not exist",
          "remediation": "Please, use `GET /agents` to find all available agents"
        },
        "id": ["999"]
      }
    ]
  }
}
```

### Common Error Codes

| Code | Description | HTTP Status |
|------|-------------|-------------|
| 1701 | Agent does not exist | 404 |
| 1707 | Agent key already exists | 409 |
| 6000 | Authorization error | 403 |
| 6001 | Authentication error | 401 |
| 1000 | Database error | 500 |
| 1001 | Invalid JSON syntax | 400 |

### Rate Limiting

The API implements rate limiting:

- **Default**: 300 requests per minute per IP
- **Authenticated users**: 1000 requests per minute
- **Headers**: `X-RateLimit-Remaining`, `X-RateLimit-Reset`

```python
# Handle rate limiting
import time
import requests

def api_request_with_retry(url, headers, max_retries=3):
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers)
            
            if response.status_code == 429:  # Rate limited
                retry_after = int(response.headers.get('Retry-After', 60))
                print(f"Rate limited. Retrying after {retry_after} seconds...")
                time.sleep(retry_after)
                continue
                
            response.raise_for_status()
            return response.json()
            
        except requests.RequestException as e:
            if attempt == max_retries - 1:
                raise e
            time.sleep(2 ** attempt)  # Exponential backoff
```

---

This API documentation provides comprehensive coverage of all available endpoints and integration patterns. For additional information, see:
- [Testing Documentation](testing.md)
- [Development Guide](development.md)
- [Deployment Guide](deployment.md)
