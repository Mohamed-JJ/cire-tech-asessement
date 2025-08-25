# Architecture Guide

This guide provides a comprehensive overview of the Wazuh Docker SOC platform architecture, including system design, component relationships, data flows, and technical implementation details.

## 🏗️ System Overview

The Wazuh SOC platform is built on a distributed, containerized architecture that provides enterprise-grade security monitoring capabilities. The system combines multiple specialized components to deliver comprehensive security information and event management (SIEM) functionality.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Wazuh SOC Platform                           │
├─────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐    │
│  │   Wazuh         │  │   OpenSearch    │  │   Wazuh         │    │
│  │   Dashboard     │◄─┤   Indexer       │◄─┤   Manager       │    │
│  │   (Frontend)    │  │   (Storage)     │  │   (Analysis)    │    │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘    │
│           │                     │                     │            │
├─────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐    │
│  │   Nginx         │  │   Certificate   │  │   Docker        │    │
│  │   (Proxy/LB)    │  │   Management    │  │   Runtime       │    │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘    │
├─────────────────────────────────────────────────────────────────────┤
│                        Infrastructure Layer                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐    │
│  │   Ansible       │  │   CI/CD         │  │   Monitoring    │    │
│  │   (Automation)  │  │   (GitHub)      │  │   (Health)      │    │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

### Core Components

| Component | Purpose | Technology | Ports |
|-----------|---------|------------|-------|
| **Wazuh Manager** | Security analysis engine | Wazuh 4.7.2 | 55000, 1514, 1515 |
| **OpenSearch Indexer** | Data storage and search | OpenSearch 2.10.0 | 9200, 9300 |
| **Wazuh Dashboard** | Web interface | OpenSearch Dashboards | 5601 |
| **Nginx** | Reverse proxy and load balancer | Nginx 1.20+ | 80, 443 |
| **Certificate Manager** | SSL/TLS certificate handling | Custom scripts | N/A |

## 🔍 Wazuh Components

### Wazuh Manager Architecture

The Wazuh Manager is the core security analysis engine that processes security events from various sources.

```
┌─────────────────────────────────────────────────────────────┐
│                    Wazuh Manager                            │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Analysis  │  │    Rules    │  │  Decoders   │        │
│  │   Engine    │◄─┤   Engine    │◄─┤   Parser    │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │  Alerting   │  │   Active    │  │  Reporting  │        │
│  │   System    │  │  Response   │  │   Engine    │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │    API      │  │   Cluster   │  │  Filebeat   │        │
│  │  Interface  │  │  Manager    │  │ Integration │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────┘
```

**Manager Components**:

1. **Analysis Engine** (`wazuh-analysisd`)
   - Event correlation and analysis
   - Rule matching and threat detection
   - Statistical analysis and anomaly detection

2. **Rules Engine**
   - Pre-built security rules (3000+)
   - Custom rule creation
   - Compliance frameworks (PCI DSS, GDPR, HIPAA)

3. **Decoders**
   - Log parsing and normalization
   - Field extraction and standardization
   - Multi-format log support

4. **API Interface**
   - RESTful API for management
   - Agent registration and control
   - Configuration management

5. **Active Response**
   - Automated threat response
   - Custom response scripts
   - Integration with external systems

### OpenSearch Indexer Architecture

The OpenSearch Indexer provides distributed storage and search capabilities for security data.

```
┌─────────────────────────────────────────────────────────────┐
│                 OpenSearch Indexer                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Search    │  │   Index     │  │   Query     │        │
│  │   Engine    │◄─┤  Manager    │◄─┤  Processor  │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Shard     │  │   Cluster   │  │  Security   │        │
│  │  Manager    │  │   State     │  │  Manager    │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │    REST     │  │ Performance │  │    Data     │        │
│  │     API     │  │   Monitor   │  │   Storage   │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────┘
```

**Indexer Components**:

1. **Search Engine**
   - Full-text search capabilities
   - Real-time data indexing
   - Aggregation and analytics

2. **Index Management**
   - Automatic index lifecycle management
   - Index templates and mappings
   - Data retention policies

3. **Cluster Management**
   - Multi-node clustering
   - Automatic failover
   - Load distribution

4. **Security Layer**
   - Authentication and authorization
   - Role-based access control
   - SSL/TLS encryption

## 📊 Data Flow Architecture

### Event Processing Pipeline

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Agents    │───►│   Manager   │───►│   Indexer   │───►│  Dashboard  │
│  (Sources)  │    │  (Process)  │    │   (Store)   │    │   (View)    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │
       │            ┌─────────────┐    ┌─────────────┐              │
       │            │   Rules     │    │   Index     │              │
       └────────────┤  Engine     │    │ Templates   │──────────────┘
                    └─────────────┘    └─────────────┘
```

**Data Flow Steps**:

1. **Data Collection**
   - Agents collect logs and events
   - Syslog integration
   - API integrations

2. **Data Processing**
   - Log parsing and normalization
   - Rule matching and correlation
   - Enrichment with threat intelligence

3. **Data Storage**
   - Indexing in OpenSearch
   - Retention policy application
   - Performance optimization

4. **Data Visualization**
   - Dashboard rendering
   - Real-time updates
   - Interactive analysis

## 🐳 Containerization Strategy

### Docker Architecture

The platform uses a multi-container architecture with Docker Compose orchestration.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Docker Environment                           │
├─────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐    │
│  │   wazuh-mgr     │  │  wazuh-indexer  │  │ wazuh-dashboard │    │
│  │   Container     │  │   Container     │  │   Container     │    │
│  │                 │  │                 │  │                 │    │
│  │ ┌─────────────┐ │  │ ┌─────────────┐ │  │ ┌─────────────┐ │    │
│  │ │   Wazuh     │ │  │ │ OpenSearch  │ │  │ │ OpenSearch  │ │    │
│  │ │   Manager   │ │  │ │   Indexer   │ │  │ │ Dashboards  │ │    │
│  │ │   + Filebeat│ │  │ │             │ │  │ │ + Wazuh App │ │    │
│  │ └─────────────┘ │  │ └─────────────┘ │  │ └─────────────┘ │    │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘    │
├─────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐    │
│  │     Volumes     │  │    Networks     │  │   Secrets       │    │
│  │   (Persistent)  │  │   (Internal)    │  │ (Certificates)  │    │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

### Volume Management

**Persistent Volumes**:

| Volume | Purpose | Size | Backup |
|--------|---------|------|--------|
| `wazuh_api_configuration` | Manager API config | 50MB | Yes |
| `wazuh_etc` | Manager configuration | 100MB | Yes |
| `wazuh_logs` | Manager logs | 10GB | Yes |
| `wazuh_queue` | Event processing queue | 5GB | Yes |
| `wazuh_var_multigroups` | Agent groups | 500MB | Yes |
| `wazuh-indexer-data` | Search index data | 100GB+ | Yes |
| `filebeat_etc` | Filebeat configuration | 50MB | Yes |
| `filebeat_var` | Filebeat data | 1GB | Optional |

### Network Architecture

**Network Topology**:
```
┌─────────────────────────────────────────────────────────────────────┐
│                          Network Layer                              │
├─────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                    External Network                             ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            ││
│  │  │   Internet  │  │    Users    │  │   Agents    │            ││
│  │  └─────────────┘  └─────────────┘  └─────────────┘            ││
│  └─────────────────────────────────────────────────────────────────┘│
│                                │                                    │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                    Host Network                                 ││
│  │         80:80   443:443   5601:5601   55000:55000              ││
│  └─────────────────────────────────────────────────────────────────┘│
│                                │                                    │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                  Internal Network (wazuh)                      ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            ││
│  │  │   Manager   │◄─┤   Indexer   │◄─┤  Dashboard  │            ││
│  │  │    :55000   │  │    :9200    │  │    :5601    │            ││
│  │  └─────────────┘  └─────────────┘  └─────────────┘            ││
│  └─────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────┘
```

## 🔐 Security Architecture

### Security Layers

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Security Architecture                         │
├─────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                    Application Security                         ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            ││
│  │  │    RBAC     │  │ Authentication│  │ Authorization│           ││
│  │  └─────────────┘  └─────────────┘  └─────────────┘            ││
│  └─────────────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                  Transport Security                             ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            ││
│  │  │  TLS 1.3    │  │   Mutual    │  │ Certificate │            ││
│  │  │ Encryption  │  │     TLS     │  │    Pinning  │            ││
│  │  └─────────────┘  └─────────────┘  └─────────────┘            ││
│  └─────────────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                   Network Security                              ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            ││
│  │  │  Firewall   │  │   Network   │  │    VPN      │            ││
│  │  │    Rules    │  │ Isolation   │  │   Support   │            ││
│  │  └─────────────┘  └─────────────┘  └─────────────┘            ││
│  └─────────────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                Container Security                               ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            ││
│  │  │  Non-root   │  │   Read-only │  │  Resource   │            ││
│  │  │    User     │  │  Filesystem │  │   Limits    │            ││
│  │  └─────────────┘  └─────────────┘  └─────────────┘            ││
│  └─────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────┘
```

---

**Next Steps**: See the [Deployment Guide](deployment.md) for implementation details, or the [Troubleshooting Guide](troubleshooting.md) for operational procedures.
