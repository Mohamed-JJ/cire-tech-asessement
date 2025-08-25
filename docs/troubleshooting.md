# Troubleshooting Guide

This comprehensive troubleshooting guide helps diagnose and resolve common issues with the Wazuh SOC deployment project.

## 🚨 Quick Diagnostics

### Health Check Script

Create a quick diagnostic script:

```bash
#!/bin/bash
# File: scripts/health_check.sh

echo "=== Wazuh SOC Health Check ==="
echo "Timestamp: $(date)"
echo

# Check Docker services
echo "1. Docker Services Status:"
docker-compose -f wazuh-docker/single-node/docker-compose.yml ps
echo

# Check port availability
echo "2. Port Status:"
netstat -tlnp | grep -E "(5601|55000|9200|80|443)"
echo

# Check service endpoints
echo "3. Service Health:"
curl -s -o /dev/null -w "%{http_code}" http://localhost:5601 && echo " - Dashboard: OK" || echo " - Dashboard: FAIL"
curl -s -o /dev/null -w "%{http_code}" http://localhost:55000 && echo " - Manager API: OK" || echo " - Manager API: FAIL"
curl -s -k -o /dev/null -w "%{http_code}" https://localhost:9200 && echo " - Indexer: OK" || echo " - Indexer: FAIL"
echo

# Check system resources
echo "4. System Resources:"
echo "Memory: $(free -h | grep Mem | awk '{print $3"/"$2}')"
echo "CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)% used"
echo "Disk: $(df -h / | tail -1 | awk '{print $5}') used"
echo

# Check logs for errors
echo "5. Recent Errors:"
docker-compose -f wazuh-docker/single-node/docker-compose.yml logs --tail 10 | grep -i error
echo
```

### Quick Commands

```bash
# Quick service status
docker-compose ps

# Quick log check
docker-compose logs --tail 20

# Quick resource check
docker stats --no-stream

# Quick connectivity check
curl -I http://localhost:5601
curl -I http://localhost:55000
curl -I -k https://localhost:9200
```

## 🐳 Docker & Container Issues

### Container Startup Problems

#### Issue: Container Fails to Start

**Symptoms**:
```
Error response from daemon: driver failed programming external connectivity
Container exits with code 125, 126, or 127
```

**Diagnosis**:
```bash
# Check container logs
docker-compose logs <service_name>

# Check container status
docker-compose ps

# Check system resources
df -h
free -h
```

**Solutions**:

1. **Port Conflicts**:
```bash
# Check port usage
sudo netstat -tlnp | grep <port_number>

# Kill process using port
sudo kill -9 <pid>

# Or modify docker-compose.yml ports
```

2. **Resource Limitations**:
```bash
# Increase memory limits in docker-compose.yml
services:
  wazuh.indexer:
    mem_limit: 2g
    
# Check Docker daemon limits
docker info | grep -i memory
```

3. **Permission Issues**:
```bash
# Fix ownership
sudo chown -R $USER:$USER ./config/

# Fix permissions
chmod -R 755 ./config/
```

#### Issue: Container Exits Immediately

**Symptoms**:
```
Container wazuh1.indexer exits with code 1
Container wazuh.dashboard exits with code 78
```

**Diagnosis**:
```bash
# Check detailed logs
docker-compose logs -f <service_name>

# Check container configuration
docker-compose config

# Inspect container
docker inspect <container_name>
```

**Solutions**:

1. **Configuration Issues**:
```bash
# Validate configuration files
cd wazuh-docker/single-node
docker-compose config --quiet || echo "Configuration error"

# Check file syntax
yamllint docker-compose.yml
```

2. **Environment Variables**:
```bash
# Check environment file
cat .env

# Verify required variables
grep -E "(PASSWORD|USER)" .env
```

3. **Volume Mount Issues**:
```bash
# Check volume permissions
ls -la config/

# Recreate volumes
docker-compose down -v
docker volume prune -f
```

### Network Connectivity Issues

#### Issue: Services Cannot Communicate

**Symptoms**:
```
Connection refused to wazuh1.indexer:9200
DNS resolution failed for service names
```

**Diagnosis**:
```bash
# Check network configuration
docker network ls
docker network inspect <network_name>

# Test connectivity between containers
docker exec <container1> ping <container2>
```

**Solutions**:

1. **Network Recreation**:
```bash
# Remove and recreate networks
docker-compose down
docker network prune -f
docker-compose up -d
```

2. **Service Name Resolution**:
```bash
# Check service names in docker-compose.yml
grep "container_name:" docker-compose.yml

# Ensure services are in same network
docker-compose config | grep networks -A 5
```

## 🔒 SSL/TLS Certificate Issues

### Certificate Generation Problems

#### Issue: Certificate Generation Fails

**Symptoms**:
```
Error: Cannot generate SSL certificates
Permission denied accessing certificate directory
```

**Diagnosis**:
```bash
# Check certificate generation logs
docker-compose -f generate-indexer-certs.yml logs generator

# Check certificate directory
ls -la config/wazuh_indexer_ssl_certs/
```

**Solutions**:

1. **Regenerate Certificates**:
```bash
# Clean existing certificates
rm -rf config/wazuh_indexer_ssl_certs/

# Regenerate certificates
cd wazuh-docker/single-node
docker-compose -f generate-indexer-certs.yml run --rm generator

# Fix permissions
chmod -R 644 config/wazuh_indexer_ssl_certs/
```

2. **Manual Certificate Creation**:
```bash
# Create self-signed certificates
mkdir -p config/nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout config/nginx/ssl/server.key \
  -out config/nginx/ssl/server.crt \
  -subj '/C=US/ST=Test/L=Test/O=Wazuh/OU=IT/CN=localhost'
```

#### Issue: SSL Handshake Failures

**Symptoms**:
```
SSL handshake failed
Certificate verification failed
SSL: WRONG_VERSION_NUMBER
```

**Diagnosis**:
```bash
# Test SSL connectivity
openssl s_client -connect localhost:9200 -servername localhost

# Check certificate validity
openssl x509 -in config/wazuh_indexer_ssl_certs/wazuh1.indexer.pem -text -noout
```

**Solutions**:

1. **Certificate Validation**:
```bash
# Verify certificate chain
openssl verify -CAfile config/wazuh_indexer_ssl_certs/root-ca.pem \
  config/wazuh_indexer_ssl_certs/wazuh1.indexer.pem
```

2. **Disable SSL for Testing**:
```bash
# Temporarily disable SSL in opensearch.yml
plugins.security.ssl.http.enabled: false
plugins.security.ssl.transport.enforce_hostname_verification: false
```

## 🔐 Authentication & Authorization Issues

### Login Problems

#### Issue: Cannot Login to Dashboard

**Symptoms**:
```
Authentication failed
Invalid username or password
401 Unauthorized
```

**Diagnosis**:
```bash
# Check user configuration
docker exec wazuh.dashboard cat /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml

# Check API connectivity
curl -u admin:SecretPassword http://localhost:55000/security/user
```

**Solutions**:

1. **Reset Default Passwords**:
```bash
# Check default credentials in docker-compose.yml
grep -E "(INDEXER_USERNAME|INDEXER_PASSWORD)" docker-compose.yml

# Reset using internal users
docker exec wazuh1.indexer bash -c "
  /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/ \
  -icl -nhnv \
  -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
  -cert /usr/share/wazuh-indexer/certs/admin.pem \
  -key /usr/share/wazuh-indexer/certs/admin-key.pem"
```

2. **Manual Password Reset**:
```bash
# Access indexer container
docker exec -it wazuh1.indexer bash

# Hash new password
echo 'newpassword' | /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh

# Update internal users
vim /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/internal_users.yml
```

### API Authentication Issues

#### Issue: API Returns 401 Unauthorized

**Symptoms**:
```
curl: (22) The requested URL returned error: 401 Unauthorized
API key authentication failed
```

**Diagnosis**:
```bash
# Test API with basic auth
curl -u admin:SecretPassword http://localhost:55000/

# Check API user configuration
docker exec wazuh.manager cat /var/ossec/api/configuration/api.yaml
```

**Solutions**:

1. **Verify API Configuration**:
```bash
# Check API users
docker exec wazuh.manager /var/ossec/bin/wazuh-apid -l

# Reset API user password
docker exec wazuh.manager /var/ossec/bin/wazuh-apid -P admin
```

2. **API Key Authentication**:
```bash
# Generate new API token
curl -u admin:SecretPassword -k -X POST "http://localhost:55000/security/user/authenticate"

# Use token for subsequent requests
curl -H "Authorization: Bearer <token>" http://localhost:55000/agents
```

## 📊 Performance Issues

### High Resource Usage

#### Issue: High Memory Consumption

**Symptoms**:
```
Out of memory errors
Container killed by OOM killer
System becomes unresponsive
```

**Diagnosis**:
```bash
# Check memory usage
free -h
docker stats --no-stream

# Check container memory limits
docker inspect <container> | grep -i memory

# Check system logs for OOM kills
dmesg | grep -i "killed process"
```

**Solutions**:

1. **Optimize Memory Settings**:
```bash
# Adjust OpenSearch heap size in docker-compose.yml
environment:
  - "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"  # Reduce from default 2g

# Set container memory limits
services:
  wazuh1.indexer:
    mem_limit: 2g
    mem_reservation: 1g
```

2. **System Configuration**:
```bash
# Increase swap space
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

#### Issue: High CPU Usage

**Symptoms**:
```
CPU usage consistently above 80%
System lag and slow response
Thermal throttling
```

**Diagnosis**:
```bash
# Monitor CPU usage
top -p $(docker inspect --format '{{.State.Pid}}' <container>)
htop

# Check container CPU limits
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"
```

**Solutions**:

1. **CPU Limiting**:
```bash
# Set CPU limits in docker-compose.yml
services:
  wazuh1.indexer:
    cpus: '2.0'
    cpu_percent: 50
```

2. **Process Optimization**:
```bash
# Reduce indexer refresh interval
curl -X PUT "localhost:9200/_all/_settings" -H 'Content-Type: application/json' -d'
{
  "refresh_interval": "30s"
}'
```

### Slow Response Times

#### Issue: Dashboard Loads Slowly

**Symptoms**:
```
Dashboard takes >30 seconds to load
Timeout errors in browser
Slow API responses
```

**Diagnosis**:
```bash
# Test response times
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:5601

# Check service logs for performance issues
docker-compose logs wazuh.dashboard | grep -i slow
```

**Solutions**:

1. **Performance Tuning**:
```bash
# Increase dashboard server timeout
echo 'server.socketTimeout: 120000' >> config/wazuh_dashboard/opensearch_dashboards.yml

# Optimize indexer performance
echo 'indices.query.bool.max_clause_count: 10000' >> config/wazuh_indexer/opensearch.yml
```

2. **Caching Configuration**:
```bash
# Enable query caching
curl -X PUT "localhost:9200/_cluster/settings" -H 'Content-Type: application/json' -d'
{
  "persistent": {
    "indices.queries.cache.size": "20%"
  }
}'
```

## 🌐 Network & Connectivity Issues

### Port Access Problems

#### Issue: Cannot Access Services Externally

**Symptoms**:
```
Connection refused from external clients
Services accessible only from localhost
Firewall blocking connections
```

**Diagnosis**:
```bash
# Check listening ports
netstat -tlnp | grep -E "(5601|55000|9200)"

# Test connectivity
telnet <server_ip> 5601

# Check firewall rules
sudo ufw status
sudo iptables -L
```

**Solutions**:

1. **Firewall Configuration**:
```bash
# Allow ports through firewall
sudo ufw allow 80
sudo ufw allow 443
sudo ufw allow 5601
sudo ufw allow 55000

# For iptables
sudo iptables -A INPUT -p tcp --dport 5601 -j ACCEPT
```

2. **Docker Network Configuration**:
```bash
# Ensure services bind to all interfaces
services:
  wazuh.dashboard:
    ports:
      - "0.0.0.0:5601:5601"  # Bind to all interfaces
```

### DNS Resolution Issues

#### Issue: Service Discovery Failures

**Symptoms**:
```
getaddrinfo: Name or service not known
DNS resolution timeout
Services cannot find each other
```

**Diagnosis**:
```bash
# Test DNS resolution
nslookup wazuh1.indexer
dig wazuh1.indexer

# Check Docker DNS
docker exec <container> nslookup wazuh1.indexer
```

**Solutions**:

1. **DNS Configuration**:
```bash
# Add DNS servers to containers
services:
  wazuh.dashboard:
    dns:
      - 8.8.8.8
      - 8.8.4.4
```

2. **Host File Updates**:
```bash
# Add entries to /etc/hosts
echo "127.0.0.1 wazuh1.indexer" | sudo tee -a /etc/hosts
echo "127.0.0.1 wazuh.manager" | sudo tee -a /etc/hosts
```

## 🧪 Testing & Development Issues

### Test Failures

#### Issue: Selenium Tests Fail

**Symptoms**:
```
WebDriverException: Chrome binary not found
TimeoutException: Element not found
Session not created: Chrome version mismatch
```

**Diagnosis**:
```bash
# Check browser installation
which chromium-browser
chromium-browser --version

# Check WebDriver
python -c "from selenium import webdriver; print(webdriver.Chrome())"
```

**Solutions**:

1. **Browser Installation**:
```bash
# Install Chrome/Chromium
sudo apt-get update
sudo apt-get install -y chromium-browser

# Install WebDriver
pip install webdriver-manager
```

2. **Headless Configuration**:
```bash
# Configure headless mode in tests
export HEADLESS=true
export CI=true

# Test specific configuration
pytest tests/ --headless --verbose
```

#### Issue: API Tests Timeout

**Symptoms**:
```
requests.exceptions.ConnectTimeout
Connection timeout after 30 seconds
API endpoint not responding
```

**Diagnosis**:
```bash
# Test API directly
curl -v http://localhost:55000/

# Check service status
docker-compose ps | grep wazuh.manager
```

**Solutions**:

1. **Increase Timeouts**:
```bash
# Modify test configuration
echo "TEST_TIMEOUT=60" >> tests/.env

# Wait for services
sleep 120
./tests/run_tests.sh api
```

2. **Service Dependencies**:
```bash
# Ensure proper startup order
services:
  wazuh.manager:
    depends_on:
      - wazuh1.indexer
```

## 🔧 Data & Storage Issues

### Volume Mount Problems

#### Issue: Data Not Persisting

**Symptoms**:
```
Data lost after container restart
Volume mount failed
Permission denied on mounted volumes
```

**Diagnosis**:
```bash
# Check volume mounts
docker inspect <container> | grep Mounts -A 10

# Check volume permissions
ls -la /var/lib/docker/volumes/

# Verify mount points
docker exec <container> df -h
```

**Solutions**:

1. **Fix Volume Permissions**:
```bash
# Create volumes with correct ownership
docker-compose down
docker volume rm $(docker volume ls -q)

# Set proper permissions
sudo chown -R 1000:1000 ./config/
```

2. **Volume Configuration**:
```yaml
# Ensure proper volume configuration
volumes:
  wazuh_api_configuration:
    driver: local
    driver_opts:
      type: none
      device: ./config/wazuh_cluster/wazuh_manager.conf
      o: bind
```

### Index/Data Corruption

#### Issue: OpenSearch Index Corruption

**Symptoms**:
```
Cluster health RED
Index corruption detected
Failed to recover index
```

**Diagnosis**:
```bash
# Check cluster health
curl -X GET "localhost:9200/_cluster/health?pretty"

# Check index status
curl -X GET "localhost:9200/_cat/indices?v"

# Check shard allocation
curl -X GET "localhost:9200/_cat/shards?v"
```

**Solutions**:

1. **Index Recovery**:
```bash
# Recover corrupted indices
curl -X POST "localhost:9200/_cluster/reroute?retry_failed=true"

# Force allocation of unassigned shards
curl -X POST "localhost:9200/_cluster/reroute" -H 'Content-Type: application/json' -d'
{
  "commands": [
    {
      "allocate_empty_primary": {
        "index": "<index_name>",
        "shard": 0,
        "node": "<node_name>",
        "accept_data_loss": true
      }
    }
  ]
}'
```

2. **Data Backup and Restore**:
```bash
# Create snapshot repository
curl -X PUT "localhost:9200/_snapshot/backup" -H 'Content-Type: application/json' -d'
{
  "type": "fs",
  "settings": {
    "location": "/usr/share/wazuh-indexer/backups"
  }
}'

# Restore from snapshot
curl -X POST "localhost:9200/_snapshot/backup/<snapshot_name>/_restore"
```

## 📋 Deployment Issues

### Ansible Deployment Problems

#### Issue: Ansible Playbook Fails

**Symptoms**:
```
TASK [role_name : task_name] failed
SSH connection timeout
Permission denied (publickey)
```

**Diagnosis**:
```bash
# Test SSH connectivity
ssh -i ~/.ssh/key.pem ubuntu@<server_ip>

# Check inventory configuration
ansible-inventory -i inventory/prod/host --list

# Validate playbook syntax
ansible-playbook --syntax-check playbooks/deploy.yml
```

**Solutions**:

1. **SSH Configuration**:
```bash
# Fix SSH key permissions
chmod 600 ~/.ssh/key.pem

# Add to SSH agent
ssh-add ~/.ssh/key.pem

# Test connection
ansible all -i inventory/prod/host -m ping
```

2. **Playbook Debug**:
```bash
# Run with verbose output
ansible-playbook -i inventory/prod/host playbooks/deploy.yml -vvv

# Check specific tasks
ansible-playbook -i inventory/prod/host playbooks/deploy.yml --start-at-task="task_name"
```

## 🆘 Emergency Procedures

### Complete System Reset

```bash
#!/bin/bash
# Emergency reset script

echo "=== EMERGENCY SYSTEM RESET ==="
echo "This will destroy all data. Are you sure? (yes/no)"
read confirmation

if [ "$confirmation" = "yes" ]; then
    # Stop all services
    docker-compose -f wazuh-docker/single-node/docker-compose.yml down -v
    
    # Remove all containers
    docker system prune -af
    
    # Remove all volumes
    docker volume prune -f
    
    # Clean configuration
    rm -rf config/wazuh_indexer_ssl_certs/
    rm -rf config/nginx/ssl/
    
    # Regenerate certificates
    cd wazuh-docker/single-node
    docker-compose -f generate-indexer-certs.yml run --rm generator
    
    # Start services
    docker-compose up -d
    
    echo "System reset complete. Wait 5 minutes for services to start."
fi
```

### Service Recovery

```bash
#!/bin/bash
# Service recovery script

SERVICE=$1
if [ -z "$SERVICE" ]; then
    echo "Usage: $0 <service_name>"
    exit 1
fi

echo "=== Recovering Service: $SERVICE ==="

# Stop service
docker-compose stop $SERVICE

# Remove container
docker-compose rm -f $SERVICE

# Recreate and start
docker-compose up -d $SERVICE

# Monitor logs
echo "Monitoring logs for $SERVICE..."
docker-compose logs -f $SERVICE
```

## 📞 Getting Help

### Log Collection

```bash
#!/bin/bash
# Collect diagnostic information

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="logs_$TIMESTAMP"
mkdir -p $LOG_DIR

# System information
uname -a > $LOG_DIR/system_info.txt
free -h > $LOG_DIR/memory_info.txt
df -h > $LOG_DIR/disk_info.txt

# Docker information
docker version > $LOG_DIR/docker_version.txt
docker-compose version > $LOG_DIR/docker_compose_version.txt
docker system df > $LOG_DIR/docker_disk_usage.txt

# Service logs
docker-compose logs > $LOG_DIR/all_services.log
docker-compose ps > $LOG_DIR/service_status.txt

# Configuration files
cp -r config/ $LOG_DIR/
cp docker-compose.yml $LOG_DIR/

# Create archive
tar -czf logs_$TIMESTAMP.tar.gz $LOG_DIR/
echo "Diagnostic logs collected in: logs_$TIMESTAMP.tar.gz"
```

### Support Checklist

Before seeking help, gather this information:

- [ ] System specifications (OS, RAM, CPU)
- [ ] Docker and Docker Compose versions
- [ ] Complete error messages and stack traces
- [ ] Service logs (docker-compose logs)
- [ ] Configuration files
- [ ] Steps to reproduce the issue
- [ ] What was working before the issue occurred

### Resources

- **Documentation**: [Wazuh Official Docs](https://documentation.wazuh.com/)
- **Community**: [Wazuh Community Forums](https://wazuh.com/community/)
- **Issues**: GitHub Issues in this repository
- **Security**: Report security issues privately

---

This troubleshooting guide covers the most common issues. For additional help, see:
- [Testing Documentation](testing.md)
- [CI/CD Documentation](cicd.md)
- [Architecture Guide](architecture.md)
