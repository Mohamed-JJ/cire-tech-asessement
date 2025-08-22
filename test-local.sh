#!/bin/bash

# Local Docker Compose Test Script
set -e

echo "🚀 Starting Wazuh Docker Compose Test"
echo "====================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Generate self-signed certificate for testing
echo -e "${YELLOW}📋 Generating SSL certificate...${NC}"
mkdir -p config/nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout config/nginx/ssl/server.key \
  -out config/nginx/ssl/server.crt \
  -subj '/C=US/ST=Test/L=Test/O=Wazuh-Local/OU=Test/CN=localhost'

echo -e "${GREEN}✅ SSL certificate generated${NC}"

# Start Docker Compose
echo -e "${YELLOW}🐳 Starting Docker Compose services...${NC}"
docker-compose -f docker-compose.ci.yml --profile ci up -d

# Wait for services
echo -e "${YELLOW}⏳ Waiting for services to be ready...${NC}"
sleep 30

# Check service status
echo -e "${YELLOW}📊 Checking service status...${NC}"
docker-compose -f docker-compose.ci.yml ps

# Test endpoints
echo -e "${YELLOW}🔍 Testing endpoints...${NC}"

echo "1. Testing Nginx health check:"
curl -f http://localhost/health && echo -e "${GREEN}✅ Health check passed${NC}" || echo -e "${RED}❌ Health check failed${NC}"

echo "2. Testing HTTP to HTTPS redirect:"
curl -I http://localhost/ | head -1

echo "3. Testing HTTPS access:"
curl -I -k https://localhost/ | head -1 && echo -e "${GREEN}✅ HTTPS accessible${NC}" || echo -e "${RED}❌ HTTPS failed${NC}"

echo "4. Testing Wazuh API direct access:"
curl -f http://localhost:55000/ && echo -e "${GREEN}✅ API accessible${NC}" || echo -e "${RED}❌ API failed${NC}"

echo "5. Testing security headers:"
curl -I -k https://localhost/ | grep -E "(Strict-Transport-Security|X-Frame-Options|X-Content-Type-Options)" && echo -e "${GREEN}✅ Security headers present${NC}" || echo -e "${YELLOW}⚠️ Some security headers missing${NC}"

# Show logs if requested
if [[ "$1" == "--logs" ]]; then
    echo -e "${YELLOW}📋 Service Logs:${NC}"
    echo "--- Nginx ---"
    docker-compose -f docker-compose.ci.yml logs --tail 20 nginx
    echo "--- Wazuh Manager ---"
    docker-compose -f docker-compose.ci.yml logs --tail 20 wazuh-manager
fi

echo ""
echo -e "${GREEN}🎉 Test completed! Access Wazuh at: https://localhost${NC}"
echo -e "${YELLOW}💡 To clean up, run: docker-compose -f docker-compose.ci.yml down -v${NC}"
