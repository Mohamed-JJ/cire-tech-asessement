#!/bin/bash

# Wazuh Docker Swarm Deployment Script
# Usage: ./deploy.sh [deploy|rollback|teardown|status|operations]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANSIBLE_DIR="$SCRIPT_DIR"
INVENTORY_FILE="$ANSIBLE_DIR/inventory/prod/host"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if ansible is installed
    if ! command -v ansible &> /dev/null; then
        error "Ansible is not installed. Please install Ansible 2.9+ and try again."
    fi
    
    # Check if inventory file exists
    if [[ ! -f "$INVENTORY_FILE" ]]; then
        error "Inventory file not found: $INVENTORY_FILE"
    fi
    
    # Check if vault file exists
    if [[ ! -f "$ANSIBLE_DIR/vault.yml" ]]; then
        error "Vault file not found: $ANSIBLE_DIR/vault.yml"
    fi
    
    # Check ansible version
    ANSIBLE_VERSION=$(ansible --version | head -n1 | cut -d' ' -f2)
    log "Ansible version: $ANSIBLE_VERSION"
    
    success "Prerequisites check completed"
}

# Test connectivity to hosts
test_connectivity() {
    log "Testing connectivity to hosts..."
    
    if ansible -i "$INVENTORY_FILE" ec2_instances -m ping --ask-vault-pass; then
        success "All hosts are reachable"
    else
        error "Some hosts are not reachable. Please check your inventory and SSH configuration."
    fi
}

# Deploy stack
deploy_stack() {
    log "Starting Wazuh Docker Swarm deployment..."
    
    if ansible-playbook -i "$INVENTORY_FILE" "$ANSIBLE_DIR/playbooks/deploy.yml" --ask-vault-pass; then
        success "Deployment completed successfully!"
        log "Access points:"
        log "  - Wazuh Dashboard: https://<manager-ip>:443"
        log "  - Wazuh API: https://<manager-ip>:55000"
        log "  - Indexer API: https://<manager-ip>:9200"
    else
        error "Deployment failed. Check the logs above for details."
    fi
}

# Rollback deployment
rollback_deployment() {
    log "Starting rollback process..."
    
    read -p "Are you sure you want to rollback the deployment? This will remove the stack. (y/N): " confirm
    if [[ $confirm =~ ^[Yy]$ ]]; then
        if ansible-playbook -i "$INVENTORY_FILE" "$ANSIBLE_DIR/playbooks/rollback.yml" --ask-vault-pass; then
            success "Rollback completed successfully!"
        else
            error "Rollback failed. Check the logs above for details."
        fi
    else
        log "Rollback cancelled."
    fi
}

# Teardown everything
teardown_deployment() {
    log "Starting complete teardown..."
    
    read -p "Are you sure you want to teardown everything? This will remove the swarm and all data. (y/N): " confirm
    if [[ $confirm =~ ^[Yy]$ ]]; then
        read -p "This action is irreversible. Type 'DELETE' to confirm: " final_confirm
        if [[ $final_confirm == "DELETE" ]]; then
            if ansible-playbook -i "$INVENTORY_FILE" "$ANSIBLE_DIR/playbooks/teardown.yml" --ask-vault-pass; then
                success "Teardown completed successfully!"
            else
                error "Teardown failed. Check the logs above for details."
            fi
        else
            log "Teardown cancelled."
        fi
    else
        log "Teardown cancelled."
    fi
}

# Check deployment status
check_status() {
    log "Checking deployment status..."
    
    ansible-playbook -i "$INVENTORY_FILE" "$ANSIBLE_DIR/playbooks/deploy.yml" --ask-vault-pass --tags=verify || true
}

# Run operations playbook
run_operations() {
    log "Starting operations menu..."
    
    ansible-playbook -i "$INVENTORY_FILE" "$ANSIBLE_DIR/playbooks/operations.yml" --ask-vault-pass
}

# Show usage
show_usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  deploy      Deploy Wazuh stack to Docker Swarm"
    echo "  rollback    Rollback the current deployment"
    echo "  teardown    Complete teardown (removes swarm)"
    echo "  status      Check deployment status"
    echo "  operations  Interactive operations menu"
    echo "  test        Test connectivity to hosts"
    echo ""
    echo "Options:"
    echo "  -h, --help  Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 deploy                 # Deploy the stack"
    echo "  $0 status                 # Check status"
    echo "  $0 operations             # Open operations menu"
    echo "  $0 rollback               # Rollback deployment"
}

# Main execution
main() {
    case "${1:-}" in
        "deploy")
            check_prerequisites
            deploy_stack
            ;;
        "rollback")
            check_prerequisites
            rollback_deployment
            ;;
        "teardown")
            check_prerequisites
            teardown_deployment
            ;;
        "status")
            check_prerequisites
            check_status
            ;;
        "operations")
            check_prerequisites
            run_operations
            ;;
        "test")
            check_prerequisites
            test_connectivity
            ;;
        "-h"|"--help"|"help")
            show_usage
            ;;
        "")
            log "No command specified."
            show_usage
            ;;
        *)
            error "Unknown command: $1"
            show_usage
            ;;
    esac
}

# Run main function
main "$@"
