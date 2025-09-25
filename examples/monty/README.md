# Monty - Kubernetes Utility with Active Directory Integration

Monty is a comprehensive Kubernetes management utility designed for financial institutions, providing secure access to Kubernetes resources through Active Directory authentication and role-based access control.

## Features

- **Active Directory Integration**: Seamless authentication using existing AD infrastructure
- **Role-Based Access Control**: Fine-grained permissions based on AD group membership
- **Multi-Cluster Support**: Manage multiple Mirantis Kubernetes Engine clusters
- **Audit Logging**: Complete audit trail for all operations
- **Multiple Output Formats**: JSON, YAML, and table formats
- **CLI and REST API**: Both command-line and programmatic access

## Quick Start

### Installation

```bash
pip install monty
```

### Configuration

1. Set up your configuration file:

```yaml
# ~/.monty/config.yaml
active_directory:
  server: "ldap://your-ad-server.company.com"
  domain: "COMPANY"
  base_dn: "DC=company,DC=com"
  
clusters:
  - name: "prod-cluster"
    endpoint: "https://prod-k8s.company.com"
    ca_cert_path: "/path/to/ca.crt"
  - name: "dev-cluster"
    endpoint: "https://dev-k8s.company.com"
    ca_cert_path: "/path/to/dev-ca.crt"

audit:
  enabled: true
  log_file: "/var/log/monty/audit.log"
  syslog_server: "syslog.company.com:514"
```

2. Authenticate with Active Directory:

```bash
monty auth login --username your.username
```

### Usage Examples

#### CLI Usage

```bash
# List namespaces in production cluster
monty namespace list --cluster prod-cluster --output table

# Create a new namespace
monty namespace create my-app --cluster dev-cluster --labels environment=dev,team=backend

# Get namespace details in YAML format
monty namespace get my-app --cluster dev-cluster --output yaml

# Update namespace resource quotas
monty namespace update my-app --cluster prod-cluster --cpu-limit 4000m --memory-limit 8Gi

# Delete a namespace (requires elevated permissions)
monty namespace delete my-app --cluster dev-cluster
```

#### REST API Usage

```bash
# Get JWT token
curl -X POST http://localhost:5000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "your.username", "password": "your.password"}'

# List namespaces
curl -X GET "http://localhost:5000/api/v1/namespaces?cluster=prod-cluster" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Create namespace
curl -X POST http://localhost:5000/api/v1/namespaces \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "namespace_name": "my-app",
    "cluster_name": "dev-cluster",
    "labels": {"environment": "dev", "team": "backend"},
    "resource_quota": {
      "cpu_limit": "2000m",
      "memory_limit": "4Gi",
      "pod_limit": 50
    }
  }'
```

## Architecture

### Components

1. **CLI Module** (`monty.cli`): Click-based command-line interface
2. **API Module** (`monty.api`): Flask-based REST API server
3. **Authentication Module** (`monty.auth`): Active Directory integration
4. **Kubernetes Module** (`monty.kubernetes`): Kubernetes API wrapper
5. **Audit Module** (`monty.audit`): Comprehensive audit logging
6. **RBAC Module** (`monty.rbac`): Role-based access control

### Security Model

- **Authentication**: Active Directory LDAP authentication
- **Authorization**: Role-based access control using AD groups
- **Token Management**: JWT tokens with configurable expiration
- **Audit Trail**: All operations logged with user context
- **Network Security**: TLS encryption for all communications

### Supported AD Group Mappings

| AD Group | Permissions | Description |
|----------|-------------|-------------|
| `K8S-Admins` | Full access | Complete cluster administration |
| `K8S-Developers` | Namespace CRUD | Create/manage development namespaces |
| `K8S-Operators` | Read/Update | View and update existing namespaces |
| `K8S-Viewers` | Read-only | View namespace information only |

## Development

### Setup Development Environment

```bash
git clone https://github.com/RBC-Workshop/monty.git
cd monty
poetry install
poetry shell
```

### Generate API Components

The project uses Firestone to generate API specifications and client code:

```bash
# Generate OpenAPI specification
firestone generate \
    --title 'Monty Kubernetes API' \
    --description 'Kubernetes namespace management with AD authentication' \
    --resources resources/kubernetes-namespace.yaml \
    --version 1.0 \
    openapi \
    --security '{"name": "ad_bearer_auth", "scheme": "bearer", "type": "http", "bearerFormat": "JWT"}' \
    -O api/openapi.yaml

# Generate CLI components
firestone generate \
    --title 'Monty CLI' \
    --description 'Kubernetes namespace management CLI' \
    --resources resources/kubernetes-namespace.yaml \
    --version 1.0 \
    cli \
    --pkg monty \
    --client-pkg monty.client > monty/cli/generated.py
```

### Running Tests

```bash
poetry run pytest
poetry run pytest --cov=monty
```

### Code Quality

```bash
poetry run black monty/
poetry run flake8 monty/
poetry run mypy monty/
```

## Configuration Reference

### Active Directory Configuration

```yaml
active_directory:
  server: "ldap://ad-server.company.com"  # AD server URL
  port: 389                               # LDAP port (389 for LDAP, 636 for LDAPS)
  domain: "COMPANY"                       # AD domain
  base_dn: "DC=company,DC=com"           # Base distinguished name
  user_search_base: "OU=Users,DC=company,DC=com"
  group_search_base: "OU=Groups,DC=company,DC=com"
  use_ssl: false                          # Use LDAPS
  ca_cert_path: "/path/to/ca.crt"        # CA certificate for SSL
  timeout: 30                             # Connection timeout
```

### Cluster Configuration

```yaml
clusters:
  - name: "production"
    endpoint: "https://prod-k8s.company.com:6443"
    ca_cert_path: "/etc/monty/certs/prod-ca.crt"
    service_account_token_path: "/etc/monty/tokens/prod-token"
    default_namespace: "default"
    
  - name: "development"
    endpoint: "https://dev-k8s.company.com:6443"
    ca_cert_path: "/etc/monty/certs/dev-ca.crt"
    service_account_token_path: "/etc/monty/tokens/dev-token"
    default_namespace: "default"
```

### RBAC Configuration

```yaml
rbac:
  group_mappings:
    "K8S-Admins":
      - "cluster-admin"
    "K8S-Developers":
      - "namespace-admin"
      - "namespace-create"
    "K8S-Operators":
      - "namespace-edit"
    "K8S-Viewers":
      - "namespace-view"
      
  permissions:
    "cluster-admin":
      - "namespaces:*"
    "namespace-admin":
      - "namespaces:create"
      - "namespaces:read"
      - "namespaces:update"
      - "namespaces:delete"
    "namespace-edit":
      - "namespaces:read"
      - "namespaces:update"
    "namespace-view":
      - "namespaces:read"
```

## License

MIT License - see LICENSE file for details.
