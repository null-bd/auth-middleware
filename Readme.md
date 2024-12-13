# Authentication Middleware for Go Microservices

A flexible, Keycloak-based authentication middleware for Go microservices using the Gin web framework. This middleware provides role-based access control (RBAC) and action-based permissions with configuration through YAML files.

## Features

- 🔐 Keycloak integration for token validation
- 📝 YAML-based configuration
- 🚦 Role-based access control (RBAC)
- 🎯 Action-based permissions
- 🔄 Redis caching support for token validation
- 🛣️ Path-based permission matching with parameter support
- 🔧 Environment variable resolution in configuration
- 🎨 Flexible permission callback system

## Installation

```bash
go get github.com/null-bd/auth-middleware
```

## Quick Start

1. Create a `config.yaml` file in your service's root directory:

```yaml
auth:
  serviceId: "my-service"
  clientId: "my-client"
  clientSecret: "${CLIENT_SECRET}"
  keycloakUrl: "http://keycloak:8080"
  realm: "my-realm"
  cacheEnabled: true
  cacheUrl: "redis:6379"
  resources:
    - path: "/api/v1/users"
      method: "GET"
      roles: ["admin", "user"]
      actions: ["read:users"]
```

2. Initialize the middleware in your service:

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/null-bd/auth-middleware/pkg/authmiddleware"
)

func main() {
    // Load configuration
    configLoader := authmiddleware.NewConfigLoader("config.yaml")
    config, err := configLoader.Load()
    if err != nil {
        log.Fatal(err)
    }

    // Initialize middleware
    authMiddleware, err := authmiddleware.NewAuthMiddleware(*config, nil)
    if err != nil {
        log.Fatal(err)
    }

    // Setup Gin router
    r := gin.Default()
    r.Use(authMiddleware.Authenticate())

    // Define routes
    r.Run(":8080")
}
```

## Configuration

### Structure

The configuration file (`config.yaml`) supports the following options:

```yaml
auth:
  serviceId: string      # Unique identifier for the service
  clientId: string      # Keycloak client ID
  clientSecret: string  # Keycloak client secret (supports env vars)
  keycloakUrl: string  # Keycloak server URL
  realm: string        # Keycloak realm name
  cacheEnabled: bool   # Enable Redis caching
  cacheUrl: string     # Redis server URL
  resources:           # Array of resource permissions
    - path: string     # API endpoint path
      method: string   # HTTP method
      roles: string[]  # Required roles
      actions: string[] # Required actions
      serviceId: string # (Optional) Override service ID
```

### Environment Variables

You can use environment variables in the configuration file using the `${VAR_NAME}` syntax:

```yaml
auth:
  clientSecret: "${KEYCLOAK_CLIENT_SECRET}"
  keycloakUrl: "${KEYCLOAK_URL}"
```

## Permission Configuration

### Path Matching

The middleware supports path parameters in resource definitions:

```yaml
resources:
  - path: "/api/v1/organizations/{orgId}/users"
    method: "GET"
    roles: ["admin"]
    actions: ["read:users"]
```

### Role-Based Access

Define required roles for each endpoint:

```yaml
resources:
  - path: "/api/v1/users"
    method: "POST"
    roles: ["admin", "user-manager"]
    actions: ["create:users"]
```

### Action-Based Permissions

Define required actions for fine-grained control:

```yaml
resources:
  - path: "/api/v1/reports"
    method: "GET"
    roles: ["analyst"]
    actions: ["read:reports", "export:data"]
```

## Custom Permission Callback

You can implement custom permission logic using a callback:

```go
permCallback := func(orgId, branchId, role string) []string {
    // Your custom permission logic here
    return []string{"read:users", "write:users"}
}

authMiddleware, err := authmiddleware.NewAuthMiddleware(config, permCallback)
```

## Token Claims

The middleware adds the following claims to the Gin context:

```go
type TokenClaims struct {
    OrgID    string   `json:"org_id"`
    BranchID string   `json:"branch_id"`
    Roles    []string `json:"roles"`
    Actions  []string `json:"actions"`
}
```

Access claims in your handlers:

```go
func handler(c *gin.Context) {
    claims, exists := c.Get("claims")
    if !exists {
        c.JSON(401, gin.H{"error": "no claims found"})
        return
    }
    
    tokenClaims := claims.(*TokenClaims)
    // Use the claims...
}
```

## Error Handling

The middleware provides the following error types:

```go
var (
    ErrInvalidToken       = errors.New("invalid token")
    ErrExpiredToken       = errors.New("token has expired")
    ErrInsufficientScope  = errors.New("insufficient scope")
    ErrMissingToken       = errors.New("missing token")
    ErrInvalidConfig      = errors.New("invalid configuration")
    ErrServiceUnavailable = errors.New("auth service unavailable")
)
```

## Cache Configuration

When caching is enabled, token validation results are cached in Redis:

```yaml
auth:
  cacheEnabled: true
  cacheUrl: "redis:6379"
```
