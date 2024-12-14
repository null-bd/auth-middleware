package authn

import (
	"github.com/null-bd/authn/pkg/auth"
	"github.com/null-bd/authn/pkg/keycloak"
	"github.com/null-bd/authn/pkg/permissions"
)

// Re-export types from auth package
type (
	ConfigLoader    = auth.ConfigLoader
	ServiceConfig   = auth.ServiceConfig
	AuthMiddleware  = auth.AuthMiddleware
	ResourceMatcher = auth.ResourceMatcher
)

// Re-export functions from auth package
var (
	NewConfigLoader    = auth.NewConfigLoader
	NewAuthMiddleware  = auth.NewAuthMiddleware
	NewResourceMatcher = auth.NewResourceMatcher
)

// Re-export types from keycloak package
type (
	TokenClaims = keycloak.TokenClaims
)

// Re-export types from permissions package
type (
	RolePermissionCallback = permissions.RolePermissionCallback
)
