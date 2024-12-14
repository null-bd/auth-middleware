package authn

import (
	"github.com/null-bd/authn/pkg/auth"
	"github.com/null-bd/authn/pkg/keycloak"
	"github.com/null-bd/authn/pkg/permissions"
)

// From auth package
type (
	ConfigLoader    = auth.ConfigLoader
	ServiceConfig   = auth.ServiceConfig
	AuthMiddleware  = auth.AuthMiddleware
	ResourceMatcher = auth.ResourceMatcher
)

// From auth package
var (
	NewConfigLoader    = auth.NewConfigLoader
	NewAuthMiddleware  = auth.NewAuthMiddleware
	NewResourceMatcher = auth.NewResourceMatcher
)

// From keycloak package
type (
	TokenClaims = keycloak.TokenClaims
)

// From permissions package
type (
	RolePermissionCallback = permissions.RolePermissionCallback
)
