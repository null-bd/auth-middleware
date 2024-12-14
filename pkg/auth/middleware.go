package auth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/null-bd/authn/pkg/keycloak"
	"github.com/null-bd/authn/pkg/permissions"

	"github.com/gin-gonic/gin"
)

type AuthMiddleware struct {
	config       ServiceConfig
	tokenManager *keycloak.TokenManager
	permManager  *permissions.Manager
	publicPaths  map[pathKey]bool
}

func NewAuthMiddleware(config ServiceConfig, permCallback permissions.RolePermissionCallback) (*AuthMiddleware, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	tm, err := keycloak.NewTokenManager(config.KeycloakURL, config.Realm, config.CacheEnabled, config.CacheURL)
	if err != nil {
		return nil, err
	}

	publicPaths := make(map[pathKey]bool)
	for _, pp := range config.PublicPaths {
		for _, method := range pp.Method {
			key := pathKey{
				path:   pp.Path,
				method: strings.ToUpper(method),
			}
			publicPaths[key] = true
		}
	}

	return &AuthMiddleware{
		config:       config,
		tokenManager: tm,
		permManager:  permissions.NewManager(permCallback),
		publicPaths:  publicPaths,
	}, nil
}

func (am *AuthMiddleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if the path is public
		if am.isPublicPath(c.Request.Method, c.Request.URL.Path) {
			c.Next()
			return
		}

		token := extractToken(c)
		if token == "" {
			handleError(c, ErrMissingToken)
			return
		}

		claims, err := am.tokenManager.ValidateToken(c.Request.Context(), token)
		if err != nil {
			handleError(c, err)
			return
		}

		if !am.permManager.HasPermission(c.Request.Method, c.Request.URL.Path, claims) {
			handleError(c, ErrInsufficientScope)
			return
		}

		c.Set("claims", claims)
		c.Next()
	}
}

func (am *AuthMiddleware) isPublicPath(method, path string) bool {
	key := pathKey{
		path:   path,
		method: strings.ToUpper(method),
	}

	// First try exact match
	if am.publicPaths[key] {
		return true
	}

	// Then try wildcard paths
	for configPath := range am.publicPaths {
		if configPath.method == key.method && isWildcardMatch(configPath.path, path) {
			return true
		}
	}

	return false
}

// isWildcardMatch checks if a path matches a pattern that might include wildcards
// Example: "/api/v1/*" matches "/api/v1/anything"
func isWildcardMatch(pattern, path string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == path
	}

	if strings.HasSuffix(pattern, "/*") {
		basePattern := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(path, basePattern)
	}

	return false
}

func validateConfig(config ServiceConfig) error {
	if config.ServiceID == "" {
		return fmt.Errorf("%w: missing ServiceID", ErrInvalidConfig)
	}
	if config.ClientID == "" {
		return fmt.Errorf("%w: missing ClientID", ErrInvalidConfig)
	}
	if config.KeycloakURL == "" {
		return fmt.Errorf("%w: missing KeycloakURL", ErrInvalidConfig)
	}
	return nil
}

func extractToken(c *gin.Context) string {
	bearerToken := c.GetHeader("Authorization")
	if len(strings.Split(bearerToken, " ")) == 2 {
		return strings.Split(bearerToken, " ")[1]
	}
	return ""
}

func handleError(c *gin.Context, err error) {
	switch err {
	case ErrMissingToken:
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
	case ErrInvalidToken:
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
	case ErrInsufficientScope:
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
	default:
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	}
}
