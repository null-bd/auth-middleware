package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/null-bd/auth-middleware/pkg/keycloak"
	"github.com/null-bd/auth-middleware/pkg/permissions"

	"github.com/gin-gonic/gin"
)

type AuthMiddleware struct {
	config       ServiceConfig
	tokenManager *keycloak.TokenManager
	permManager  *permissions.Manager
}

func NewAuthMiddleware(config ServiceConfig, permCallback permissions.RolePermissionCallback) (*AuthMiddleware, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	tm, err := keycloak.NewTokenManager(config.KeycloakURL, config.Realm, config.CacheEnabled, config.CacheURL)
	if err != nil {
		return nil, err
	}

	return &AuthMiddleware{
		config:       config,
		tokenManager: tm,
		permManager:  permissions.NewManager(permCallback),
	}, nil
}

func (am *AuthMiddleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
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
