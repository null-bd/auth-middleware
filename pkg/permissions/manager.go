// pkg/permissions/manager.go
package permissions

import (
	"strings"

	"github.com/null-bd/auth-middleware/pkg/keycloak"
)

type RolePermissionCallback func(orgId string, branchId string, role string) []string

type Manager struct {
	pathCache      map[string]bool
	getPermissions RolePermissionCallback
}

func NewManager(callback RolePermissionCallback) *Manager {
	return &Manager{
		pathCache:      make(map[string]bool),
		getPermissions: callback,
	}
}

func (m *Manager) HasPermission(method, path string, claims *keycloak.TokenClaims) bool {
	key := method + ":" + path
	if cached, exists := m.pathCache[key]; exists {
		return cached
	}

	hasPermission := m.checkPermission(method, path, claims)
	m.pathCache[key] = hasPermission
	return hasPermission
}

func (m *Manager) checkPermission(method, reqPath string, claims *keycloak.TokenClaims) bool {
	for _, role := range claims.Roles {
		permissions := m.getPermissions(claims.OrgID, claims.BranchID, role)
		if len(permissions) == 0 {
			continue
		}

		if m.matchPath(reqPath, claims.Actions) &&
			m.matchMethod(method, claims.Actions) {
			return true
		}
	}
	return false
}

func (m *Manager) matchPath(reqPath string, allowedActions []string) bool {
	for _, action := range allowedActions {
		if strings.HasPrefix(reqPath, action) {
			return true
		}
	}
	return false
}

func (m *Manager) matchMethod(method string, allowedActions []string) bool {
	for _, action := range allowedActions {
		if strings.HasPrefix(action, method) {
			return true
		}
	}
	return false
}
