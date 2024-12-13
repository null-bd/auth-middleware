package permissions

type Validator struct {
	rules map[string][]string
}

func NewValidator() *Validator {
	return &Validator{
		rules: make(map[string][]string),
	}
}

func (v *Validator) AddRule(role string, permissions []string) {
	v.rules[role] = permissions
}

func (v *Validator) Validate(roles []string, requiredPermissions []string) bool {
	for _, required := range requiredPermissions {
		if !v.hasPermission(roles, required) {
			return false
		}
	}
	return true
}

func (v *Validator) hasPermission(roles []string, requiredPermission string) bool {
	for _, role := range roles {
		permissions, exists := v.rules[role]
		if !exists {
			continue
		}
		for _, permission := range permissions {
			if permission == requiredPermission {
				return true
			}
		}
	}
	return false
}
