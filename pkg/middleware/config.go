package middleware

type ResourcePermission struct {
	Method    string   `json:"method"`
	Path      string   `json:"path"`
	Roles     []string `json:"roles"`
	Actions   []string `json:"actions"`
	ServiceID string   `json:"serviceId"`
}

type ServiceConfig struct {
	ServiceID    string               `json:"serviceId"`
	ClientID     string               `json:"clientId"`
	ClientSecret string               `json:"clientSecret"`
	KeycloakURL  string               `json:"keycloakUrl"`
	Realm        string               `json:"realm"`
	Resources    []ResourcePermission `json:"resources"`
	CacheEnabled bool                 `json:"cacheEnabled"`
	CacheURL     string               `json:"cacheUrl"`
}
