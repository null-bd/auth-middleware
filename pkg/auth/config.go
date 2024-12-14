package auth

type ServiceConfig struct {
	ServiceID    string               `json:"serviceId"`
	ClientID     string               `json:"clientId"`
	ClientSecret string               `json:"clientSecret"`
	KeycloakURL  string               `json:"keycloakUrl"`
	Realm        string               `json:"realm"`
	Resources    []ResourcePermission `json:"resources"`
	CacheEnabled bool                 `json:"cacheEnabled"`
	CacheURL     string               `json:"cacheUrl"`
	PublicPaths  []PublicPath         `json:"publicPaths"`
}

type ResourcePermission struct {
	Path      string   `json:"path"`
	Method    string   `json:"method"`
	Roles     []string `json:"roles"`
	Actions   []string `json:"actions"`
	ServiceID string   `json:"serviceId"`
}

type PublicPath struct {
	Path   string   `json:"path"`
	Method []string `json:"methods"` // HTTP methods to bypass auth (GET, POST, etc)
}

type pathKey struct {
	path   string
	method string
}
