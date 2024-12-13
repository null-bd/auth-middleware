package middleware

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ConfigLoader handles loading and processing of authentication configuration
type ConfigLoader struct {
	configPath string
}

func NewConfigLoader(configPath string) *ConfigLoader {
	return &ConfigLoader{
		configPath: configPath,
	}
}

func (cl *ConfigLoader) Load() (*ServiceConfig, error) {
	data, err := os.ReadFile(cl.configPath)
	if err != nil {
		return nil, err
	}

	config := struct {
		Auth ServiceConfig `yaml:"auth"`
	}{}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Process environment variables in the configuration
	cl.processEnvVars(&config.Auth)

	return &config.Auth, nil
}

func (cl *ConfigLoader) processEnvVars(config *ServiceConfig) {
	config.ClientSecret = resolveEnvVar(config.ClientSecret)
	config.KeycloakURL = resolveEnvVar(config.KeycloakURL)
	config.CacheURL = resolveEnvVar(config.CacheURL)
}

func resolveEnvVar(value string) string {
	if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") {
		envVar := strings.TrimSuffix(strings.TrimPrefix(value, "${"), "}")
		if envValue := os.Getenv(envVar); envValue != "" {
			return envValue
		}
	}
	return value
}

// Enhanced ResourceMatcher for flexible path matching
type ResourceMatcher struct {
	resources []ResourcePermission
}

func NewResourceMatcher(resources []ResourcePermission) *ResourceMatcher {
	return &ResourceMatcher{
		resources: resources,
	}
}

func (rm *ResourceMatcher) FindMatchingResource(method, path string) *ResourcePermission {
	for _, resource := range rm.resources {
		if matchesPath(resource.Path, path) && resource.Method == method {
			return &resource
		}
	}
	return nil
}

// matchesPath handles path matching including path parameters
func matchesPath(pattern, path string) bool {
	patternParts := strings.Split(pattern, "/")
	pathParts := strings.Split(path, "/")

	if len(patternParts) != len(pathParts) {
		return false
	}

	for i := range patternParts {
		if strings.HasPrefix(patternParts[i], "{") && strings.HasSuffix(patternParts[i], "}") {
			continue // Skip path parameter comparison
		}
		if patternParts[i] != pathParts[i] {
			return false
		}
	}
	return true
}
