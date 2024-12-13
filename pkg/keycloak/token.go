package keycloak

import (
	"context"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

type TokenManager struct {
	kc       *KeycloakClient
	cache    *redis.Client
	useCache bool
}

type TokenClaims struct {
	OrgID    string   `json:"org_id"`
	BranchID string   `json:"branch_id"`
	Roles    []string `json:"roles"`
	Actions  []string `json:"actions"`
}

func NewTokenManager(url, realm string, useCache bool, cacheURL string) (*TokenManager, error) {
	kc := NewKeycloakClient(url, realm)

	var cache *redis.Client
	if useCache {
		cache = redis.NewClient(&redis.Options{
			Addr: cacheURL,
		})
	}

	return &TokenManager{
		kc:       kc,
		cache:    cache,
		useCache: useCache,
	}, nil
}

func (tm *TokenManager) ValidateToken(ctx context.Context, token string) (*TokenClaims, error) {
	// Caching diabled
	// if tm.useCache {
	//     if claims, err := tm.getFromCache(ctx, token); err == nil {
	//         return claims, nil
	//     }
	// }

	claims, err := tm.validateWithKeycloak(ctx, token)
	if err != nil {
		return nil, err
	}

	// Caching disabled
	// if tm.useCache {
	// 	tm.cacheToken(ctx, token, claims)
	// }

	return claims, nil
}

func (tm *TokenManager) validateWithKeycloak(ctx context.Context, token string) (*TokenClaims, error) {
	_, mapClaims, err := tm.kc.client.DecodeAccessToken(ctx, token, tm.kc.realm)
	if err != nil {
		return nil, err
	}

	tokenClaims := &TokenClaims{
		OrgID:    (*mapClaims)["org_id"].(string),
		BranchID: (*mapClaims)["branch_id"].(string),
		Roles:    extractRoles(mapClaims),
		Actions:  extractActions(mapClaims),
	}

	return tokenClaims, nil
}

func extractRoles(claims *jwt.MapClaims) []string {
	if realmAccess, ok := (*claims)["realm_access"].(map[string]interface{}); ok {
		if roles, ok := realmAccess["roles"].([]string); ok {
			return roles
		}
	}
	return []string{}
}

func extractActions(claims *jwt.MapClaims) []string {
	if actions, ok := (*claims)["actions"].([]string); ok {
		return actions
	}
	return []string{}
}
