package keycloak

import (
    "context"
    "github.com/Nerzal/gocloak/v13"
)

type KeycloakClient struct {
    client  *gocloak.GoCloak
    realm   string
    context context.Context
}

func NewKeycloakClient(url, realm string) *KeycloakClient {
    return &KeycloakClient{
        client:  gocloak.NewClient(url),
        realm:   realm,
        context: context.Background(),
    }
}

func (kc *KeycloakClient) GetUserInfo(token string) (*gocloak.UserInfo, error) {
    return kc.client.GetUserInfo(kc.context, token, kc.realm)
}