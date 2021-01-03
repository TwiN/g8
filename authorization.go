package g8

import (
	"net/http"
	"strings"
)

// AuthorizationService is the service that manages client/token registry and client fallback as well as the service
// that determines whether a token meets the specific requirements to be authorized by a Gate or not.
type AuthorizationService struct {
	clients        map[string]*Client
	clientProvider *ClientProvider
}

// NewAuthorizationService creates a new AuthorizationService
func NewAuthorizationService() *AuthorizationService {
	return &AuthorizationService{
		clients: make(map[string]*Client),
	}
}

// WithToken is used to specify a single token for which authorization will be granted
//
// The client that will be created from this token will have access to all handlers that are not protected with a
// specific permission.
//
// In other words, if you were to do the following:
//     gate := g8.NewGate(NewAuthorizationService().WithToken("12345"))
//
// The following handler would be accessible with the token 12345:
//     gate.Protect(yourHandler)
//
// But not this one would not be accessible with the token 12345:
//     gate.ProtectWithPermissions(yourHandler, []string{"admin"})
//
// Calling this function multiple times will add multiple clients, though you may want to use WithTokens instead
// if you plan to add multiple clients
//
// If you wish to configure advanced permissions, consider using WithClient instead.
//
func (authorizationService *AuthorizationService) WithToken(token string) *AuthorizationService {
	authorizationService.clients[token] = NewClient(token)
	return authorizationService
}

// WithTokens is used to specify a slice of tokens for which authorization will be granted
func (authorizationService *AuthorizationService) WithTokens(tokens []string) *AuthorizationService {
	for _, token := range tokens {
		authorizationService.clients[token] = NewClient(token)
	}
	return authorizationService
}

// WithClient is used to specify a single client for which authorization will be granted
//
// Calling this function multiple times will add multiple clients, though you may want to use WithClients instead
// if you plan to add multiple clients
func (authorizationService *AuthorizationService) WithClient(client *Client) *AuthorizationService {
	authorizationService.clients[client.Token] = client
	return authorizationService
}

// WithClients is used to specify a slice of clients for which authorization will be granted
func (authorizationService *AuthorizationService) WithClients(clients []*Client) *AuthorizationService {
	for _, client := range clients {
		authorizationService.clients[client.Token] = client
	}
	return authorizationService
}

// WithClientProvider allows specifying a custom provider to fetch clients by token.
//
// For example, you can use it to fallback to making a call in your database when a request is made with a token that
// hasn't been specified via WithToken, WithTokens, WithClient or WithClients.
func (authorizationService *AuthorizationService) WithClientProvider(provider *ClientProvider) *AuthorizationService {
	authorizationService.clientProvider = provider
	return authorizationService
}

// IsAuthorized checks whether a client with a given token exists and has the permissions required.
//
// If permissionsRequired is nil or empty and a client with the given token exists, said client will have access to all
// handlers that are not protected by a given permission.
func (authorizationService *AuthorizationService) IsAuthorized(token string, permissionsRequired []string) bool {
	client, _ := authorizationService.clients[token]
	// If there's no clients with the given token directly stored in the AuthorizationService, fall back to the
	// client provider, if there's one configured.
	if client == nil && authorizationService.clientProvider != nil {
		client = authorizationService.clientProvider.GetClientByToken(token)
	}
	if client != nil {
		return client.HasPermissions(permissionsRequired)
	}
	return false
}

func (authorizationService *AuthorizationService) extractTokenFromRequest(request *http.Request) string {
	return strings.TrimPrefix(request.Header.Get(AuthorizationHeader), "Bearer ")
}
