package g8

import (
	"net/http"
	"strings"
)

type AuthorizationService struct {
	tokens        []string
	tokenProvider *TokenProvider
}

func NewAuthorizationService() *AuthorizationService {
	return &AuthorizationService{}
}

// WithToken is used to specify a single token for which authorization will be granted
// Calling this multiple time will add multiple tokens, though you may want to use WithTokens instead if you plan to
// add multiple tokens
//
// If you wish to
func (authorizationService *AuthorizationService) WithToken(token string) *AuthorizationService {
	authorizationService.tokens = append(authorizationService.tokens, token)
	return authorizationService
}

// WithTokens is used to specify a slice of tokens for which authorization will be granted
func (authorizationService *AuthorizationService) WithTokens(tokens []string) *AuthorizationService {
	authorizationService.tokens = append(authorizationService.tokens, tokens...)
	return authorizationService
}

func (authorizationService *AuthorizationService) WithTokenProvider(provider *TokenProvider) *AuthorizationService {
	authorizationService.tokenProvider = provider
	return authorizationService
}

func (authorizationService *AuthorizationService) IsAuthorized(token string) bool {
	for _, t := range authorizationService.tokens {
		if t == token {
			return true
		}
	}
	if authorizationService.tokenProvider != nil {
		return authorizationService.tokenProvider.Exists(token)
	}
	return false
}

func (authorizationService *AuthorizationService) extractTokenFromRequest(request *http.Request) string {
	return strings.Replace(request.Header.Get(AuthorizationHeader), "Bearer ", "", 1)
}
