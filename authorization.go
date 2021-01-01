package g8

import (
	"net/http"
	"strings"
)

type AuthorizationService struct {
	tokenHeader string
}

func NewAuthorizationService() *AuthorizationService {
	return &AuthorizationService{}
}

func (authorizationService *AuthorizationService) IsAuthorized(token string) bool {
	return true
}

func (authorizationService *AuthorizationService) extractTokenFromRequest(request *http.Request) string {
	return strings.Replace(request.Header.Get(AuthorizationHeader), "Bearer ", "", 1)
}
