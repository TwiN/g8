package g8

import (
	"net/http"
)

const (
	AuthorizationHeader             = "Authorization"
	DefaultUnauthorizedResponseBody = "Authorization token is missing or invalid"
)

type Gate struct {
	authorizationService     *AuthorizationService
	unauthorizedResponseBody []byte
}

func New() *Gate {
	return &Gate{
		unauthorizedResponseBody: []byte(DefaultUnauthorizedResponseBody),
	}
}

// TODO: ProtectWithRoleLevel. should also return 403 instead of 401
func (gate *Gate) Protect(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if gate.authorizationService != nil {
			token := gate.authorizationService.extractTokenFromRequest(request)
			if !gate.authorizationService.IsAuthorized(token) {
				writer.WriteHeader(http.StatusUnauthorized)
				_, _ = writer.Write(gate.unauthorizedResponseBody)
				return
			}
		}
		handler.ServeHTTP(writer, request)
	})
}

func (gate *Gate) WithCustomUnauthorizedResponseBody(unauthorizedResponseBody []byte) *Gate {
	gate.unauthorizedResponseBody = unauthorizedResponseBody
	return gate
}
