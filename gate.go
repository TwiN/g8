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

// NewGate creates a new Gate.
func NewGate(authorizationService *AuthorizationService) *Gate {
	return &Gate{
		unauthorizedResponseBody: []byte(DefaultUnauthorizedResponseBody),
		authorizationService:     authorizationService,
	}
}

func (gate *Gate) WithCustomUnauthorizedResponseBody(unauthorizedResponseBody []byte) *Gate {
	gate.unauthorizedResponseBody = unauthorizedResponseBody
	return gate
}

// Protect secures a handler, requiring requests going through to have a valid Authorization bearer token.
// Unlike ProtectWithPermissions, Protect will allow access to any existing clients, regardless of their permissions
// or lack thereof.
func (gate *Gate) Protect(handler http.Handler) http.Handler {
	return gate.ProtectWithPermissions(handler, nil)
}

// ProtectWithPermissions secures a handler, requiring requests going through to have a valid Authorization bearer token
// as well as a slice of permissions that must be met.
func (gate *Gate) ProtectWithPermissions(handler http.Handler, permissions []string) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if gate.authorizationService != nil {
			token := gate.authorizationService.extractTokenFromRequest(request)
			if !gate.authorizationService.IsAuthorized(token, permissions) {
				writer.WriteHeader(http.StatusUnauthorized)
				_, _ = writer.Write(gate.unauthorizedResponseBody)
				return
			}
		}
		handler.ServeHTTP(writer, request)
	})
}
