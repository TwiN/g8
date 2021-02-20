package g8

import (
	"net/http"
)

const (
	// AuthorizationHeader is the header in which g8 looks for the authorization bearer token
	AuthorizationHeader = "Authorization"

	// DefaultUnauthorizedResponseBody is the default response body returned if a request was sent with a missing or
	// invalid token
	DefaultUnauthorizedResponseBody = "Authorization Bearer token is missing or invalid"
)

// Gate is the front door to your API which opens the door only to those with the key
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

// WithCustomUnauthorizedResponseBody sets a custom response body when Gate determines that a request must be blocked
func (gate *Gate) WithCustomUnauthorizedResponseBody(unauthorizedResponseBody []byte) *Gate {
	gate.unauthorizedResponseBody = unauthorizedResponseBody
	return gate
}

// Protect secures a handler, requiring requests going through to have a valid Authorization Bearer token.
// Unlike ProtectWithPermissions, Protect will allow access to any registered tokens, regardless of their permissions
// or lack thereof.
//
// Example:
//    gate := g8.NewGate(g8.NewAuthorizationService().WithToken("token"))
//    router := http.NewServeMux()
//    // Without protection
//    router.Handle("/handle", yourHandler)
//    // With protection
//    router.Handle("/handle", gate.Protect(yourHandler))
//
func (gate *Gate) Protect(handler http.Handler) http.Handler {
	return gate.ProtectWithPermissions(handler, nil)
}

// ProtectWithPermissions secures a handler, requiring requests going through to have a valid Authorization Bearer token
// as well as a slice of permissions that must be met.
//
// Example:
//    gate := g8.NewGate(g8.NewAuthorizationService().WithClient(g8.NewClient("token").WithPermission("admin")))
//    router := http.NewServeMux()
//    // Without protection
//    router.Handle("/handle", yourHandler)
//    // With protection
//    router.Handle("/handle", gate.ProtectWithPermissions(yourHandler, []string{"admin"}))
//
func (gate *Gate) ProtectWithPermissions(handler http.Handler, permissions []string) http.Handler {
	return gate.ProtectFuncWithPermissions(func(writer http.ResponseWriter, request *http.Request) {
		handler.ServeHTTP(writer, request)
	}, permissions)
}

// ProtectWithPermission does the same thing as ProtectWithPermissions, but for a single permission instead of a
// slice of permissions
//
// See ProtectWithPermissions for further documentation
func (gate *Gate) ProtectWithPermission(handler http.Handler, permission string) http.Handler {
	return gate.ProtectFuncWithPermissions(func(writer http.ResponseWriter, request *http.Request) {
		handler.ServeHTTP(writer, request)
	}, []string{permission})
}

// ProtectFunc secures a handlerFunc, requiring requests going through to have a valid Authorization Bearer token.
// Unlike ProtectFuncWithPermissions, ProtectFunc will allow access to any registered tokens, regardless of their
// permissions or lack thereof.
//
// Example:
//    gate := g8.NewGate(g8.NewAuthorizationService().WithToken("token"))
//    router := http.NewServeMux()
//    // Without protection
//    router.HandleFunc("/handle", yourHandlerFunc)
//    // With protection
//    router.HandleFunc("/handle", gate.ProtectFunc(yourHandlerFunc))
//
func (gate *Gate) ProtectFunc(handlerFunc http.HandlerFunc) http.HandlerFunc {
	return gate.ProtectFuncWithPermissions(handlerFunc, nil)
}

// ProtectFuncWithPermissions secures a handler, requiring requests going through to have a valid Authorization Bearer
// token as well as a slice of permissions that must be met.
//
// Example:
//    gate := g8.NewGate(g8.NewAuthorizationService().WithClient(g8.NewClient("token").WithPermission("admin")))
//    router := http.NewServeMux()
//    // Without protection
//    router.HandleFunc("/handle", yourHandlerFunc)
//    // With protection
//    router.HandleFunc("/handle", gate.ProtectFuncWithPermissions(yourHandlerFunc, []string{"admin"}))
//
func (gate *Gate) ProtectFuncWithPermissions(handlerFunc http.HandlerFunc, permissions []string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if gate.authorizationService != nil {
			token := gate.authorizationService.extractTokenFromRequest(request)
			if !gate.authorizationService.IsAuthorized(token, permissions) {
				writer.WriteHeader(http.StatusUnauthorized)
				_, _ = writer.Write(gate.unauthorizedResponseBody)
				return
			}
		}
		handlerFunc(writer, request)
	}
}

// ProtectFuncWithPermission does the same thing as ProtectFuncWithPermissions, but for a single permission instead of a
// slice of permissions
//
// See ProtectFuncWithPermissions for further documentation
func (gate *Gate) ProtectFuncWithPermission(handlerFunc http.HandlerFunc, permission string) http.HandlerFunc {
	return gate.ProtectFuncWithPermissions(handlerFunc, []string{permission})
}
