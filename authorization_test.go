package g8

import "testing"

func TestAuthorizationService_IsAuthorized(t *testing.T) {
	authorizationService := NewAuthorizationService().WithToken("token")
	if !authorizationService.IsAuthorized("token", nil) {
		t.Error("should've returned true")
	}
	if authorizationService.IsAuthorized("bad-token", nil) {
		t.Error("should've returned true")
	}
}

func TestAuthorizationService_IsAuthorizedWithPermissions(t *testing.T) {
	authorizationService := NewAuthorizationService().WithClient(NewClient("token").WithPermissions([]string{"a", "b"}))
	if !authorizationService.IsAuthorized("token", nil) {
		t.Error("should've returned true")
	}
	if !authorizationService.IsAuthorized("token", []string{"a"}) {
		t.Error("should've returned true")
	}
	if !authorizationService.IsAuthorized("token", []string{"b"}) {
		t.Error("should've returned true")
	}
	if !authorizationService.IsAuthorized("token", []string{"a", "b"}) {
		t.Error("should've returned true")
	}
	if authorizationService.IsAuthorized("token", []string{"c"}) {
		t.Error("should've returned false")
	}
	if authorizationService.IsAuthorized("token", []string{"a", "c"}) {
		t.Error("should've returned false")
	}
	if authorizationService.IsAuthorized("bad-token", nil) {
		t.Error("should've returned false")
	}
	if authorizationService.IsAuthorized("bad-token", []string{"a"}) {
		t.Error("should've returned false")
	}
}
