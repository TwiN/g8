package g8

import "testing"

func TestAuthorizationService_IsAuthorized(t *testing.T) {
	authorizationService := NewAuthorizationService().WithToken("token")
	if !authorizationService.IsAuthorized("token", nil) {
		t.Error("should've returned true")
	}
	if authorizationService.IsAuthorized("bad-token", nil) {
		t.Error("should've returned false")
	}
	if authorizationService.IsAuthorized("token", []string{"admin"}) {
		t.Error("should've returned false")
	}
	if authorizationService.IsAuthorized("", nil) {
		t.Error("should've returned false")
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
	if authorizationService.IsAuthorized("", []string{"a"}) {
		t.Error("should've returned false")
	}
}

func TestAuthorizationService_WithToken(t *testing.T) {
	authorizationService := NewAuthorizationService().WithToken("token")
	if !authorizationService.IsAuthorized("token", nil) {
		t.Error("should've returned true")
	}
	if authorizationService.IsAuthorized("bad-token", nil) {
		t.Error("should've returned false")
	}
	if authorizationService.IsAuthorized("token", []string{"admin"}) {
		t.Error("should've returned false")
	}
}

func TestAuthorizationService_WithTokens(t *testing.T) {
	authorizationService := NewAuthorizationService().WithTokens([]string{"1", "2"})
	if !authorizationService.IsAuthorized("1", nil) {
		t.Error("should've returned true")
	}
	if !authorizationService.IsAuthorized("2", nil) {
		t.Error("should've returned true")
	}
	if authorizationService.IsAuthorized("3", nil) {
		t.Error("should've returned false")
	}
}

func TestAuthorizationService_WithClient(t *testing.T) {
	authorizationService := NewAuthorizationService().WithClient(NewClient("token").WithPermissions([]string{"a", "b"}))
	if !authorizationService.IsAuthorized("token", []string{"a", "b"}) {
		t.Error("should've returned true")
	}
	if !authorizationService.IsAuthorized("token", []string{"a"}) {
		t.Error("should've returned true")
	}
	if !authorizationService.IsAuthorized("token", []string{"b"}) {
		t.Error("should've returned true")
	}
	if authorizationService.IsAuthorized("token", []string{"c"}) {
		t.Error("should've returned false")
	}
}

func TestAuthorizationService_WithClients(t *testing.T) {
	authorizationService := NewAuthorizationService().WithClients([]*Client{NewClient("1").WithPermission("a"), NewClient("2").WithPermission("b")})
	if !authorizationService.IsAuthorized("1", []string{"a"}) {
		t.Error("should've returned true")
	}
	if !authorizationService.IsAuthorized("2", []string{"b"}) {
		t.Error("should've returned true")
	}
	if authorizationService.IsAuthorized("1", []string{"b"}) {
		t.Error("should've returned false")
	}
	if authorizationService.IsAuthorized("2", []string{"a"}) {
		t.Error("should've returned false")
	}
}
