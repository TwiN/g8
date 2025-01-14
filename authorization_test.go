package g8

import "testing"

func TestAuthorizationService_Authorize(t *testing.T) {
	authorizationService := NewAuthorizationService().WithToken("token")
	if _, authorized := authorizationService.Authorize("token", nil); !authorized {
		t.Error("should've returned true")
	}
	if _, authorized := authorizationService.Authorize("bad-token", nil); authorized {
		t.Error("should've returned false")
	}
	if _, authorized := authorizationService.Authorize("token", []string{"admin"}); authorized {
		t.Error("should've returned false")
	}
	if _, authorized := authorizationService.Authorize("", nil); authorized {
		t.Error("should've returned false")
	}
}

func TestAuthorizationService_AuthorizeWithPermissions(t *testing.T) {
	authorizationService := NewAuthorizationService().WithClient(NewClient("token").WithPermissions([]string{"a", "b"}))
	if _, authorized := authorizationService.Authorize("token", nil); !authorized {
		t.Error("should've returned true")
	}
	if _, authorized := authorizationService.Authorize("token", []string{"a"}); !authorized {
		t.Error("should've returned true")
	}
	if _, authorized := authorizationService.Authorize("token", []string{"b"}); !authorized {
		t.Error("should've returned true")
	}
	if _, authorized := authorizationService.Authorize("token", []string{"a", "b"}); !authorized {
		t.Error("should've returned true")
	}
	if _, authorized := authorizationService.Authorize("token", []string{"c"}); authorized {
		t.Error("should've returned false")
	}
	if _, authorized := authorizationService.Authorize("token", []string{"a", "c"}); authorized {
		t.Error("should've returned false")
	}
	if _, authorized := authorizationService.Authorize("bad-token", nil); authorized {
		t.Error("should've returned false")
	}
	if _, authorized := authorizationService.Authorize("bad-token", []string{"a"}); authorized {
		t.Error("should've returned false")
	}
	if _, authorized := authorizationService.Authorize("", []string{"a"}); authorized {
		t.Error("should've returned false")
	}
}

func TestAuthorizationService_WithToken(t *testing.T) {
	authorizationService := NewAuthorizationService().WithToken("token")
	if _, authorized := authorizationService.Authorize("token", nil); !authorized {
		t.Error("should've returned true")
	}
	if _, authorized := authorizationService.Authorize("bad-token", nil); authorized {
		t.Error("should've returned false")
	}
	if _, authorized := authorizationService.Authorize("token", []string{"admin"}); authorized {
		t.Error("should've returned false")
	}
}

func TestAuthorizationService_WithTokens(t *testing.T) {
	authorizationService := NewAuthorizationService().WithTokens([]string{"1", "2"})
	if _, authorized := authorizationService.Authorize("1", nil); !authorized {
		t.Error("should've returned true")
	}
	if _, authorized := authorizationService.Authorize("2", nil); !authorized {
		t.Error("should've returned true")
	}
	if _, authorized := authorizationService.Authorize("3", nil); authorized {
		t.Error("should've returned false")
	}
}

func TestAuthorizationService_WithClient(t *testing.T) {
	authorizationService := NewAuthorizationService().WithClient(NewClient("token").WithPermissions([]string{"a", "b"}))
	if _, authorized := authorizationService.Authorize("token", []string{"a", "b"}); !authorized {
		t.Error("should've returned true")
	}
	if _, authorized := authorizationService.Authorize("token", []string{"a"}); !authorized {
		t.Error("should've returned true")
	}
	if _, authorized := authorizationService.Authorize("token", []string{"b"}); !authorized {
		t.Error("should've returned true")
	}
	if _, authorized := authorizationService.Authorize("token", []string{"c"}); authorized {
		t.Error("should've returned false")
	}
}

func TestAuthorizationService_WithClients(t *testing.T) {
	authorizationService := NewAuthorizationService().WithClients([]*Client{NewClient("1").WithPermission("a"), NewClient("2").WithPermission("b")})
	if _, authorized := authorizationService.Authorize("1", []string{"a"}); !authorized {
		t.Error("should've returned true")
	}
	if _, authorized := authorizationService.Authorize("2", []string{"b"}); !authorized {
		t.Error("should've returned true")
	}
	if _, authorized := authorizationService.Authorize("1", []string{"b"}); authorized {
		t.Error("should've returned false")
	}
	if _, authorized := authorizationService.Authorize("2", []string{"a"}); authorized {
		t.Error("should've returned false")
	}
}
