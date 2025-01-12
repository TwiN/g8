package g8

import "testing"

func TestClient_HasPermission(t *testing.T) {
	client := NewClientWithPermissions("token", []string{"a", "b"})
	if !client.HasPermission("a") {
		t.Errorf("client has permissions %s, therefore HasPermission(a) should've been true", client.Permissions)
	}
	if !client.HasPermission("b") {
		t.Errorf("client has permissions %s, therefore HasPermission(b) should've been true", client.Permissions)
	}
	if client.HasPermission("c") {
		t.Errorf("client has permissions %s, therefore HasPermission(c) should've been false", client.Permissions)
	}
	if client.HasPermission("ab") {
		t.Errorf("client has permissions %s, therefore HasPermission(ab) should've been false", client.Permissions)
	}
}

func TestClient_HasPermissions(t *testing.T) {
	client := NewClientWithPermissions("token", []string{"a", "b"})
	if !client.HasPermissions(nil) {
		t.Errorf("client has permissions %s, therefore HasPermissions(nil) should've been true", client.Permissions)
	}
	if !client.HasPermissions([]string{"a"}) {
		t.Errorf("client has permissions %s, therefore HasPermissions([a]) should've been true", client.Permissions)
	}
	if !client.HasPermissions([]string{"b"}) {
		t.Errorf("client has permissions %s, therefore HasPermissions([b]) should've been true", client.Permissions)
	}
	if !client.HasPermissions([]string{"a", "b"}) {
		t.Errorf("client has permissions %s, therefore HasPermissions([a, b]) should've been true", client.Permissions)
	}
	if client.HasPermissions([]string{"a", "b", "c"}) {
		t.Errorf("client has permissions %s, therefore HasPermissions([a, b, c]) should've been false", client.Permissions)
	}
}

func TestClient_WithData(t *testing.T) {
	client := NewClient("token")
	if client.Data != nil {
		t.Error("expected client data to be nil")
	}
	client.WithData(5)
	if client.Data != 5 {
		t.Errorf("expected client data to be 5, got %d", client.Data)
	}
	client.WithData(map[string]string{"key": "value"})
	if data, ok := client.Data.(map[string]string); !ok || data["key"] != "value" {
		t.Errorf("expected client data to be map[string]string{key: value}, got %v", client.Data)
	}
}

func TestNewClientWithData(t *testing.T) {
	client := NewClientWithData("token", 5)
	if client.Data != 5 {
		t.Errorf("expected client data to be 5, got %d", client.Data)
	}
}

func TestNewClientWithPermissionsAndData(t *testing.T) {
	client := NewClientWithPermissionsAndData("token", []string{"a", "b"}, 5)
	if client.Data != 5 {
		t.Errorf("expected client data to be 5, got %d", client.Data)
	}
	if !client.HasPermission("a") {
		t.Errorf("client has permissions %s, therefore HasPermission(a) should've been true", client.Permissions)
	}
	if !client.HasPermission("b") {
		t.Errorf("client has permissions %s, therefore HasPermission(b) should've been true", client.Permissions)
	}
	if client.HasPermission("c") {
		t.Errorf("client has permissions %s, therefore HasPermission(c) should've been false", client.Permissions)
	}
}
