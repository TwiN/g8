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
