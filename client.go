package g8

type Client struct {
	Token       string
	Permissions []string
}

func NewClient(token string) *Client {
	return &Client{
		Token: token,
	}
}

func NewClientWithPermissions(token string, permissions []string) *Client {
	return &Client{
		Token:       token,
		Permissions: permissions,
	}
}

func (client *Client) WithPermissions(permissions []string) *Client {
	client.Permissions = append(client.Permissions, permissions...)
	return client
}

func (client *Client) WithPermission(permission string) *Client {
	client.Permissions = append(client.Permissions, permission)
	return client
}

func (client Client) HasPermission(permissionRequired string) bool {
	for _, permission := range client.Permissions {
		if permissionRequired == permission {
			return true
		}
	}
	return false
}

func (client Client) HasPermissions(permissionsRequired []string) bool {
	for _, permissionRequired := range permissionsRequired {
		if !client.HasPermission(permissionRequired) {
			return false
		}
	}
	return true
}
