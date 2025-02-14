package g8

// Client is a struct containing both a Token and a slice of extra Permissions that said token has.
type Client struct {
	// Token is the value used to authenticate with the API.
	Token string

	// Permissions is a slice of extra permissions that may be used for more granular access control.
	//
	// If you only wish to use Gate.Protect and Gate.ProtectFunc, you do not have to worry about this,
	// since they're only used by Gate.ProtectWithPermissions and Gate.ProtectFuncWithPermissions
	Permissions []string

	// Data is a field that can be used to store any data you want to associate with the client.
	Data any
}

// NewClient creates a Client with a given token
func NewClient(token string) *Client {
	return &Client{
		Token: token,
	}
}

// NewClientWithPermissions creates a Client with a slice of permissions
// Equivalent to using NewClient and WithPermissions
func NewClientWithPermissions(token string, permissions []string) *Client {
	return NewClient(token).WithPermissions(permissions)
}

// NewClientWithData creates a Client with some data
// Equivalent to using NewClient and WithData
func NewClientWithData(token string, data any) *Client {
	return NewClient(token).WithData(data)
}

// NewClientWithPermissionsAndData creates a Client with a slice of permissions and some data
// Equivalent to using NewClient, WithPermissions and WithData
func NewClientWithPermissionsAndData(token string, permissions []string, data any) *Client {
	return NewClient(token).WithPermissions(permissions).WithData(data)
}

// WithPermissions adds a slice of permissions to a client
func (client *Client) WithPermissions(permissions []string) *Client {
	client.Permissions = append(client.Permissions, permissions...)
	return client
}

// WithPermission adds a permission to a client
func (client *Client) WithPermission(permission string) *Client {
	client.Permissions = append(client.Permissions, permission)
	return client
}

// WithData attaches data to a client
func (client *Client) WithData(data any) *Client {
	client.Data = data
	return client
}

// HasPermission checks whether a client has a given permission
func (client *Client) HasPermission(permissionRequired string) bool {
	for _, permission := range client.Permissions {
		if permissionRequired == permission {
			return true
		}
	}
	return false
}

// HasPermissions checks whether a client has the all permissions passed
func (client *Client) HasPermissions(permissionsRequired []string) bool {
	for _, permissionRequired := range permissionsRequired {
		if !client.HasPermission(permissionRequired) {
			return false
		}
	}
	return true
}
