package g8

type ClientProvider struct {
	cache bool

	getClientByTokenFunc func(token string) *Client
}

// NewClientProvider creates a ClientProvider
// The parameter that must be passed is a function that the provider will use to retrieve a client by a given token
//
// Example:
//     clientProvider := NewClientProvider(func(token string) *Client {
//         // We'll assume that the following function calls your database and checks whether a given token exists
//         exists := database.CheckIfTokenExists(token)
//         if exists {
//             return g8.NewClient(token)
//         }
//         return nil
//     })
func NewClientProvider(getClientByTokenFunc func(token string) *Client) *ClientProvider {
	return &ClientProvider{
		cache:                false,
		getClientByTokenFunc: getClientByTokenFunc,
	}
}

// GetClientByToken retrieves a client by its token through the provided getClientByTokenFunc.
func (provider *ClientProvider) GetClientByToken(token string) *Client {
	return provider.getClientByTokenFunc(token)
}
